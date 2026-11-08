// DISPOSABLE POSTGRESQL 18 REHEARSAL for the Sprint 3.0.3 disable/suspension lock-order fix. Skipped unless started by
//   scripts/rehearsal/disable-lock-order-rehearsal.sh
// which creates a brand-new local PostgreSQL 18 cluster (Unix socket only, no TCP listener) in a temp directory, runs
// this file, then deletes the cluster. No Netlify database, URL or credential is ever read; beforeAll refuses anything
// that is not that freshly initialised cluster.
//
// Two templates are built inside the cluster: M1-M7 exactly as shipped, and M1-M7 + the M8 PROPOSAL (never applied
// anywhere else). Every race runs real application code (PostgresAuthStore through the role- and statement-guarded
// client) on separate PostgreSQL backends. Interleavings are made deterministic by pausing one party before a named
// statement and by waiting, through pg_stat_activity, until the other party is blocked on the expected lock.
//
//   D0  (M8)    control: the Sprint 3.0.2 statement order (session sweep BEFORE the member UPDATE) deadlocks with
//               organization suspension. PostgreSQL detects it and aborts one side (40P01).
//   D1a (M7/M8) the disable runs first: it has changed the member and holds the session lock; suspension waits (M8), then
//               both commit.
//   D1b (M7/M8) suspension runs first (uncommitted): the disable waits in the member trigger (M8), then both commit.
//   D1c (M7/M8) suspension commits between the disable's member-row lock and its status change (the old deadlock
//               window): suspension does not wait for the member row lock, and the disable then completes.
//   L1  (M7)    login racing disable leaves a stale (unusable) session row, in both login timings; the repeated
//               disable and the reviewed reinstatement procedure both sweep it, and no old session ever resurrects.
//   L2  (M8)    login racing disable: the session insert guard refuses the login, or the disable revokes it; reinstatement
//               restores no old session.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { THRIVESOURCE_ORGANIZATION_ID, mintMultiOrganizationCapabilityForOfflineTests, organizationContextForVerifiedMembership, type OrganizationContext, type OrganizationId } from '../../src/domain/organization';
import { sha256Hex } from './crypto';
import { poolSqlClient } from './runtime';
import { roleScopedSqlClient, statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import type { SqlClient } from './types';
import {
  M8_PROPOSAL_SQL, ORGANIZATIONS_SQL, PLATFORM_ADMIN_SQL, PLATFORM_ROLES_SQL, PLATFORM_SQL, REINSTATE_MEMBER_SQL, ROLE_SQL, SCHEMA_SQL, SEARCH_PATH_SQL,
  SUPER_ADMIN_SQL, fillOperatorSql,
} from './testing/harness';

interface PgClient { connect(): Promise<void>; end(): Promise<void>; query<T = any>(text: string, params?: unknown[]): Promise<{ rows: T[]; rowCount: number | null }>; on(event: 'notice', fn: (n: { message?: string }) => void): void }
interface PgPool { query: PgClient['query']; end(): Promise<void>; on(event: 'error', fn: (e: Error) => void): void }
const pg = createRequire(import.meta.url)('pg') as { Client: new (c: Record<string, unknown>) => PgClient; Pool: new (c: Record<string, unknown>) => PgPool };

const env = process.env;
const SOCKET = env.HOURVIA_REHEARSAL_PGSOCKET ?? '';
const PORT = Number(env.HOURVIA_REHEARSAL_PGPORT ?? 0);
const PGDATA = env.HOURVIA_REHEARSAL_PGDATA ?? '';
const SUPER = 'rehearsal_super';
const enabled = env.HOURVIA_LOCK_ORDER_REHEARSAL === 'disposable-local-cluster' && !!SOCKET && PORT > 0 && !!PGDATA;
type Variant = 'm7' | 'm8';
const TEMPLATE = (v: Variant) => `hourvia_lock_order_template_${v}`;
const TS = THRIVESOURCE_ORGANIZATION_ID;
const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const cap = mintMultiOrganizationCapabilityForOfflineTests();
const ctx = (o: OrganizationId, slug: string): OrganizationContext => organizationContextForVerifiedMembership({ organizationId: o, workspaceId: slug }, { id: o, slug, status: 'active' }, cap);
const log = (...a: unknown[]) => console.log('[lock-order]', ...a);
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const settle = <T>(p: Promise<T>) => p.then(v => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e instanceof Error ? e.message : e) }));
const SUSPEND = `UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`;

let admin: PgClient;
const created = new Set<string>();
const client = (database: string, user = 'netlifydb_owner', app = 'lock-order') => new pg.Client({ host: SOCKET, port: PORT, user, database, application_name: app });

/** Pauses (transaction still open) before the first statement matching `pauseBefore`, until release(). */
function gate(pauseBefore?: RegExp) {
  let open!: () => void; const opened = new Promise<void>(r => { open = r; });
  let arrive!: () => void; const atGate = new Promise<void>(r => { arrive = r; });
  let used = false;
  const wrap = (c: SqlClient): SqlClient => ({
    query: async <T>(text: string, params?: unknown[]) => {
      if (!used && pauseBefore?.test(text.trim())) { used = true; arrive(); await opened; }
      return c.query<T>(text, params);
    },
    transaction: fn => c.transaction(tx => fn(wrap(tx))),
  });
  return { wrap, atGate, release: () => open() };
}

async function scenario(variant: Variant, name: string) {
  const db = `hourvia_lock_${variant}_${name}`;
  await admin.query(`CREATE DATABASE ${db} TEMPLATE ${TEMPLATE(variant)} OWNER netlifydb_owner`);
  created.add(db);
  const op = client(db), mon = client(db, SUPER, 'lock-monitor');
  await op.connect(); await mon.connect();
  // M8 races run in a customer organization; M7 only has ThriveSource, so its races suspend ThriveSource (disposable).
  const org = variant === 'm8' ? ACME : TS, slug = variant === 'm8' ? 'acme' : 'thrivesource';
  if (variant === 'm8') {
    await op.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'ACME', 'customer', 'active')`, [ACME]);
    await op.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref) VALUES ($1, 'customer', 'standard', 100, 'REH-LOCK-1')`, [ACME]);
  }
  const parties: PgPool[] = [];
  const guarded = (app: string) => {
    const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: db, max: 4, application_name: app });
    pool.on('error', () => undefined); // idle clients are terminated by DROP DATABASE ... WITH (FORCE)
    parties.push(pool);
    return statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool as any)));
  };
  const sql = guarded(`lock-app-${variant}-${name}`);
  const raceCtx = variant === 'm8' ? ctx(ACME, 'acme') : undefined;
  const store = new PostgresAuthStore(sql, raceCtx); // the organization the races run in
  const ts = new PostgresAuthStore(sql);
  /** Another application instance with its own pool (identified by application_name), optionally gated. */
  const party = (app: string, c: OrganizationContext | undefined, pauseBefore?: RegExp) => {
    const g = gate(pauseBefore);
    return { store: new PostgresAuthStore(g.wrap(guarded(app)), c), atGate: g.atGate, release: g.release };
  };
  const seed = async (o: OrganizationId, s: string, email: string, role: string) => {
    const uid = randomUUID();
    const { rows } = await op.query<{ id: string }>(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
      VALUES ($1, $2, $3, $4, 'r', $5, 'active', now()) RETURNING id`, [o, s, uid, email, role]);
    return { id: rows[0]!.id, uid };
  };
  const session = async (st: PostgresAuthStore, memberId: string) => {
    const token = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43), now = new Date();
    await st.createSession({ tokenHash: sha256Hex(token), memberId, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 43200_000) });
    return token;
  };
  const usable = async (st: PostgresAuthStore, token: string) => (await st.resolveSession(sha256Hex(token), new Date())) !== null;
  const live = async (memberId: string) => (await mon.query<{ n: number }>(`SELECT count(*)::int n FROM auth_sessions WHERE member_id = $1 AND revoked_at IS NULL`, [memberId])).rows[0]!.n;
  const revocations = async (memberId: string) => (await mon.query<{ reason: string | null; by: string | null }>(
    `SELECT revoked_reason AS reason, revoked_by_member_id::text AS by FROM auth_sessions WHERE member_id = $1 ORDER BY created_at, id`, [memberId])).rows;
  const states = async (memberId: string) => (await mon.query<{ member: string; organization: string }>(
    `SELECT m.status AS member, o.status AS organization FROM workspace_members m JOIN organizations o ON o.id = m.organization_id WHERE m.id = $1`, [memberId])).rows[0]!;
  /** Waits until a backend of `app` is blocked on a heavyweight lock (optionally of one kind, e.g. 'advisory'). */
  const waitApp = async (app: string, event?: string) => {
    for (let i = 0; i < 200; i++) {
      const r = (await mon.query<{ w: string; t: string; q: string }>(`SELECT wait_event_type w, wait_event t, left(query, 60) q FROM pg_stat_activity
        WHERE datname = current_database() AND application_name = $1 AND wait_event_type = 'Lock'`, [app])).rows[0];
      if (r && (!event || r.t === event)) return r;
      await sleep(25);
    }
    throw new Error(`${app} never blocked${event ? ` on ${event}` : ''}`);
  };
  const operator = async (app: string) => { const c = client(db, 'netlifydb_owner', app); await c.connect(); return c; };
  const close = async () => { for (const p of parties) await p.end().catch(() => undefined); for (const c of [op, mon]) await c.end().catch(() => undefined); };
  return { db, variant, org, slug, op, mon, store, ts, raceCtx, party, seed, session, usable, live, revocations, states, waitApp, operator, close };
}
type Scenario = Awaited<ReturnType<typeof scenario>>;
async function withScenario(variant: Variant, name: string, fn: (s: Scenario) => Promise<void>) {
  const s = await scenario(variant, name);
  try { await fn(s); } finally { await s.close(); await admin.query(`DROP DATABASE IF EXISTS ${s.db} WITH (FORCE)`); created.delete(s.db); }
}

/** Administrator, the member being disabled (two sessions) and a bystander (one session), all in the race organization. */
async function cast(s: Scenario, tag: string) {
  const adm = await s.seed(s.org, s.slug, `admin.${tag}@example.test`, 'workspace_admin');
  const casey = await s.seed(s.org, s.slug, `casey.${tag}@example.test`, 'contractor');
  const bystander = await s.seed(s.org, s.slug, `bea.${tag}@example.test`, 'contractor');
  const tokens = [await s.session(s.store, casey.id), await s.session(s.store, casey.id)];
  const other = await s.session(s.store, bystander.id);
  return { adm, casey, bystander, tokens, other };
}
/** Shared final-state checks for D1: no session of the organization is usable; the disabled member has none live. */
async function expectFinal(s: Scenario, c: Awaited<ReturnType<typeof cast>>) {
  expect(await s.states(c.casey.id)).toEqual({ member: 'disabled', organization: 'suspended' });
  for (const t of [...c.tokens, c.other]) expect(await s.usable(s.store, t)).toBe(false);
  expect(await s.live(c.casey.id)).toBe(0);
  if (s.variant === 'm8') {
    expect((await s.mon.query(`SELECT count(*)::int n FROM auth_sessions WHERE organization_id = $1 AND revoked_at IS NULL`, [s.org])).rows[0].n).toBe(0);
    expect(await s.revocations(c.bystander.id)).toEqual([{ reason: 'organization_suspended', by: null }]);
  } else {
    // M7 limitation: organization suspension does not revoke sessions; the bystander's row stays unrevoked and is only
    // refused by session resolution while the organization is suspended.
    expect(await s.live(c.bystander.id)).toBe(1);
  }
  expect((await s.mon.query<{ n: number }>(`SELECT count(*)::int n FROM pg_locks WHERE NOT granted`)).rows[0]!.n).toBe(0); // nobody left waiting
}

describe.skipIf(!enabled)('Sprint 3.0.3 disable/suspension lock order on a disposable PostgreSQL 18 cluster', () => {
  beforeAll(async () => {
    const socketDir = resolve(SOCKET);
    if (!socketDir.startsWith(resolve(tmpdir()) + '/') || !resolve(PGDATA).startsWith(resolve(tmpdir()) + '/')) throw new Error('refusing: socket/data dir not under the temp directory');
    admin = client('postgres', SUPER, 'lock-admin');
    await admin.connect();
    const ev = (await admin.query(`SELECT current_setting('server_version') v, current_setting('server_version_num')::int vn,
        current_setting('data_directory') data, current_setting('listen_addresses') listen, inet_server_addr() addr,
        current_setting('default_transaction_isolation') iso, current_setting('deadlock_timeout') dl,
        (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) su,
        (SELECT array_agg(datname::text ORDER BY datname) FROM pg_database) dbs,
        (SELECT array_agg(rolname::text ORDER BY rolname) FROM pg_roles WHERE rolname !~ '^pg_') roles`)).rows[0];
    log('isolation evidence', JSON.stringify(ev));
    if (ev.vn < 180000 || ev.vn >= 190000) throw new Error(`refusing: PostgreSQL 18 required, got ${ev.v}`);
    if (resolve(ev.data) !== resolve(PGDATA)) throw new Error('refusing: server data directory is not the disposable one');
    if (ev.listen !== '' || ev.addr !== null) throw new Error('refusing: server has a TCP listener');
    if (!ev.su) throw new Error('refusing: not the local bootstrap superuser');
    if (JSON.stringify(ev.dbs) !== JSON.stringify(['postgres', 'template0', 'template1']) || JSON.stringify(ev.roles) !== JSON.stringify([SUPER])) {
      throw new Error('refusing: cluster is not freshly initialised');
    }
    // M1-M7 once (roles are cluster-wide), then the M8 template is a copy of it with the M8 proposal applied on top.
    const build = async (variant: Variant, migrations: [string, string][], setup?: string) => {
      await admin.query(variant === 'm7' ? `CREATE DATABASE ${TEMPLATE('m7')}` : `CREATE DATABASE ${TEMPLATE('m8')} TEMPLATE ${TEMPLATE('m7')} OWNER netlifydb_owner`);
      created.add(TEMPLATE(variant));
      const t = client(TEMPLATE(variant), SUPER);
      await t.connect();
      if (setup) await t.query(setup);
      await t.query('SET SESSION AUTHORIZATION netlifydb_owner');
      for (const [, sql] of migrations) { await t.query('BEGIN'); await t.query(sql); await t.query('COMMIT'); } // one transaction per file
      log(`template ${variant}: applied ${migrations.map(m => m[0]).join(', ')}`);
      await t.end();
    };
    await build('m7', [['M1', SCHEMA_SQL], ['M2', ROLE_SQL], ['M3', SUPER_ADMIN_SQL], ['M4', PLATFORM_SQL], ['M5', PLATFORM_ADMIN_SQL], ['M6', SEARCH_PATH_SQL], ['M7', ORGANIZATIONS_SQL]], PLATFORM_ROLES_SQL);
    await build('m8', [['M8 proposal', M8_PROPOSAL_SQL]]);
  }, 180_000);

  afterAll(async () => {
    if (!admin) return;
    for (const db of [...created]) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`).then(() => created.delete(db));
    const left = (await admin.query<{ d: string[] }>(`SELECT array_agg(datname::text ORDER BY datname) d FROM pg_database`)).rows[0]!.d;
    log('databases after cleanup', JSON.stringify(left));
    await admin.end();
    expect(left).toEqual(['postgres', 'template0', 'template1']);
  });

  it('D0 (control, M8): the Sprint 3.0.2 order (sweep sessions, then update the member) deadlocks with suspension', async () => {
    await withScenario('m8', 'd0', async s => {
      const c = await cast(s, 'd0');
      const legacy = await s.operator('hv-legacy-disable');
      const susp = await s.operator('hv-suspend');
      try {
        await legacy.query('BEGIN'); await legacy.query('SET LOCAL ROLE hourvia_auth_runtime');
        await legacy.query(`SELECT id FROM workspace_members WHERE id = $1 FOR NO KEY UPDATE`, [c.casey.id]);
        await legacy.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'member_disabled', revoked_by_member_id = $2 WHERE member_id = $1 AND revoked_at IS NULL`, [c.casey.id, c.adm.id]);
        await susp.query('BEGIN');
        const suspending = settle(susp.query(SUSPEND, [s.org]));
        log('D0 suspension (holding the session lock) waits for the swept session rows', JSON.stringify(await s.waitApp('hv-suspend', 'transactionid')));
        const disabling = settle(legacy.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now(), disabled_by = $2 WHERE id = $1`, [c.casey.id, c.adm.id]));
        const [x, y] = await Promise.all([suspending, disabling]);
        log('D0 outcomes', JSON.stringify({ suspension: x.ok ? 'ok' : x.e, legacyDisable: y.ok ? 'ok' : y.e }));
        const failures = [x, y].filter(r => !r.ok);
        expect(failures).toHaveLength(1);
        expect(failures[0]!.ok ? '' : failures[0]!.e).toMatch(/deadlock detected/);
      } finally {
        await legacy.query('ROLLBACK').catch(() => undefined); await susp.query('ROLLBACK').catch(() => undefined);
        await legacy.end(); await susp.end();
      }
      expect(await s.states(c.casey.id)).toEqual({ member: 'active', organization: 'active' });
      expect(await s.live(c.casey.id)).toBe(2);
    });
  }, 60_000);

  for (const variant of ['m7', 'm8'] as const) {
    it(`D1a (${variant}): disable first (status changed, lock held); suspension ${variant === 'm8' ? 'waits on the session lock, then' : 'does not wait;'} both commit`, async () => {
      await withScenario(variant, 'd1a', async s => {
        const c = await cast(s, 'd1a');
        // Pause at the explicit sweep: the member UPDATE has run (M8: its trigger holds the exclusive session lock). This is
        // exactly where Sprint 3.0.2 held the session rows instead.
        const dis = s.party('hv-d1a-disable', s.raceCtx, /^UPDATE auth_sessions/);
        const susp = await s.operator('hv-suspend');
        try {
          const disabling = settle(dis.store.disableMemberAndRevokeSessions(c.casey.id, c.adm.id, new Date()));
          await dis.atGate;
          const suspending = settle(susp.query(SUSPEND, [s.org]));
          if (variant === 'm8') log('D1a suspension blocked', JSON.stringify(await s.waitApp('hv-suspend', 'advisory')));
          else { expect(await suspending).toMatchObject({ ok: true }); log('D1a (m7) suspension committed without waiting'); }
          dis.release();
          const [x, y] = await Promise.all([disabling, suspending]);
          log(`D1a (${variant})`, JSON.stringify({ disable: x, suspension: y.ok }));
          expect(x).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 2 } });
          expect(y.ok).toBe(true);
        } finally { dis.release(); await susp.end(); }
        expect(await s.revocations(c.casey.id)).toEqual([{ reason: 'member_disabled', by: c.adm.id }, { reason: 'member_disabled', by: c.adm.id }]);
        await expectFinal(s, c);
      });
    }, 60_000);

    it(`D1b (${variant}): suspension first (uncommitted); the disable ${variant === 'm8' ? 'waits in the member trigger, then' : 'does not wait;'} both commit`, async () => {
      await withScenario(variant, 'd1b', async s => {
        const c = await cast(s, 'd1b');
        const susp = await s.operator('hv-suspend');
        const dis = s.party('hv-d1b-disable', s.raceCtx);
        try {
          await susp.query('BEGIN');
          await susp.query(SUSPEND, [s.org]);
          const disabling = settle(dis.store.disableMemberAndRevokeSessions(c.casey.id, c.adm.id, new Date()));
          if (variant === 'm8') {
            log('D1b disable blocked', JSON.stringify(await s.waitApp('hv-d1b-disable', 'advisory')));
            await susp.query('COMMIT');
            expect(await disabling).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 0 } }); // suspension revoked them first
            expect(await s.revocations(c.casey.id)).toEqual([{ reason: 'organization_suspended', by: null }, { reason: 'organization_suspended', by: null }]);
          } else {
            expect(await disabling).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 2 } });
            await susp.query('COMMIT');
            expect(await s.revocations(c.casey.id)).toEqual([{ reason: 'member_disabled', by: c.adm.id }, { reason: 'member_disabled', by: c.adm.id }]);
          }
        } finally { await susp.query('ROLLBACK').catch(() => undefined); await susp.end(); }
        await expectFinal(s, c);
      });
    }, 60_000);

    it(`D1c (${variant}): suspension commits inside the old deadlock window (member row locked, status not yet changed)`, async () => {
      await withScenario(variant, 'd1c', async s => {
        const c = await cast(s, 'd1c');
        const dis = s.party('hv-d1c-disable', s.raceCtx, /^UPDATE workspace_members SET status = 'disabled'/);
        const susp = await s.operator('hv-suspend');
        try {
          const disabling = settle(dis.store.disableMemberAndRevokeSessions(c.casey.id, c.adm.id, new Date()));
          await dis.atGate;
          // The disable holds only the member row (FOR NO KEY UPDATE) and no session row, so suspension never waits for it.
          const suspended = await Promise.race([settle(susp.query(SUSPEND, [s.org])), sleep(10_000).then(() => ({ ok: false as const, e: 'suspension blocked' }))]);
          expect(suspended).toMatchObject({ ok: true });
          log(`D1c (${variant}) suspension committed while the disable held the member row lock`);
          dis.release();
          const x = await disabling;
          log(`D1c (${variant})`, JSON.stringify(x));
          expect(x).toEqual({ ok: true, v: { changed: true, sessionsRevoked: variant === 'm8' ? 0 : 2 } });
        } finally { dis.release(); await susp.end(); }
        const reason = variant === 'm8' ? { reason: 'organization_suspended', by: null } : { reason: 'member_disabled', by: c.adm.id };
        expect(await s.revocations(c.casey.id)).toEqual([reason, reason]);
        await expectFinal(s, c);
      });
    }, 60_000);
  }

  /** The reviewed operator procedure, filled exactly as the runbook instructs; returns its stale-session count. */
  const reinstate = async (s: Scenario, memberId: string, approval: string) => {
    const notices: string[] = [];
    const op = await s.operator('hv-reinstate');
    op.on('notice', n => notices.push(n.message ?? ''));
    try { await op.query(fillOperatorSql(REINSTATE_MEMBER_SQL, { EXPECTED_MEMBER_ID: memberId, APPROVAL_REF: approval })); } finally { await op.end(); }
    const audit = (await s.mon.query<{ n: number }>(`SELECT (details->>'stale_sessions_revoked')::int n FROM auth_audit_events WHERE event_type = 'member_reinstated' AND subject_member_id = $1 AND details->>'approval_ref' = $2`, [memberId, approval])).rows;
    log('reinstatement', notices.join(' | '));
    expect(audit).toHaveLength(1);
    return audit[0]!.n;
  };

  it('L1 (m7): login racing disable leaves an unusable stale session; the repeated disable and reinstatement sweep it, nothing resurrects', async () => {
    await withScenario('m7', 'l1', async s => {
      const adm = await s.seed(TS, 'thrivesource', 'admin.l1@example.test', 'workspace_admin');
      const casey = await s.seed(TS, 'thrivesource', 'casey.l1@example.test', 'contractor');
      const before = await s.session(s.ts, casey.id);

      // (a) The login has read the active member and is about to insert its session (the production login does these as
      // separate statements). The disable commits in between; on M7 nothing re-checks the member at insert.
      const login = s.party('hv-l1-login', undefined, /^INSERT INTO auth_sessions/);
      const token = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43);
      const logging = settle((async () => {
        const m = await login.store.findMemberByAuthUserId(casey.uid);
        expect(m?.status).toBe('active');
        const now = new Date();
        await login.store.createSession({ tokenHash: sha256Hex(token), memberId: casey.id, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 43200_000) });
      })());
      await login.atGate;
      expect(await s.ts.disableMemberAndRevokeSessions(casey.id, adm.id, new Date())).toEqual({ changed: true, sessionsRevoked: 1 });
      login.release();
      expect(await logging).toEqual({ ok: true, v: undefined });
      log('L1a stale session after the race', JSON.stringify({ live: await s.live(casey.id), usable: await s.usable(s.ts, token) }));
      expect(await s.live(casey.id)).toBe(1);                  // the stale row exists ...
      expect(await s.usable(s.ts, token)).toBe(false);         // ... but resolves to nothing while the member is disabled

      // (b) The other timing: the session INSERT is uncommitted when the disable runs. Neither waits for the other (the
      // FK lock on the member row is compatible, the sweep does not see uncommitted rows), so a second stale row lands.
      const raw = await s.operator('hv-l1-raw-login');
      const token2 = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43);
      try {
        await raw.query('BEGIN'); await raw.query('SET LOCAL ROLE hourvia_auth_runtime');
        await raw.query(`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
          VALUES ($1, $2, now(), now(), now() + interval '30 minutes', now() + interval '12 hours')`, [sha256Hex(token2), casey.id]);
        // Already disabled: the repeated disable sweeps (a) but cannot see (b).
        expect(await s.ts.disableMemberAndRevokeSessions(casey.id, adm.id, new Date())).toEqual({ changed: false, sessionsRevoked: 1 });
        await raw.query('COMMIT');
      } finally { await raw.end(); }
      expect(await s.live(casey.id)).toBe(1);
      expect(await s.usable(s.ts, token2)).toBe(false);

      // Reviewed reinstatement: sweeps the stale row FIRST, then reactivates. No old session resurrects.
      expect(await reinstate(s, casey.id, 'REH-L1-REINSTATE')).toBe(1);
      expect(await s.states(casey.id)).toEqual({ member: 'active', organization: 'active' });
      expect(await s.live(casey.id)).toBe(0);
      for (const t of [before, token, token2]) expect(await s.usable(s.ts, t)).toBe(false);
      expect((await s.revocations(casey.id)).map(r => r.reason)).toEqual(['member_disabled', 'member_disabled', 'member_reinstated']);
      const fresh = await s.session(s.ts, casey.id);
      expect(await s.usable(s.ts, fresh)).toBe(true);
    });
  }, 60_000);

  it('L2 (m8): login racing disable is refused by the session insert guard or revoked by the disable; reinstatement restores nothing', async () => {
    await withScenario('m8', 'l2', async s => {
      const adm = await s.seed(TS, 'thrivesource', 'admin.l2@example.test', 'workspace_admin');
      const casey = await s.seed(TS, 'thrivesource', 'casey.l2@example.test', 'contractor');
      const before = await s.session(s.ts, casey.id);

      // (a) The disable commits between the login's member read and its insert: the insert guard re-reads the member
      // under the shared session lock and refuses.
      const login = s.party('hv-l2-login', undefined, /^INSERT INTO auth_sessions/);
      const token = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43);
      const logging = settle((async () => {
        expect((await login.store.findMemberByAuthUserId(casey.uid))?.status).toBe('active');
        const now = new Date();
        await login.store.createSession({ tokenHash: sha256Hex(token), memberId: casey.id, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 43200_000) });
      })());
      await login.atGate;
      expect(await s.ts.disableMemberAndRevokeSessions(casey.id, adm.id, new Date())).toEqual({ changed: true, sessionsRevoked: 1 });
      login.release();
      const r = await logging;
      log('L2a login outcome', JSON.stringify(r));
      expect(r.ok ? '' : r.e).toMatch(/sessions can be created only for an active member of an active organization/);
      expect(await s.live(casey.id)).toBe(0);

      // Reinstate, sign in, then (b): the login's INSERT is uncommitted (shared session lock held) when the disable runs.
      expect(await reinstate(s, casey.id, 'REH-L2-REINSTATE-1')).toBe(0);
      const mid = await s.session(s.ts, casey.id);
      const raw = await s.operator('hv-l2-raw-login');
      const token2 = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43);
      const dis = s.party('hv-l2-disable', undefined);
      try {
        await raw.query('BEGIN'); await raw.query('SET LOCAL ROLE hourvia_auth_runtime');
        await raw.query(`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
          VALUES ($1, $2, now(), now(), now() + interval '30 minutes', now() + interval '12 hours')`, [sha256Hex(token2), casey.id]);
        const disabling = settle(dis.store.disableMemberAndRevokeSessions(casey.id, adm.id, new Date()));
        log('L2b disable blocked', JSON.stringify(await s.waitApp('hv-l2-disable', 'advisory')));
        await raw.query('COMMIT');
        expect(await disabling).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 2 } }); // `mid` and the raced login
      } finally { await raw.query('ROLLBACK').catch(() => undefined); await raw.end(); }
      expect(await s.live(casey.id)).toBe(0);

      expect(await reinstate(s, casey.id, 'REH-L2-REINSTATE-2')).toBe(0);
      expect(await s.states(casey.id)).toEqual({ member: 'active', organization: 'active' });
      for (const t of [before, token, mid, token2]) expect(await s.usable(s.ts, t)).toBe(false);
      expect(await s.revocations(casey.id)).toEqual([
        { reason: 'member_disabled', by: adm.id }, { reason: 'member_disabled', by: adm.id }, { reason: 'member_disabled', by: adm.id }]);
      const fresh = await s.session(s.ts, casey.id);
      expect(await s.usable(s.ts, fresh)).toBe(true);
    });
  }, 60_000);
});
