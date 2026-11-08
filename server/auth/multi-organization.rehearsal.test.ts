// DISPOSABLE POSTGRESQL 18 CONCURRENCY REHEARSAL for the Sprint 3.0.1 M8 hardening — skipped unless started by
// scripts/rehearsal/multi-organization-rehearsal.sh, which creates a brand-new local PostgreSQL 18 cluster (Unix socket
// only, no TCP listener) in a temp directory, runs this file, then deletes the cluster. No Netlify database, URL or
// credential is ever read; beforeAll refuses anything that is not that freshly initialised cluster.
//
// It applies M1-M7 exactly as shipped plus the M8 PROPOSAL (db/proposals/sprint-3.0/) as the non-superuser
// netlifydb_owner, and drives the real application code (PostgresAuthStore, OrganizationAccessService) through real
// connection pools, so every race below runs on separate PostgreSQL backends.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { THRIVESOURCE_ORGANIZATION_ID, mintMultiOrganizationCapabilityForOfflineTests, organizationContextForVerifiedMembership, type OrganizationContext, type OrganizationId } from '../../src/domain/organization';
import { sha256Hex } from './crypto';
import { IdentityDirectory } from './organization-directory';
import { OrganizationAccessService } from './organization-service';
import { poolSqlClient } from './runtime';
import { roleScopedSqlClient, statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { PostgresTenancyStore } from './store-tenancy';
import type { SqlClient } from './types';
import {
  M8_PROPOSAL_SQL, ORGANIZATIONS_SQL, PLATFORM_ADMIN_SQL, PLATFORM_ROLES_SQL, PLATFORM_SQL, ROLE_SQL, SCHEMA_SQL, SEARCH_PATH_SQL, SUPER_ADMIN_SQL,
} from './testing/harness';

interface PgClient { connect(): Promise<void>; end(): Promise<void>; query<T = any>(text: string, params?: unknown[]): Promise<{ rows: T[] }> }
interface PgPool { query: PgClient['query']; connect(): Promise<PgClient & { release(): void }>; end(): Promise<void>; on(event: 'error', fn: (e: Error) => void): void }
const pg = createRequire(import.meta.url)('pg') as { Client: new (c: Record<string, unknown>) => PgClient; Pool: new (c: Record<string, unknown>) => PgPool };

const env = process.env;
const SOCKET = env.HOURVIA_REHEARSAL_PGSOCKET ?? '';
const PORT = Number(env.HOURVIA_REHEARSAL_PGPORT ?? 0);
const PGDATA = env.HOURVIA_REHEARSAL_PGDATA ?? '';
const SUPER = 'rehearsal_super';
const enabled = env.HOURVIA_M8_REHEARSAL === 'disposable-local-cluster' && !!SOCKET && PORT > 0 && !!PGDATA;
const TEMPLATE = 'hourvia_m8_rehearsal_template';
const TS = THRIVESOURCE_ORGANIZATION_ID;
const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const cap = mintMultiOrganizationCapabilityForOfflineTests();
const ctx = (o: OrganizationId, slug: string): OrganizationContext => organizationContextForVerifiedMembership({ organizationId: o, workspaceId: slug }, { id: o, slug, status: 'active' }, cap);
const log = (...a: unknown[]) => console.log('[m8-rehearsal]', ...a);
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const settle = <T>(p: Promise<T>) => p.then(v => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e instanceof Error ? e.message : e) }));

let admin: PgClient;
const created = new Set<string>();
const client = (database: string, user = 'netlifydb_owner', app = 'm8-rehearsal') => new pg.Client({ host: SOCKET, port: PORT, user, database, application_name: app });

async function scenario(name: string, seats: number) {
  const db = `hourvia_m8_${name}`;
  await admin.query(`CREATE DATABASE ${db} TEMPLATE ${TEMPLATE} OWNER netlifydb_owner`);
  created.add(db);
  const op = client(db), mon = client(db, SUPER, 'm8-monitor');
  await op.connect(); await mon.connect();
  await op.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'ACME', 'customer', 'active')`, [ACME]);
  await op.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref) VALUES ($1, 'customer', 'standard', $2, 'REH-M8-1')`, [ACME, seats]);
  const app = `m8-app-${name}`;
  const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: db, max: 12, application_name: app });
  pool.on('error', () => undefined); // idle clients are terminated by DROP DATABASE ... WITH (FORCE)
  const sql = statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool as any)));
  const storeFor = (c: OrganizationContext) => new PostgresAuthStore(sql, c);
  const service = new OrganizationAccessService({
    capability: cap, directory: new IdentityDirectory(sql), storeFor, tenancyFor: c => new PostgresTenancyStore(sql, c),
    transaction: fn => sql.transaction(tx => fn(c => new PostgresAuthStore(tx, c))),
    now: () => new Date(), session: { idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200 },
  });
  /** Operator-side member row (owner SQL). */
  const seed = async (org: OrganizationId, slug: string, email: string, role: string, status = 'active', uid: string = randomUUID()) => {
    const { rows } = await op.query<{ id: string }>(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
      VALUES ($1, $2, $3, $4, 'r', $5, $6, CASE WHEN $6 <> 'invited' THEN now() END) RETURNING id`, [org, slug, uid, email, role, status]);
    return { id: rows[0]!.id, uid };
  };
  const consumed = async () => (await mon.query<{ n: number }>(`SELECT ((SELECT count(*) FROM workspace_members WHERE organization_id = $1 AND status = 'active')
      + (SELECT count(*) FROM workspace_invitations i JOIN workspace_members m ON m.id = i.member_id WHERE i.organization_id = $1 AND i.status = 'pending' AND i.expires_at > now() AND m.status = 'invited'))::int AS n`, [ACME])).rows[0]!.n;
  const session = async (store: PostgresAuthStore, memberId: string) => {
    const token = randomUUID().replace(/-/g, '').repeat(2).slice(0, 43);
    const now = new Date();
    await store.createSession({ tokenHash: sha256Hex(token), memberId, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 43200_000) });
    return { ip: '203.0.113.10', sessionToken: token };
  };
  const waitBlocked = async (pid: number) => {
    for (let i = 0; i < 200; i++) {
      const r = (await mon.query<{ w: string | null; t: string | null }>(`SELECT wait_event_type w, wait_event t FROM pg_stat_activity WHERE pid = $1`, [pid])).rows[0];
      if (r?.w === 'Lock') return r;
      await sleep(25);
    }
    throw new Error(`pid ${pid} never blocked`);
  };
  const close = async () => { await pool.end().catch(() => undefined); for (const c of [op, mon]) await c.end().catch(() => undefined); };
  return { db, app, op, mon, pool, sql, storeFor, service, seed, consumed, session, waitBlocked, close, ts: storeFor(ctx(TS, 'thrivesource')), acme: storeFor(ctx(ACME, 'acme')) };
}
type Scenario = Awaited<ReturnType<typeof scenario>>;
async function withScenario(name: string, seats: number, fn: (s: Scenario) => Promise<void>) {
  const s = await scenario(name, seats);
  try { await fn(s); } finally { await s.close(); await admin.query(`DROP DATABASE IF EXISTS ${s.db} WITH (FORCE)`); created.delete(s.db); }
}
const invitation = (s: Scenario, inviter: string, email: string) => {
  const now = new Date();
  return s.acme.upsertInvitation({ email, role: 'contractor', displayName: '', authUserId: randomUUID(), invitedBy: inviter, now, expiresAt: new Date(now.getTime() + 86400_000) });
};

// ---- Sprint 3.0.2: deterministic interleavings ------------------------------------------------------------------------
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
/** The production switch path, whose single transaction pauses before `pauseBefore` (runs on the scenario pool). */
function gatedSwitch(s: Scenario, pauseBefore: RegExp) {
  const g = gate(pauseBefore);
  const service = new OrganizationAccessService({
    capability: cap, directory: new IdentityDirectory(s.sql), storeFor: s.storeFor, tenancyFor: c => new PostgresTenancyStore(s.sql, c),
    transaction: fn => s.sql.transaction(tx => fn(c => new PostgresAuthStore(g.wrap(tx), c))),
    now: () => new Date(), session: { idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200 },
  });
  return { service, atGate: g.atGate, release: g.release };
}
/** Another application instance: its own one-connection pool (identified by application_name), optionally gated. */
function party(s: Scenario, app: string, c: OrganizationContext, pauseBefore?: RegExp) {
  const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: s.db, max: 1, application_name: app });
  pool.on('error', () => undefined);
  const g = gate(pauseBefore);
  const store = new PostgresAuthStore(g.wrap(statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool as any)))), c);
  return { pool, store, atGate: g.atGate, release: g.release };
}
/** Waits until a backend of `app` is blocked on a heavyweight lock (optionally of one kind, e.g. 'advisory'). */
async function waitApp(s: Scenario, app: string, event?: string) {
  for (let i = 0; i < 200; i++) {
    const r = (await s.mon.query<{ w: string; t: string }>(`SELECT wait_event_type w, wait_event t FROM pg_stat_activity
      WHERE datname = current_database() AND application_name = $1 AND wait_event_type = 'Lock'`, [app])).rows[0];
    if (r && (!event || r.t === event)) return r;
    await sleep(25);
  }
  throw new Error(`${app} never blocked${event ? ` on ${event}` : ''}`);
}
/** Dana: Manager in ThriveSource and Contractor in ACME, one identity. */
async function dana(s: Scenario, tag: string) {
  const uid = randomUUID();
  const t = await s.seed(TS, 'thrivesource', `dana.${tag}@example.test`, 'workspace_manager', 'active', uid);
  const am = await s.seed(ACME, 'acme', `dana.${tag}@example.test`, 'contractor', 'active', uid);
  return { t, am };
}
const live = async (s: Scenario, memberId: string) => (await s.mon.query<{ n: number }>(`SELECT count(*)::int n FROM auth_sessions WHERE member_id = $1 AND revoked_at IS NULL`, [memberId])).rows[0]!.n;
const revocations = async (s: Scenario, memberId: string) => (await s.mon.query<{ reason: string; by: string | null }>(
  `SELECT revoked_reason AS reason, revoked_by_member_id::text AS by FROM auth_sessions WHERE member_id = $1 ORDER BY created_at, id`, [memberId])).rows;
const runtimeTx = async (s: Scenario) => {
  const c = client(s.db, 'netlifydb_owner', 'm8-raw-runtime');
  await c.connect();
  const pid = (await c.query<{ p: number }>(`SELECT pg_backend_pid() p`)).rows[0]!.p;
  await c.query('BEGIN'); await c.query('SET LOCAL ROLE hourvia_auth_runtime');
  return { c, pid };
};
const tokenOf = (o: { cookie?: unknown }) => ({ ip: '203.0.113.10', sessionToken: (o.cookie as { set: string }).set });
const TS_CTX = () => ctx(TS, 'thrivesource');
const ACME_CTX = () => ctx(ACME, 'acme');

describe.skipIf(!enabled)('Sprint 3.0.1 M8 concurrency rehearsal on a disposable PostgreSQL 18 cluster', () => {
  beforeAll(async () => {
    const socketDir = resolve(SOCKET);
    if (!socketDir.startsWith(resolve(tmpdir()) + '/') || !resolve(PGDATA).startsWith(resolve(tmpdir()) + '/')) throw new Error('refusing: socket/data dir not under the temp directory');
    admin = client('postgres', SUPER, 'm8-admin');
    await admin.connect();
    const ev = (await admin.query(`SELECT current_setting('server_version') v, current_setting('server_version_num')::int vn,
        current_setting('data_directory') data, current_setting('listen_addresses') listen, inet_server_addr() addr,
        current_setting('default_transaction_isolation') iso,
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
    await admin.query(`CREATE DATABASE ${TEMPLATE}`);
    created.add(TEMPLATE);
    const t = client(TEMPLATE, SUPER);
    await t.connect();
    await t.query(PLATFORM_ROLES_SQL);
    await t.query('SET SESSION AUTHORIZATION netlifydb_owner');
    for (const [name, sql] of [['M1', SCHEMA_SQL], ['M2', ROLE_SQL], ['M3', SUPER_ADMIN_SQL], ['M4', PLATFORM_SQL], ['M5', PLATFORM_ADMIN_SQL],
      ['M6', SEARCH_PATH_SQL], ['M7', ORGANIZATIONS_SQL], ['M8 proposal', M8_PROPOSAL_SQL]] as const) {
      await t.query('BEGIN'); await t.query(sql); await t.query('COMMIT');
      log(`applied ${name}`);
    }
    await t.end();
  }, 180_000);

  afterAll(async () => {
    if (!admin) return;
    for (const db of [...created]) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`).then(() => created.delete(db));
    const left = (await admin.query<{ d: string[] }>(`SELECT array_agg(datname::text ORDER BY datname) d FROM pg_database`)).rows[0]!.d;
    log('databases after cleanup', JSON.stringify(left));
    await admin.end();
    expect(left).toEqual(['postgres', 'template0', 'template1']);
  });

  it('S1. 12 concurrent invitations for the last 2 seats: exactly 2 succeed, the limit is never exceeded', async () => {
    await withScenario('s1', 3, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const results = await Promise.all(Array.from({ length: 12 }, (_, i) => settle(invitation(s, a.id, `c${i}@acme.test`))));
      const ok = results.filter(r => r.ok).length;
      log('S1', JSON.stringify({ ok, refused: results.filter(r => !r.ok).map(r => (r as { e: string }).e).filter((v, i, x) => x.indexOf(v) === i) }));
      expect(ok).toBe(2);
      expect(results.filter(r => !r.ok).every(r => /no seat is available/.test((r as { e: string }).e))).toBe(true);
      expect(await s.consumed()).toBe(3);
    });
  });

  it('S2. deterministic interleaving: a second seat consumer blocks on the first and then sees its commit', async () => {
    await withScenario('s2', 2, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const x = await s.seed(ACME, 'acme', 'x@acme.test', 'contractor', 'invited');
      const y = await s.seed(ACME, 'acme', 'y@acme.test', 'contractor', 'invited');
      const c1 = client(s.db), c2 = client(s.db);
      await c1.connect(); await c2.connect();
      try {
        const pid2 = (await c2.query<{ p: number }>(`SELECT pg_backend_pid() p`)).rows[0]!.p;
        const ins = (m: string, e: string) => [`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
          VALUES ($1, 'acme', $2, $3, 'contractor', 'pending', $4, now(), now() + interval '1 day')`, [ACME, m, e, a.id] as unknown[]] as const;
        await c1.query('BEGIN'); await c1.query('SET LOCAL ROLE hourvia_auth_runtime');
        await c1.query(...ins(x.id, 'x@acme.test')); // holds the seat lock, uncommitted
        await c2.query('BEGIN'); await c2.query('SET LOCAL ROLE hourvia_auth_runtime');
        const second = settle(c2.query(...ins(y.id, 'y@acme.test')));
        const blocked = await s.waitBlocked(pid2);
        log('S2 blocked on', JSON.stringify(blocked));
        expect(blocked).toMatchObject({ w: 'Lock', t: 'advisory' });
        await c1.query('COMMIT');
        const r = await second;
        expect(r.ok).toBe(false);
        expect((r as { e: string }).e).toMatch(/no seat is available/);
        await c2.query('ROLLBACK');
        expect(await s.consumed()).toBe(2);
      } finally { await c1.end(); await c2.end(); }
    });
  });

  it('S3. concurrent operator reactivations for one free seat: exactly one succeeds', async () => {
    await withScenario('s3', 3, async s => {
      await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const m1 = await s.seed(ACME, 'acme', 'm1@acme.test', 'contractor');
      const m2 = await s.seed(ACME, 'acme', 'm2@acme.test', 'contractor');
      await s.op.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = ANY($1)`, [[m1.id, m2.id]]);
      await s.seed(ACME, 'acme', 'm3@acme.test', 'contractor'); // 2 of 3 used now
      for (let round = 0; round < 10; round++) {
        const c1 = client(s.db), c2 = client(s.db);
        await c1.connect(); await c2.connect();
        try {
          const r = await Promise.all([m1, m2].map((m, i) => settle((i ? c2 : c1).query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [m.id]))));
          expect(r.filter(x => x.ok)).toHaveLength(1);
          expect(await s.consumed()).toBe(3);
          await s.op.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = ANY($1) AND status = 'active'`, [[m1.id, m2.id]]);
        } finally { await c1.end(); await c2.end(); }
      }
    });
  });

  it('S4. concurrent acceptance, invitations and reactivation never exceed the limit', async () => {
    await withScenario('s4', 4, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const sus = await s.seed(ACME, 'acme', 'sus@acme.test', 'contractor');
      await s.op.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [sus.id]);
      const pending = await invitation(s, a.id, 'pending@acme.test'); // admin + pending = 2 of 4
      const r = await Promise.all([
        settle(s.acme.acceptInvitation(pending.id, new Date())),
        settle(invitation(s, a.id, 'n1@acme.test')), settle(invitation(s, a.id, 'n2@acme.test')), settle(invitation(s, a.id, 'n3@acme.test')),
        settle((async () => { const c = client(s.db); await c.connect(); try { return await c.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [sus.id]); } finally { await c.end(); } })()),
      ]);
      log('S4', JSON.stringify(r.map(x => x.ok)));
      expect(r[0]).toEqual({ ok: true, v: true }); // acceptance replaces its own reservation and always fits
      expect(r.slice(1).filter(x => x.ok)).toHaveLength(2); // two of {three invitations, one reactivation}
      expect(await s.consumed()).toBe(4);
    });
  });

  it('S5. on real PostgreSQL, REPEATABLE READ and SERIALIZABLE seat and session paths fail closed', async () => {
    await withScenario('s5', 5, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const x = await s.seed(ACME, 'acme', 'x@acme.test', 'contractor', 'invited');
      const c = client(s.db);
      await c.connect();
      try {
        for (const level of ['REPEATABLE READ', 'SERIALIZABLE']) {
          await c.query(`BEGIN ISOLATION LEVEL ${level}`); await c.query('SET LOCAL ROLE hourvia_auth_runtime');
          const r = await settle(c.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
            VALUES ($1, 'acme', $2, 'x@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, x.id, a.id]));
          await c.query('ROLLBACK');
          expect((r as { e: string }).e).toMatch(/require READ COMMITTED/);
          await c.query(`BEGIN ISOLATION LEVEL ${level}`); await c.query('SET LOCAL ROLE hourvia_auth_runtime');
          const t = await settle(c.query(`INSERT INTO auth_sessions (organization_id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
            VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', now() + interval '2 hours')`, [ACME, 'd'.repeat(64), a.id]));
          await c.query('ROLLBACK');
          expect((t as { e: string }).e).toMatch(/requires READ COMMITTED/);
        }
      } finally { await c.end(); }
    });
  });

  it('S6. 10 concurrent switches with one token on separate backends: exactly one replacement', async () => {
    await withScenario('s6', 5, async s => {
      const uid = randomUUID();
      const t = await s.seed(TS, 'thrivesource', 'dana@example.test', 'workspace_manager', 'active', uid);
      await s.seed(ACME, 'acme', 'dana@example.test', 'contractor', 'active', uid);
      const meta = await s.session(s.ts, t.id);
      const out = await Promise.all(Array.from({ length: 10 }, () => s.service.selectOrganization({ organizationId: ACME }, meta)));
      log('S6', JSON.stringify(out.map(o => o.status)));
      expect(out.filter(o => o.status === 200)).toHaveLength(1);
      expect(out.every(o => o.status === 200 || o.status === 401)).toBe(true);
      expect((await s.mon.query(`SELECT count(*)::int n FROM auth_sessions WHERE organization_id = $1 AND revoked_at IS NULL`, [ACME])).rows[0].n).toBe(1);
    });
  });

  it('S7. switch racing logout, member suspension and organization-wide suspension: no session survives what it raced', async () => {
    await withScenario('s7', 100, async s => {
      const summary: Record<string, Record<string, number>> = { logout: {}, suspend: {} };
      for (let i = 0; i < 15; i++) {
        for (const race of ['logout', 'suspend'] as const) {
          const uid = randomUUID();
          const t = await s.seed(TS, 'thrivesource', `d${race}${i}@example.test`, 'workspace_manager', 'active', uid);
          const am = await s.seed(ACME, 'acme', `d${race}${i}@example.test`, 'contractor', 'active', uid);
          const meta = await s.session(s.ts, t.id);
          const other = race === 'logout'
            ? settle(s.ts.revokeSession(sha256Hex(meta.sessionToken), 'logout', new Date()))
            : settle((async () => { const c = client(s.db); await c.connect(); try { await c.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [am.id]); return true; } finally { await c.end(); } })());
          const [sw, ot] = await Promise.all([s.service.selectOrganization({ organizationId: ACME }, meta), other]);
          const key = `${sw.status}/${ot.ok ? (race === 'logout' ? (ot.v ? 'revoked' : 'noop') : 'suspended') : 'error'}`;
          summary[race]![key] = (summary[race]![key] ?? 0) + 1;
          expect(ot.ok).toBe(true); // never a deadlock or an error on the other side
          const live = (await s.mon.query(`SELECT count(*)::int n FROM auth_sessions WHERE member_id = $1 AND revoked_at IS NULL`, [am.id])).rows[0].n;
          if (race === 'suspend') expect(live).toBe(0);
          else {
            // Exactly one of them consumed the source session; a replacement exists only if the switch won.
            expect([sw.status === 200, (ot as { v: string | null }).v !== null].filter(Boolean)).toHaveLength(1);
            expect(live).toBe(sw.status === 200 ? 1 : 0);
          }
        }
      }
      log('S7 outcomes', JSON.stringify(summary));
      // Organization-wide suspension racing several switches: nothing unrevoked remains in the organization.
      const metas = [];
      for (let i = 0; i < 6; i++) {
        const uid = randomUUID();
        const t = await s.seed(TS, 'thrivesource', `o${i}@example.test`, 'workspace_manager', 'active', uid);
        await s.seed(ACME, 'acme', `o${i}@example.test`, 'contractor', 'active', uid);
        metas.push(await s.session(s.ts, t.id));
      }
      const results = await Promise.all([
        ...metas.map(m => s.service.selectOrganization({ organizationId: ACME }, m)),
        (async () => { const c = client(s.db); await c.connect(); try { await c.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]); return { status: 0 }; } finally { await c.end(); } })(),
      ]);
      log('S7 organization race', JSON.stringify(results.map(r => r.status)));
      expect((await s.mon.query(`SELECT count(*)::int n FROM auth_sessions WHERE organization_id = $1 AND revoked_at IS NULL`, [ACME])).rows[0].n).toBe(0);
    });
  }, 120_000);
  // ---- Sprint 3.0.2 concurrency evidence --------------------------------------------------------------------------------
  it('S8. switch winning before logout: logout waits on the consumed row, then matches nothing; and the reverse order', async () => {
    await withScenario('s8', 100, async s => {
      // (a) switch first: the source session is consumed (row locked) and the transaction is still open.
      const a = await dana(s, 's8a');
      const meta = await s.session(s.ts, a.t.id);
      const sw = gatedSwitch(s, /^INSERT INTO auth_sessions/);
      const logout = party(s, 'hv-s8-logout', TS_CTX());
      try {
        const switching = sw.service.selectOrganization({ organizationId: ACME }, meta);
        await sw.atGate;
        const out = settle(logout.store.revokeSession(sha256Hex(meta.sessionToken), 'logout', new Date()));
        log('S8a logout blocked', JSON.stringify(await waitApp(s, 'hv-s8-logout')));
        sw.release();
        const [r, l] = await Promise.all([switching, out]);
        log('S8a', JSON.stringify({ switch: r.status, logout: l }));
        expect(r.status).toBe(200);
        expect(l).toEqual({ ok: true, v: null }); // the winner already revoked the source: logout is a no-op
        expect(await revocations(s, a.t.id)).toEqual([{ reason: 'organization_switched', by: a.t.id }]);
        expect([await live(s, a.t.id), await live(s, a.am.id)]).toEqual([0, 1]);
        const next = tokenOf(r);
        expect(await s.service.principal(next)).toMatchObject({ id: a.am.id, organizationId: ACME });
        // Logging out with the replacement token ends it.
        expect(await s.acme.revokeSession(sha256Hex(next.sessionToken), 'logout', new Date())).toBe(a.am.id);
        expect(await s.service.principal(next)).toBeNull();
      } finally { sw.release(); logout.release(); await logout.pool.end(); }

      // (b) logout first (uncommitted): the switch's conditional consume waits, then matches nothing. No replacement.
      const b = await dana(s, 's8b');
      const metaB = await s.session(s.ts, b.t.id);
      const raw = await runtimeTx(s);
      try {
        await raw.c.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'logout', revoked_by_member_id = member_id
          WHERE token_hash = $1 AND organization_id = $2 AND revoked_at IS NULL`, [sha256Hex(metaB.sessionToken), TS]);
        const switching = s.service.selectOrganization({ organizationId: ACME }, metaB);
        log('S8b switch blocked', JSON.stringify(await waitApp(s, s.app)));
        await raw.c.query('COMMIT');
        const r = await switching;
        expect(r.status).toBe(401);
        expect([await live(s, b.t.id), await live(s, b.am.id)]).toEqual([0, 0]);
        expect(await revocations(s, b.t.id)).toEqual([{ reason: 'logout', by: b.t.id }]);
      } finally { await raw.c.end(); }
    });
  });

  it('S9. switch racing administrator session revocation, in both orders and across organizations', async () => {
    await withScenario('s9', 100, async s => {
      const tsAdmin = await s.seed(TS, 'thrivesource', 'admin.s9@thrivesource.test', 'workspace_admin');
      const acmeAdmin = await s.seed(ACME, 'acme', 'admin.s9@acme.test', 'workspace_admin');

      // (a) administrator first (uncommitted): the switch waits on the source row and then finds it revoked.
      const a = await dana(s, 's9a');
      const metaA = await s.session(s.ts, a.t.id);
      const raw = await runtimeTx(s);
      try {
        await raw.c.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'admin_revoked', revoked_by_member_id = $2
          WHERE member_id = $1 AND organization_id = $3 AND revoked_at IS NULL`, [a.t.id, tsAdmin.id, TS]);
        const switching = s.service.selectOrganization({ organizationId: ACME }, metaA);
        log('S9a switch blocked', JSON.stringify(await waitApp(s, s.app)));
        await raw.c.query('COMMIT');
        expect((await switching).status).toBe(401);
        expect([await live(s, a.t.id), await live(s, a.am.id)]).toEqual([0, 0]);
        expect(await revocations(s, a.t.id)).toEqual([{ reason: 'admin_revoked', by: tsAdmin.id }]);
      } finally { await raw.c.end(); }

      // (b) switch first: the ThriveSource administrator's revocation waits on the consumed row, then revokes nothing in
      // ThriveSource. The replacement belongs to the ACME membership, which only ACME's administrator can end.
      const b = await dana(s, 's9b');
      const metaB = await s.session(s.ts, b.t.id);
      const sw = gatedSwitch(s, /^INSERT INTO auth_sessions/);
      const adm = party(s, 'hv-s9-admin', TS_CTX());
      try {
        const switching = sw.service.selectOrganization({ organizationId: ACME }, metaB);
        await sw.atGate;
        const revoking = settle(adm.store.revokeMemberSessions(b.t.id, 'admin_revoked', new Date(), tsAdmin.id));
        log('S9b admin blocked', JSON.stringify(await waitApp(s, 'hv-s9-admin')));
        sw.release();
        const [r, v] = await Promise.all([switching, revoking]);
        log('S9b', JSON.stringify({ switch: r.status, revoked: v }));
        expect(r.status).toBe(200);
        expect(v).toEqual({ ok: true, v: 0 });
        expect([await live(s, b.t.id), await live(s, b.am.id)]).toEqual([0, 1]);
        expect(await s.acme.revokeMemberSessions(b.am.id, 'admin_revoked', new Date(), acmeAdmin.id)).toBe(1);
        expect(await s.service.principal(tokenOf(r))).toBeNull();
      } finally { sw.release(); adm.release(); await adm.pool.end(); }

      // (c) ACME administrator revokes while the replacement is inserted but uncommitted: the revocation does not wait and
      // ends what was committed at that instant (nothing); the replacement commits afterwards. Revocation is a point-in-time
      // action; a lasting block is disable or suspension, which serialize with session creation (S10, S11).
      const c = await dana(s, 's9c');
      const metaC = await s.session(s.ts, c.t.id);
      const sw2 = gatedSwitch(s, /^INSERT INTO auth_audit_events/);
      try {
        const switching = sw2.service.selectOrganization({ organizationId: ACME }, metaC);
        await sw2.atGate;
        const t0 = Date.now();
        expect(await s.acme.revokeMemberSessions(c.am.id, 'admin_revoked', new Date(), acmeAdmin.id)).toBe(0);
        log(`S9c ACME revocation returned in ${Date.now() - t0} ms while the switch was open`);
        sw2.release();
        expect((await switching).status).toBe(200);
        expect(await live(s, c.am.id)).toBe(1);
      } finally { sw2.release(); }
    });
  });

  it('S10. organization suspension during an active switch transaction: revoked if the session committed first, refused otherwise', async () => {
    // (a) switch holds the shared session lock with its replacement inserted; suspension waits, then revokes it.
    await withScenario('s10a', 100, async s => {
      const d = await dana(s, 's10a');
      const meta = await s.session(s.ts, d.t.id);
      const sw = gatedSwitch(s, /^INSERT INTO auth_audit_events/);
      const op = client(s.db, 'netlifydb_owner', 'hv-s10-operator');
      await op.connect();
      try {
        const switching = sw.service.selectOrganization({ organizationId: ACME }, meta);
        await sw.atGate;
        const suspending = settle(op.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]));
        const blocked = await waitApp(s, 'hv-s10-operator', 'advisory');
        log('S10a suspension blocked', JSON.stringify(blocked));
        sw.release();
        const [r, x] = await Promise.all([switching, suspending]);
        expect(r.status).toBe(200);
        expect(x.ok).toBe(true);
        expect(await revocations(s, d.am.id)).toEqual([{ reason: 'organization_suspended', by: null }]);
        expect(await s.service.principal(tokenOf(r))).toBeNull();
        expect((await s.mon.query(`SELECT count(*)::int n FROM auth_sessions WHERE organization_id = $1 AND revoked_at IS NULL`, [ACME])).rows[0].n).toBe(0);
      } finally { sw.release(); await op.end(); }
    });
    // (b) suspension first (uncommitted): the switch's session insert waits on the lock, then is refused; the whole switch
    // rolls back, so the ThriveSource source session stays valid and nothing exists in ACME.
    await withScenario('s10b', 100, async s => {
      const d = await dana(s, 's10b');
      const meta = await s.session(s.ts, d.t.id);
      const op = client(s.db, 'netlifydb_owner', 'hv-s10-operator');
      await op.connect();
      try {
        await op.query('BEGIN');
        await op.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]);
        const switching = s.service.selectOrganization({ organizationId: ACME }, meta);
        log('S10b switch blocked', JSON.stringify(await waitApp(s, s.app, 'advisory')));
        await op.query('COMMIT');
        const r = await switching;
        log('S10b switch outcome', r.status);
        expect(r.status).toBe(503);
        expect([await live(s, d.t.id), await live(s, d.am.id)]).toEqual([1, 0]);
        expect(await s.service.principal(meta)).toMatchObject({ id: d.t.id, organizationId: TS });
      } finally { await op.end(); }
    });
  });

  it('S11. disabled-member reinstatement and session invalidation under concurrency', async () => {
    await withScenario('s11', 100, async s => {
      const acmeAdmin = await s.seed(ACME, 'acme', 'admin.s11@acme.test', 'workspace_admin');
      const d = await dana(s, 's11');
      const old1 = await s.session(s.acme, d.am.id), old2 = await s.session(s.acme, d.am.id);
      const metaTs = await s.session(s.ts, d.t.id);

      // (a) a switch into ACME holds the shared lock with its replacement uncommitted; the Administrator's disable locks the
      // member, changes its status, waits for the lock in the status trigger, then revokes the two committed sessions AND
      // the replacement. Sprint 3.0.3: the count includes trigger revocations, so it is 3 (Sprint 3.0.2 reported 2).
      const sw = gatedSwitch(s, /^INSERT INTO auth_audit_events/);
      const dis = party(s, 'hv-s11-disable', ACME_CTX());
      let replacement: { ip: string; sessionToken: string };
      try {
        const switching = sw.service.selectOrganization({ organizationId: ACME }, metaTs);
        await sw.atGate;
        const disabling = settle(dis.store.disableMemberAndRevokeSessions(d.am.id, acmeAdmin.id, new Date()));
        log('S11a disable blocked', JSON.stringify(await waitApp(s, 'hv-s11-disable', 'advisory')));
        sw.release();
        const [r, x] = await Promise.all([switching, disabling]);
        log('S11a', JSON.stringify({ switch: r.status, disable: x }));
        expect(r.status).toBe(200);
        expect(x).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 3 } });
        replacement = tokenOf(r);
      } finally { sw.release(); dis.release(); await dis.pool.end(); }
      expect(await revocations(s, d.am.id)).toEqual([
        { reason: 'member_disabled', by: acmeAdmin.id }, { reason: 'member_disabled', by: acmeAdmin.id }, { reason: 'member_disabled', by: acmeAdmin.id }]);
      const audit = (await s.mon.query<{ a: string; src: string }>(`SELECT details->>'authority' a, details->>'source' src FROM auth_audit_events
        WHERE event_type = 'session_revocation' AND subject_member_id = $1 ORDER BY id`, [d.am.id])).rows;
      expect(audit).toEqual(Array(3).fill({ a: 'workspace_admin', src: 'application' }));
      for (const m of [old1, old2, replacement]) expect(await s.service.principal(m)).toBeNull();

      // (b) operator reinstatement: the member is active again, but no old session is (revocation is final).
      await s.op.query('BEGIN');
      await s.op.query(`SELECT set_config('hourvia.member_reinstatement', 'approved', true)`);
      await s.op.query(`UPDATE workspace_members SET status = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = $1`, [d.am.id]);
      await s.op.query('COMMIT');
      for (const m of [old1, old2, replacement]) expect(await s.service.principal(m)).toBeNull();
      expect(await live(s, d.am.id)).toBe(0);
      const fresh = await s.session(s.acme, d.am.id);
      expect(await s.service.principal(fresh)).toMatchObject({ id: d.am.id, organizationId: ACME });

      // (c) reverse order: the disable holds the exclusive lock (status changed, transaction open); a switch into ACME
      // waits on it and is then refused; the switch rolls back and the ThriveSource source session stays valid.
      const metaTs2 = await s.session(s.ts, d.t.id);
      const dis2 = party(s, 'hv-s11-disable2', ACME_CTX(), /^UPDATE workspace_invitations SET status = 'revoked'/);
      try {
        const disabling = settle(dis2.store.disableMemberAndRevokeSessions(d.am.id, acmeAdmin.id, new Date()));
        await dis2.atGate;
        const switching = s.service.selectOrganization({ organizationId: ACME }, metaTs2);
        log('S11c switch blocked', JSON.stringify(await waitApp(s, s.app, 'advisory')));
        dis2.release();
        const [x, r] = await Promise.all([disabling, switching]);
        log('S11c', JSON.stringify({ disable: x, switch: r.status }));
        expect(x).toEqual({ ok: true, v: { changed: true, sessionsRevoked: 1 } });
        expect(r.status).toBe(503);
        expect(await live(s, d.am.id)).toBe(0);
        expect(await s.service.principal(fresh)).toBeNull();
        expect(await s.service.principal(metaTs2)).toMatchObject({ id: d.t.id, organizationId: TS });
      } finally { dis2.release(); await dis2.pool.end(); }
    });
  }, 120_000);
  // ---- Sprint 3.0.5: invitation state machine under real concurrency ---------------------------------------------------
  it('S12. concurrent acceptance on separate backends: exactly one wins; a racing second acceptance or revoke is refused', async () => {
    await withScenario('s12', 20, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      // (a) 10 application acceptances of one invitation at once: exactly one activates the member.
      const m = await invitation(s, a.id, 'race@acme.test');
      const out = await Promise.all(Array.from({ length: 10 }, () => settle(s.acme.acceptInvitation(m.id, new Date()))));
      log('S12a', JSON.stringify(out.map(o => o.ok ? o.v : o.e)));
      expect(out.filter(o => o.ok && o.v === true)).toHaveLength(1);
      expect(out.every(o => o.ok)).toBe(true);
      expect((await s.mon.query(`SELECT count(*)::int n FROM workspace_invitations WHERE member_id = $1 AND status = 'accepted'`, [m.id])).rows[0].n).toBe(1);

      // (b)-(d) raw runtime statements WITHOUT the status filter, deterministically interleaved on the row lock.
      const raceOnce = async (email: string, first: string, level: string) => {
        const x = await invitation(s, a.id, email);
        const c1 = client(s.db), c2 = client(s.db);
        await c1.connect(); await c2.connect();
        try {
          const pid2 = (await c2.query<{ p: number }>(`SELECT pg_backend_pid() p`)).rows[0]!.p;
          await c1.query('BEGIN'); await c1.query('SET LOCAL ROLE hourvia_auth_runtime');
          await c1.query(first, [x.id]);
          await c2.query(`BEGIN ISOLATION LEVEL ${level}`); await c2.query('SET LOCAL ROLE hourvia_auth_runtime');
          const second = settle(c2.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE member_id = $1`, [x.id]));
          const blocked = await s.waitBlocked(pid2);
          await c1.query('COMMIT');
          const r = await second;
          await c2.query('ROLLBACK');
          const final = (await s.mon.query<{ status: string }>(`SELECT status FROM workspace_invitations WHERE member_id = $1`, [x.id])).rows.map(r => r.status);
          return { blocked, r, final };
        } finally { await c1.end(); await c2.end(); }
      };
      const accept = `UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE member_id = $1`;
      const revoke = `UPDATE workspace_invitations SET status = 'revoked' WHERE member_id = $1`;
      const b = await raceOnce('b@acme.test', accept, 'READ COMMITTED');
      const c = await raceOnce('c@acme.test', revoke, 'READ COMMITTED');
      const d = await raceOnce('d@acme.test', accept, 'REPEATABLE READ');
      log('S12b-d', JSON.stringify({ b: [b.blocked, b.r], c: [c.blocked, c.r], d: [d.blocked, d.r] }));
      for (const x of [b, c, d]) expect(x.blocked.w).toBe('Lock');
      expect(b.r.ok).toBe(false); expect((b.r as { e: string }).e).toMatch(/acceptance is final/);
      expect(b.final).toEqual(['accepted']);
      expect(c.r.ok).toBe(false); expect((c.r as { e: string }).e).toMatch(/accepted and revoked invitations are final/);
      expect(c.final).toEqual(['revoked']);
      expect(d.r.ok).toBe(false); expect((d.r as { e: string }).e).toMatch(/could not serialize access/);
      expect(d.final).toEqual(['accepted']);
    });
  }, 120_000);
  // ---- Sprint 3.0.5 (PR #23 correction): expiry is judged by the real clock, not the transaction start ------------------
  it('S13. a transaction opened before an invitation expires cannot accept it after expiry (raw and application paths)', async () => {
    await withScenario('s13', 20, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const shortInvitation = async (email: string, seconds: number) => {
        const m = await s.seed(ACME, 'acme', email, 'contractor', 'invited');
        await s.op.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
          VALUES ($1, 'acme', $2, $3, 'contractor', 'pending', $4, now(), now() + $5 * interval '1 second')`, [ACME, m.id, email, a.id, seconds]);
        return m;
      };
      const statusOf = async (memberId: string) => (await s.mon.query<{ i: string; m: string }>(`SELECT i.status i, m.status m FROM workspace_invitations i
        JOIN workspace_members m ON m.id = i.member_id WHERE i.member_id = $1`, [memberId])).rows[0];

      // (a) raw runtime statements: the transaction (and so now()) starts before expiry; the UPDATE runs after it.
      for (const claimed of ['now()', `now() - interval '1 second'`]) {
        const x = await shortInvitation(`raw${claimed.length}@acme.test`, 2);
        const c = client(s.db);
        await c.connect();
        try {
          await c.query('BEGIN'); await c.query('SET LOCAL ROLE hourvia_auth_runtime');
          const t = (await c.query<{ before: boolean }>(`SELECT now() < (SELECT expires_at FROM workspace_invitations WHERE member_id = $1) AS before`, [x.id])).rows[0]!;
          expect(t.before).toBe(true);
          await c.query(`SELECT pg_sleep(3)`);
          const late = (await c.query<{ after: boolean }>(`SELECT clock_timestamp() > (SELECT expires_at FROM workspace_invitations WHERE member_id = $1) AS after`, [x.id])).rows[0]!;
          expect(late.after).toBe(true);
          const r = await settle(c.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = ${claimed} WHERE member_id = $1 AND status = 'pending'`, [x.id]));
          log('S13a', claimed, JSON.stringify(r.ok ? 'ACCEPTED (after real expiry)' : r.e));
          await c.query(r.ok ? 'COMMIT' : 'ROLLBACK');
          expect(r.ok).toBe(false);
          expect((r as { e: string }).e).toMatch(/expired invitations cannot be accepted/);
        } finally { await c.end(); }
        expect(await statusOf(x.id)).toEqual({ i: 'pending', m: 'invited' });
      }

      // (b) application path: acceptInvitation's transaction opens (member row locked) before expiry and stalls; its
      // own predicate uses the stale application time captured at the call, so only the database can refuse.
      const y = await shortInvitation('app@acme.test', 2);
      const p = party(s, 'hv-s13-accept', ctx(ACME, 'acme'), /^UPDATE workspace_invitations SET status = 'accepted'/);
      try {
        const accepting = settle(p.store.acceptInvitation(y.id, new Date()));
        await p.atGate;
        await sleep(3000);
        expect((await s.mon.query<{ after: boolean }>(`SELECT clock_timestamp() > expires_at AS after FROM workspace_invitations WHERE member_id = $1`, [y.id])).rows[0]!.after).toBe(true);
        p.release();
        const r = await accepting;
        log('S13b', JSON.stringify(r));
        expect(r.ok).toBe(false);
        expect((r as { e: string }).e).toMatch(/expired invitations cannot be accepted/);
      } finally { p.release(); await p.pool.end(); }
      expect(await statusOf(y.id)).toEqual({ i: 'pending', m: 'invited' });

      // (c) control: the same long transaction still accepts an invitation that is valid by the real clock.
      const z = await shortInvitation('valid@acme.test', 60);
      const c = client(s.db);
      await c.connect();
      try {
        await c.query('BEGIN'); await c.query('SET LOCAL ROLE hourvia_auth_runtime');
        await c.query(`SELECT pg_sleep(1)`);
        await c.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE member_id = $1 AND status = 'pending'`, [z.id]);
        await c.query('COMMIT');
      } finally { await c.end(); }
      expect((await statusOf(z.id))!.i).toBe('accepted');
    });
  }, 120_000);
  // ---- Sprint 3.0.5 (PR #23 billing correction): billing expiry is judged by the real clock -----------------------------
  it('S14. a transaction opened before billing expiry cannot reserve or consume a seat after it (all four seat paths)', async () => {
    await withScenario('s14', 20, async s => {
      const a = await s.seed(ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const billingIn = (seconds: number) => s.op.query(`UPDATE organization_seat_entitlements SET billing_expires_at = now() + $2 * interval '1 second' WHERE organization_id = $1`, [ACME, seconds]);
      /** Opens a transaction while billing is valid, sleeps past expiry (by the real clock), then runs `late`. */
      const straddle = async (user: 'runtime' | 'operator', late: (c: PgClient) => Promise<unknown>, seconds = 2) => {
        await billingIn(seconds);
        const c = client(s.db);
        await c.connect();
        try {
          await c.query('BEGIN');
          if (user === 'runtime') await c.query('SET LOCAL ROLE hourvia_auth_runtime');
          expect((await c.query<{ ok: boolean }>(`SELECT now() < $1::timestamptz AS ok`, [(await s.mon.query(`SELECT billing_expires_at b FROM organization_seat_entitlements WHERE organization_id = $1`, [ACME])).rows[0].b])).rows[0]!.ok).toBe(true);
          await c.query(`SELECT pg_sleep(${seconds + 1})`);
          const r = await settle(late(c));
          await c.query(r.ok ? 'COMMIT' : 'ROLLBACK');
          return r;
        } finally { await c.end(); }
      };
      const results: Record<string, string> = {};
      const expectExpired = (name: string, r: { ok: boolean; e?: string }) => {
        results[name] = r.ok ? 'ALLOWED after real billing expiry' : r.e!;
        expect(r.ok).toBe(false);
        expect(r.e).toMatch(/organization seat entitlement has expired/);
      };

      // (a) runtime: a new pending invitation reserves a seat.
      const inv = await s.seed(ACME, 'acme', 'inv@acme.test', 'contractor', 'invited');
      expectExpired('runtime invitation', await straddle('runtime', c => c.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
        VALUES ($1, 'acme', $2, 'inv@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, inv.id, a.id])));

      // (b) application acceptance: the transaction opens (member locked) before billing expiry and stalls; the activation
      // that follows consumes a seat after it.
      await billingIn(60);
      const pending = await invitation(s, a.id, 'accept@acme.test');
      await billingIn(2);
      const p = party(s, 'hv-s14-accept', ctx(ACME, 'acme'), /^UPDATE workspace_invitations SET status = 'accepted'/);
      try {
        const accepting = settle(p.store.acceptInvitation(pending.id, new Date()));
        await p.atGate;
        await sleep(3000);
        p.release();
        expectExpired('application activation', await accepting as { ok: boolean; e?: string });
      } finally { p.release(); await p.pool.end(); }
      expect((await s.mon.query(`SELECT status FROM workspace_members WHERE id = $1`, [pending.id])).rows[0].status).toBe('invited');

      // (c) operator reactivation of a suspended member.
      const sus = await s.seed(ACME, 'acme', 'sus@acme.test', 'contractor');
      await s.op.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [sus.id]);
      expectExpired('operator reactivation', await straddle('operator', c => c.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [sus.id])));

      // (d) operator insert of an active member.
      expectExpired('operator active insert', await straddle('operator', c => c.query(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
        VALUES ($1, 'acme', $2, 'late@acme.test', 'r', 'contractor', 'active', now())`, [ACME, randomUUID()])));
      log('S14', JSON.stringify(results));

      // (e) control: the same long transaction still consumes a seat while billing is valid by the real clock.
      const ok = await straddle('runtime', c => c.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
        VALUES ($1, 'acme', $2, 'inv@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, inv.id, a.id]), 0);
      expect(ok.ok).toBe(true);
    });
  }, 180_000);
});
