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
import {
  M8_PROPOSAL_SQL, ORGANIZATIONS_SQL, PLATFORM_ADMIN_SQL, PLATFORM_ROLES_SQL, PLATFORM_SQL, ROLE_SQL, SCHEMA_SQL, SEARCH_PATH_SQL, SUPER_ADMIN_SQL,
} from './testing/harness';

interface PgClient { connect(): Promise<void>; end(): Promise<void>; query<T = any>(text: string, params?: unknown[]): Promise<{ rows: T[] }> }
interface PgPool { query: PgClient['query']; connect(): Promise<PgClient & { release(): void }>; end(): Promise<void> }
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
  const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: db, max: 12, application_name: `m8-app-${name}` });
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
  return { db, op, mon, pool, sql, storeFor, service, seed, consumed, session, waitBlocked, close, ts: storeFor(ctx(TS, 'thrivesource')), acme: storeFor(ctx(ACME, 'acme')) };
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
});
