// DISPOSABLE POSTGRESQL 18 CONCURRENCY REHEARSAL for AP-PSA-GRANT — skipped unless started by
//   scripts/rehearsal/platform-grant-rehearsal.sh
// which creates a brand-new local PostgreSQL 18 cluster (Unix socket only, no TCP listener) in a temp directory, runs
// this file against it and then destroys the cluster. It never reads NETLIFY_DB_URL or any other existing database.
//
// The four applied migrations run unchanged. Only inside the disposable cluster, the designated mailbox is swapped for
// a synthetic one in two places: the operator procedure text (in memory, never on disk) and the migration's
// hourvia_is_verified_platform_candidate() body, rewritten from its own pg_get_functiondef with only that literal changed.
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { handleAuthRequest } from './http';
import { poolSqlClient, TransactionClosedError } from './runtime';
import { roleScopedSqlClient, statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { FakeSupabase, GRANT_PLATFORM_SQL, ORIGIN, PLATFORM_ADMIN_SQL, PLATFORM_EMAIL, PLATFORM_ROLES_SQL, PLATFORM_SQL, ROLE_SQL, SCHEMA_SQL, SEARCH_PATH_SQL, SUPER_ADMIN_SQL, fillOperatorSql } from './testing/harness';
import type { AuthConfig, AuthDeps, SqlClient } from './types';

interface PgClient { connect(): Promise<void>; end(): Promise<void>; query<T = any>(text: string, params?: unknown[]): Promise<{ rows: T[]; rowCount: number | null }> }
interface PgModule {
  Client: new (cfg: Record<string, unknown>) => PgClient;
  Pool: new (cfg: Record<string, unknown>) => { query: PgClient['query']; connect(): Promise<PgClient & { release(): void }>; end(): Promise<void> };
}
const pg = createRequire(import.meta.url)('pg') as PgModule;

const env = process.env;
const SOCKET = env.HOURVIA_REHEARSAL_PGSOCKET ?? '';
const PORT = Number(env.HOURVIA_REHEARSAL_PGPORT ?? 0);
const PGDATA = env.HOURVIA_REHEARSAL_PGDATA ?? '';
const SUPER = 'rehearsal_super';
const enabled = env.HOURVIA_GRANT_REHEARSAL === 'disposable-local-cluster' && !!SOCKET && PORT > 0 && !!PGDATA;

const SYNTHETIC_EMAIL = 'grant-rehearsal@hourvia.invalid';
const TEMPLATE = 'hourvia_rehearsal_template';
const LOCK_TIMEOUT_MS = 5000;

// ---- Test-only operator SQL: identical to the shipped procedure except the designated mailbox literal. ----------------
const MAILBOX_CLAUSE = `email = '${PLATFORM_EMAIL}'`;
const REHEARSAL_GRANT_SQL = GRANT_PLATFORM_SQL.replace(MAILBOX_CLAUSE, `email = '${SYNTHETIC_EMAIL}'`);

const log = (...a: unknown[]) => console.log('[rehearsal]', ...a);
const owner = (database: string) => new pg.Client({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database, application_name: 'rehearsal' });
const superuser = (database: string) => new pg.Client({ host: SOCKET, port: PORT, user: SUPER, database, application_name: 'rehearsal-monitor' });
const sha = (s: string) => createHash('sha256').update(s).digest('hex').slice(0, 16);
const grantSql = (uid: string, memberId: string, approval = 'REH-2026-0001') =>
  fillOperatorSql(REHEARSAL_GRANT_SQL, { SUPABASE_AUTH_UID: uid, EXPECTED_MEMBER_ID: memberId, APPROVAL_REF: approval });
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

let admin: PgClient; // superuser connection to the maintenance database of the disposable cluster
const created = new Set<string>();

/** One fresh database per scenario (designation and grant history are immutable, so nothing is reused). */
async function scenarioDb(name: string) {
  const db = `hourvia_rehearsal_${name}`;
  await admin.query(`CREATE DATABASE ${db} TEMPLATE ${TEMPLATE} OWNER netlifydb_owner`);
  created.add(db);
  const a = owner(db), b = owner(db), mon = superuser(db);
  await a.connect(); await b.connect(); await mon.connect();
  const pidA = (await a.query<{ p: number }>(`SELECT pg_backend_pid() p`)).rows[0]!.p;
  const pidB = (await b.query<{ p: number }>(`SELECT pg_backend_pid() p`)).rows[0]!.p;
  expect(pidA).not.toBe(pidB);
  const seed = async (role: string, status: string, email = SYNTHETIC_EMAIL, uid: string = randomUUID()) => {
    const { rows } = await a.query<{ id: string }>(
      `INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status, activated_at, disabled_at)
       VALUES ('thrivesource', $1, $2, 'Rehearsal', $3, $4, CASE WHEN $4 <> 'invited' THEN now() END, CASE WHEN $4 = 'disabled' THEN now() END) RETURNING id`,
      [uid, email, role, status]);
    return { id: rows[0]!.id, uid };
  };
  const state = async () => ({
    designation: (await mon.query(`SELECT auth_user_id, approval_ref FROM platform_super_admin_designation`)).rows,
    privileges: (await mon.query(`SELECT id, auth_user_id, grant_approval_ref, revoked_at FROM platform_privileges ORDER BY granted_at, id`)).rows,
    platformAudit: (await mon.query(`SELECT id, event_type, subject_auth_user_id, details FROM platform_audit_events ORDER BY id`)).rows,
    authAudit: (await mon.query(`SELECT id, event_type, subject_member_id, details FROM auth_audit_events ORDER BY id`)).rows,
    members: (await mon.query(`SELECT id, auth_user_id, email, role, status, activated_at, disabled_at FROM workspace_members ORDER BY id`)).rows,
  });
  /** Waits until `pid` is blocked on a heavyweight lock held by `holder`. */
  const waitBlocked = async (pid: number, holder: number) => {
    for (let i = 0; i < 200; i++) {
      const r = (await mon.query<{ w: string | null; blockers: number[] }>(
        `SELECT wait_event_type w, pg_blocking_pids($1) blockers FROM pg_stat_activity WHERE pid = $1`, [pid])).rows[0];
      if (r?.w === 'Lock' && r.blockers.includes(holder)) return r;
      await sleep(25);
    }
    throw new Error(`pid ${pid} never blocked on ${holder}`);
  };
  const close = async () => { for (const c of [a, b, mon]) await c.end().catch(() => undefined); };
  return { db, a, b, mon, pidA, pidB, seed, state, waitBlocked, close };
}
type Scenario = Awaited<ReturnType<typeof scenarioDb>>;
async function withScenario(name: string, fn: (s: Scenario) => Promise<void>) {
  const s = await scenarioDb(name);
  try { await fn(s); } finally { await s.close(); await admin.query(`DROP DATABASE IF EXISTS ${s.db} WITH (FORCE)`); created.delete(s.db); }
}
const expectNothingGranted = (st: Awaited<ReturnType<Scenario['state']>>) => {
  expect(st.designation).toEqual([]); expect(st.privileges).toEqual([]); expect(st.platformAudit).toEqual([]);
};
const expectConsistentGrant = (st: Awaited<ReturnType<Scenario['state']>>, uid: string, approval = 'REH-2026-0001') => {
  expect(st.designation).toEqual([{ auth_user_id: uid, approval_ref: approval }]);
  expect(st.privileges).toHaveLength(1);
  expect(st.privileges[0]).toMatchObject({ auth_user_id: uid, grant_approval_ref: approval, revoked_at: null });
  expect(st.platformAudit.map((e: any) => [e.event_type, e.subject_auth_user_id])).toEqual([['platform_designation_set', uid], ['platform_privilege_granted', uid]]);
  expect(st.platformAudit[1].details).toMatchObject({ grant_id: st.privileges[0].id, approval_ref: approval, source: 'operator_sql' });
};

describe.skipIf(!enabled)('AP-PSA-GRANT rehearsal on a disposable PostgreSQL 18 cluster', () => {
  beforeAll(async () => {
    // ---- Isolation evidence: refuse anything that is not the cluster this run just created. ----
    const socketDir = resolve(SOCKET);
    if (!socketDir.startsWith(resolve(tmpdir()) + '/') || !resolve(PGDATA).startsWith(resolve(tmpdir()) + '/')) throw new Error('refusing: socket/data dir not under the temp directory');
    admin = superuser('postgres');
    await admin.connect();
    const ev = (await admin.query(`SELECT current_setting('server_version') v, current_setting('server_version_num')::int vn,
        current_setting('data_directory') data, current_setting('listen_addresses') listen, inet_server_addr() addr,
        (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) su, (SELECT system_identifier FROM pg_control_system())::text sysid,
        (SELECT array_agg(datname::text ORDER BY datname) FROM pg_database) dbs,
        (SELECT array_agg(rolname::text ORDER BY rolname) FROM pg_roles WHERE rolname !~ '^pg_') roles`)).rows[0];
    log('isolation evidence', JSON.stringify(ev));
    if (ev.vn < 180000 || ev.vn >= 190000) throw new Error(`refusing: PostgreSQL 18 required, got ${ev.v}`);
    if (resolve(ev.data) !== resolve(PGDATA)) throw new Error('refusing: server data directory is not the disposable one');
    if (ev.listen !== '' || ev.addr !== null) throw new Error('refusing: server has a TCP listener');
    if (!ev.su) throw new Error('refusing: not the local bootstrap superuser (a hosted database never grants this)');
    if (JSON.stringify(ev.dbs) !== JSON.stringify(['postgres', 'template0', 'template1']) || JSON.stringify(ev.roles) !== JSON.stringify([SUPER])) {
      throw new Error('refusing: cluster is not freshly initialised');
    }

    // ---- Template: platform role emulation + the applied migrations, unchanged, as non-superuser netlifydb_owner. ----
    await admin.query(`CREATE DATABASE ${TEMPLATE}`);
    created.add(TEMPLATE);
    const t = superuser(TEMPLATE);
    await t.connect();
    await t.query(PLATFORM_ROLES_SQL);
    await t.query('SET SESSION AUTHORIZATION netlifydb_owner');
    // Sprint 1.9C.1: all six applied migrations, exactly as on the preview and production branches.
    for (const [name, sql] of [['20261103170000', SCHEMA_SQL], ['20261103170100', ROLE_SQL], ['20261104120000', SUPER_ADMIN_SQL], ['20261104130000', PLATFORM_SQL],
      ['20261104150000', PLATFORM_ADMIN_SQL], ['20261104160000', SEARCH_PATH_SQL]] as const) {
      await t.query('BEGIN'); await t.query(sql); await t.query('COMMIT'); // one transaction per file, like the runner
      log(`applied migration ${name} sha256:${sha(sql)}`);
    }
    // ---- Test-only mailbox substitution inside the disposable cluster. ----
    const def = (await t.query<{ d: string }>(`SELECT pg_get_functiondef('hourvia_is_verified_platform_candidate(uuid)'::regprocedure) d`)).rows[0]!.d;
    expect(def.split(`'${PLATFORM_EMAIL}'`).length).toBe(2);
    await t.query(def.replace(`'${PLATFORM_EMAIL}'`, `'${SYNTHETIC_EMAIL}'`));
    const after = (await t.query<{ d: string }>(`SELECT pg_get_functiondef('hourvia_is_verified_platform_candidate(uuid)'::regprocedure) d`)).rows[0]!.d;
    expect(after).toBe(def.replace(`'${PLATFORM_EMAIL}'`, `'${SYNTHETIC_EMAIL}'`));
    expect((await t.query(`SELECT 1 FROM pg_proc WHERE prosrc LIKE '%' || $1 || '%'`, [PLATFORM_EMAIL])).rows).toEqual([]);
    await t.end();
  }, 120_000);

  afterAll(async () => {
    if (!admin) return;
    for (const db of [...created]) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`).then(() => created.delete(db));
    const left = (await admin.query<{ d: string[] }>(`SELECT array_agg(datname::text ORDER BY datname) d FROM pg_database`)).rows[0]!.d;
    log('databases after cleanup', JSON.stringify(left));
    await admin.end();
    expect(left).toEqual(['postgres', 'template0', 'template1']);
  });

  it('uses the shipped procedure unchanged except for the designated mailbox literal', () => {
    expect(GRANT_PLATFORM_SQL.split(MAILBOX_CLAUSE).length).toBe(2); // exactly one executable occurrence
    expect(REHEARSAL_GRANT_SQL).not.toContain(MAILBOX_CLAUSE);
    expect(REHEARSAL_GRANT_SQL.replace(`email = '${SYNTHETIC_EMAIL}'`, MAILBOX_CLAUSE)).toBe(GRANT_PLATFORM_SQL);
    log(`grant procedure sha256:${sha(GRANT_PLATFORM_SQL)} (on disk, unmodified)`);
  });

  it('1a. grant holds the membership row lock; a concurrent disable waits, then commits after the grant', async () => {
    await withScenario('s1a', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      await s.a.query('BEGIN');
      await s.a.query(grantSql(lis.uid, lis.id)); // grant done, transaction still open: row lock held
      const lockedBy = (await s.mon.query<{ x: string }>(`SELECT xmax::text x FROM workspace_members WHERE id = $1`, [lis.id])).rows[0]!.x;
      expect(lockedBy).toBe((await s.a.query<{ x: string }>(`SELECT pg_current_xact_id()::text x`)).rows[0]!.x);
      const t0 = Date.now();
      const disable = s.b.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [lis.id]);
      const blocked = await s.waitBlocked(s.pidB, s.pidA);
      log('1a: session B blocked', JSON.stringify(blocked), `A=${s.pidA} B=${s.pidB}`);
      await sleep(500);
      expect((await s.mon.query(`SELECT status FROM workspace_members WHERE id = $1`, [lis.id])).rows[0].status).toBe('active');
      await s.a.query('COMMIT');
      const r = await disable;
      log(`1a: B's disable completed after ${Date.now() - t0} ms, rows=${r.rowCount}`);
      expect(r.rowCount).toBe(1);
      const st = await s.state();
      expectConsistentGrant(st, lis.uid);
      expect(st.members[0]).toMatchObject({ status: 'disabled' });
      expect(st.authAudit.filter((e: any) => e.event_type === 'membership_status_changed').map((e: any) => e.details))
        .toEqual([expect.objectContaining({ from_status: 'active', to_status: 'disabled', source: 'operator_sql' })]);
      // Serialized: B's change landed after the grant. Effective authority is gone even though the grant row remains.
      expect((await s.mon.query(`SELECT hourvia_member_authority($1, 'thrivesource') a, hourvia_is_verified_platform_candidate($2) c`, [lis.id, lis.uid])).rows[0]).toEqual({ a: null, c: false });
    });
  });

  it('1b. grant holds the lock; a concurrent role change waits, then is refused by the membership guard', async () => {
    await withScenario('s1b', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      const other = await s.seed('workspace_admin', 'active', 'other-admin@rehearsal.invalid');
      await s.a.query('BEGIN');
      await s.a.query(grantSql(lis.uid, lis.id));
      // The application path (runtime role) is the only one allowed to change an active member's role.
      await s.b.query('BEGIN'); await s.b.query('SET LOCAL ROLE hourvia_auth_runtime');
      const change = s.b.query(`UPDATE workspace_members SET role = 'workspace_manager', role_changed_by = $2, role_changed_at = now() WHERE id = $1`, [lis.id, other.id])
        .then(() => 'committed', (e: Error) => e.message);
      log('1b: session B blocked', JSON.stringify(await s.waitBlocked(s.pidB, s.pidA)));
      await s.a.query('COMMIT');
      const outcome = await change;
      await s.b.query('ROLLBACK');
      log('1b: role change outcome after grant commit:', outcome);
      expect(outcome).toMatch(/role change is not authorized/);
      const st = await s.state();
      expectConsistentGrant(st, lis.uid);
      expect(st.members.find((m: any) => m.id === lis.id)).toMatchObject({ role: 'workspace_admin', status: 'active' });
      expect(st.authAudit.filter((e: any) => e.event_type !== 'membership_created')).toEqual([]);
    });
  });

  it('1c. two concurrent grant runs serialize on the platform table locks; the second is an idempotent no-op', async () => {
    await withScenario('s1c', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      await s.a.query('BEGIN');
      await s.a.query(grantSql(lis.uid, lis.id));
      const second = s.b.query(grantSql(lis.uid, lis.id, 'REH-2026-0002')).then(() => 'ok', (e: Error) => e.message);
      log('1c: second grant blocked', JSON.stringify(await s.waitBlocked(s.pidB, s.pidA)));
      await s.a.query('COMMIT');
      expect(await second).toBe('ok');
      expectConsistentGrant(await s.state(), lis.uid); // still exactly one grant, first approval only
    });
  });

  it('2a. membership lock held first: the grant hits its five-second lock timeout and rolls back completely', async () => {
    await withScenario('s2a', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      const before = await s.state();
      await s.b.query('BEGIN');
      await s.b.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [lis.id]); // uncommitted
      const t0 = Date.now();
      const err = await s.a.query(grantSql(lis.uid, lis.id)).then(() => null, (e: Error & { code?: string }) => e);
      const elapsed = Date.now() - t0;
      log(`2a: grant failed after ${elapsed} ms: ${err?.code} ${err?.message}`);
      expect(err?.code).toBe('55P03'); // lock_not_available
      expect(err?.message).toMatch(/lock timeout/);
      expect(elapsed).toBeGreaterThanOrEqual(LOCK_TIMEOUT_MS - 50);
      expect(elapsed).toBeLessThan(LOCK_TIMEOUT_MS + 2000);
      expect((await s.mon.query(`SELECT count(*)::int n FROM pg_locks WHERE pid = $1 AND relation IS NOT NULL AND locktype = 'relation' AND mode = 'ShareRowExclusiveLock'`, [s.pidA])).rows[0].n).toBe(0);
      await s.b.query('ROLLBACK');
      const st = await s.state();
      expectNothingGranted(st);
      expect(st).toEqual(before); // memberships and membership audit also unchanged
      // Retry after the conflicting transaction ended succeeds normally.
      await s.a.query(grantSql(lis.uid, lis.id));
      expectConsistentGrant(await s.state(), lis.uid);
    });
  }, 30_000);

  it('2b. membership change committed while the grant waits: the grant re-reads the committed row and is refused', async () => {
    await withScenario('s2b', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      await s.b.query('BEGIN');
      await s.b.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [lis.id]);
      const pending = s.a.query(grantSql(lis.uid, lis.id)).then(() => null, (e: Error) => e.message);
      log('2b: grant blocked', JSON.stringify(await s.waitBlocked(s.pidA, s.pidB)));
      await sleep(1000);
      await s.b.query('COMMIT');
      const msg = await pending;
      log('2b: grant outcome:', msg);
      expect(msg).toMatch(/grant_guard: the membership is disabled/);
      expectNothingGranted(await s.state());
    });
  });

  for (const [label, role, status, message] of [
    ['Manager', 'workspace_manager', 'active', /the membership role is workspace_manager, not workspace_admin/],
    ['Contractor', 'contractor', 'active', /the membership role is contractor, not workspace_admin/],
    ['disabled Administrator', 'workspace_admin', 'disabled', /the membership is disabled/],
  ] as const) {
    it(`3. previously committed ${label} membership is rejected with nothing written`, async () => {
      await withScenario(`s3_${role}_${status}`, async s => {
        const lis = await s.seed(role, status);
        const before = await s.state();
        const msg = await s.a.query(grantSql(lis.uid, lis.id)).then(() => null, (e: Error) => e.message);
        log(`3 (${label}):`, msg);
        expect(msg).toMatch(message);
        const st = await s.state();
        expectNothingGranted(st);
        expect(st).toEqual(before);
      });
    });
  }

  it('4. audit and designation stay consistent across failure, success, idempotent re-run and wrong identity', async () => {
    await withScenario('s4', async s => {
      const lis = await s.seed('workspace_admin', 'active');
      const empty = await s.state();
      expect(await s.a.query(grantSql(randomUUID(), lis.id)).then(() => null, (e: Error) => e.message)).toMatch(/do not match/);
      expect(await s.state()).toEqual(empty);
      await s.a.query(grantSql(lis.uid, lis.id));
      const granted = await s.state();
      expectConsistentGrant(granted, lis.uid);
      await s.b.query(grantSql(lis.uid, lis.id, 'REH-2026-0009')); // other session, other approval: no-op
      expect(await s.state()).toEqual(granted);
      expect(await s.b.query(grantSql(lis.uid, randomUUID())).then(() => null, (e: Error) => e.message)).toMatch(/do not match/);
      expect(await s.state()).toEqual(granted);
      log('4: platform audit', JSON.stringify(granted.platformAudit.map((e: any) => e.event_type)));
    });
  });

  it('5. membership disabled immediately after the grant commits: effective authorization is removed at once', async () => {
    await withScenario('s5', async s => {
      const provider = new FakeSupabase();
      const uid = provider.addUser(SYNTHETIC_EMAIL, 'correct horse battery'); // synthetic UID
      const lis = await s.seed('workspace_admin', 'active', SYNTHETIC_EMAIL, uid);
      const target = await s.seed('contractor', 'active', 'c@rehearsal.invalid');
      const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: s.db, max: 2 });
      try {
        const config: AuthConfig = { hashKey: 'k'.repeat(48), appOrigin: ORIGIN, emailDeliveryAuthorized: true, idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200, invitationTtlSeconds: 7 * 86400, recoveryMinimumMs: 0, smokeTestEmails: null };
        const deps: AuthDeps = { store: new PostgresAuthStore(statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool as any)))), provider, config, now: () => new Date(), sleep: async () => undefined };
        const call = async (method: 'GET' | 'POST', path: string, cookie?: string, body?: unknown) => {
          const headers: Record<string, string> = method === 'POST' ? { origin: ORIGIN, 'content-type': 'application/json' } : {};
          if (cookie) headers.cookie = `__Host-hourvia_session=${cookie}`;
          const res = await handleAuthRequest(new Request(ORIGIN + path, { method, headers, body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined }), '203.0.113.10', async () => deps);
          const text = await res.text();
          return { status: res.status, json: text ? JSON.parse(text) : null, cookie: res.headers.get('set-cookie')?.match(/^__Host-hourvia_session=([^;]*)/)?.[1] };
        };
        const login = await call('POST', '/api/auth/login', undefined, { email: SYNTHETIC_EMAIL, password: 'correct horse battery' });
        expect(login.status).toBe(200);
        const cookie = login.cookie!;

        await s.a.query(grantSql(uid, lis.id)); // committed
        expect((await call('GET', '/api/auth/session', cookie)).json.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: ['platform_super_admin'] });
        expect((await s.mon.query(`SELECT hourvia_member_authority($1, 'thrivesource') a`, [lis.id])).rows[0].a).toBe('platform_super_admin');

        await s.b.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [lis.id]); // operator disable
        const authority = (await s.mon.query(`SELECT hourvia_member_authority($1, 'thrivesource') a, hourvia_is_verified_platform_candidate($2) c`, [lis.id, uid])).rows[0];
        const sessionAfter = await call('GET', '/api/auth/session', cookie);
        const inviteAfter = await call('POST', '/api/admin/invitations', cookie, { email: 'new.admin@rehearsal.invalid', role: 'workspace_admin' });
        const loginAfter = await call('POST', '/api/auth/login', undefined, { email: SYNTHETIC_EMAIL, password: 'correct horse battery' });
        const dbAttempt = await s.b.query('BEGIN').then(() => s.b.query('SET LOCAL ROLE hourvia_auth_runtime'))
          .then(() => s.b.query(`UPDATE workspace_members SET role = 'workspace_manager', role_changed_by = $2, role_changed_at = now() WHERE id = $1`, [target.id, lis.id]))
          .then(() => 'allowed', (e: Error) => e.message).finally(() => s.b.query('ROLLBACK'));
        log('5:', JSON.stringify({ authority, session: sessionAfter.status, invite: inviteAfter.status, login: loginAfter.status, dbAttempt }));
        expect(authority).toEqual({ a: null, c: false });
        expect(sessionAfter.status).toBe(401);
        expect([401, 403]).toContain(inviteAfter.status);
        expect(loginAfter.status).toBe(401);
        expect(dbAttempt).toMatch(/not authorized/);
        // Grant row and audit remain intact (history is never rewritten); a fresh grant run is refused.
        const st = await s.state();
        expectConsistentGrant(st, uid);
        expect(await s.a.query(grantSql(uid, lis.id)).then(() => null, (e: Error) => e.message)).toMatch(/grant_guard: the membership is disabled/);
        expect(await s.state()).toEqual(st);
      } finally { await pool.end(); }
    });
  });

  // ---- Sprint 1.9C.1: application runtime under real concurrency (F-2 transaction lifecycle, F-3 lock order) --------
  /** The production client chain over a real pg.Pool, optionally pausing (transaction still open) before one statement. */
  const appStore = (s: Scenario, app: string, pauseBefore?: RegExp) => {
    const pool = new pg.Pool({ host: SOCKET, port: PORT, user: 'netlifydb_owner', database: s.db, max: 1, application_name: app });
    const base = statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool as any)));
    let open!: () => void; const gate = new Promise<void>(r => { open = r; });
    let arrived!: () => void; const atGate = new Promise<void>(r => { arrived = r; });
    const pausing = (c: SqlClient): SqlClient => ({
      query: async <T>(text: string, params?: unknown[]) => { if (pauseBefore?.test(text.trim())) { arrived(); await gate; } return c.query<T>(text, params); },
      transaction: fn => c.transaction(tx => fn(pausing(tx))),
    });
    return { pool, sql: base, store: new PostgresAuthStore(pausing(base)), atGate, release: () => open() };
  };
  const waitAppBlocked = async (s: Scenario, app: string) => {
    for (let i = 0; i < 200; i++) {
      const r = (await s.mon.query<{ pid: number; w: string | null; blockers: number[] }>(
        `SELECT pid, wait_event_type w, pg_blocking_pids(pid) blockers FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1`, [app])).rows[0];
      if (r?.w === 'Lock' && r.blockers.length) return r;
      await sleep(25);
    }
    throw new Error(`${app} never blocked on a lock`);
  };
  /** Superuser probe: can the invitation rows be locked right now without waiting? (Always rolled back.) */
  const invitationLockFree = async (s: Scenario, memberId: string) => {
    await s.mon.query('BEGIN');
    try { await s.mon.query(`SELECT 1 FROM workspace_invitations WHERE member_id = $1 FOR UPDATE NOWAIT`, [memberId]); return true; }
    catch (e) { if (/could not obtain lock/.test((e as Error).message)) return false; throw e; }
    finally { await s.mon.query('ROLLBACK'); }
  };
  const seedInvited = async (s: Scenario) => {
    const adm = await s.seed('workspace_admin', 'active', 'admin@rehearsal.invalid');
    const inv = await s.seed('contractor', 'invited', 'invitee@rehearsal.invalid');
    await s.a.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
      VALUES ('thrivesource', $1, 'invitee@rehearsal.invalid', 'contractor', 'pending', $2, now(), now() + interval '7 days')`, [inv.id, adm.id]);
    return { adm, inv };
  };
  const membershipOutcome = async (s: Scenario, memberId: string) => ({
    member: (await s.mon.query(`SELECT status FROM workspace_members WHERE id = $1`, [memberId])).rows[0].status,
    invitations: (await s.mon.query(`SELECT status FROM workspace_invitations WHERE member_id = $1 ORDER BY created_at`, [memberId])).rows.map((r: any) => r.status),
    audit: (await s.mon.query(`SELECT details->>'to_status' AS s, details->>'source' AS src FROM auth_audit_events
      WHERE subject_member_id = $1 AND event_type = 'membership_status_changed' ORDER BY id`, [memberId])).rows.map((r: any) => `${r.s}:${r.src}`),
  });
  const settle = (p: Promise<unknown>) => p.then(v => ({ ok: true as const, v }), (e: any) => ({ ok: false as const, code: e?.code, message: String(e?.message) }));

  it('6a. F-3: disable holds the member row; a concurrent accept waits on the MEMBER row (invitation untouched), no deadlock', async () => {
    await withScenario('s6a', async s => {
      const { adm, inv } = await seedInvited(s);
      const disabler = appStore(s, 'hv-disable', /^UPDATE workspace_invitations SET status = 'revoked'/);
      const accepter = appStore(s, 'hv-accept');
      try {
        const disable = settle(disabler.store.disableMember(inv.id, adm.id, new Date()));
        await disabler.atGate; // member row updated and locked; invitation revocation not yet sent
        const accept = settle(accepter.store.acceptInvitation(inv.id, new Date()));
        const blocked = await waitAppBlocked(s, 'hv-accept');
        const free = await invitationLockFree(s, inv.id); // with the old order accept would already hold the invitation row
        log('6a:', JSON.stringify({ blocked, invitationLockFree: free }));
        expect(free).toBe(true);
        disabler.release();
        const [d, a] = await Promise.all([disable, accept]);
        log('6a: results', JSON.stringify({ disable: d, accept: a }));
        expect(d).toEqual({ ok: true, v: true });
        expect(a).toEqual({ ok: true, v: false }); // invitation was revoked first: acceptance correctly refused
        expect(await membershipOutcome(s, inv.id)).toEqual({ member: 'disabled', invitations: ['revoked'], audit: ['disabled:application'] });
      } finally { disabler.release(); accepter.release(); await disabler.pool.end(); await accepter.pool.end(); }
    });
  });

  it('6b. F-3: accept holds the member row; a concurrent disable waits, then disables the activated member, no deadlock', async () => {
    await withScenario('s6b', async s => {
      const { adm, inv } = await seedInvited(s);
      const accepter = appStore(s, 'hv-accept', /^UPDATE workspace_members SET status = 'active'/);
      const disabler = appStore(s, 'hv-disable');
      try {
        const accept = settle(accepter.store.acceptInvitation(inv.id, new Date()));
        await accepter.atGate; // member row locked FOR NO KEY UPDATE and invitation accepted, transaction open
        const disable = settle(disabler.store.disableMember(inv.id, adm.id, new Date()));
        const blocked = await waitAppBlocked(s, 'hv-disable');
        log('6b:', JSON.stringify({ blocked }));
        accepter.release();
        const [a, d] = await Promise.all([accept, disable]);
        log('6b: results', JSON.stringify({ accept: a, disable: d }));
        expect(a).toEqual({ ok: true, v: true });
        expect(d).toEqual({ ok: true, v: true });
        expect(await membershipOutcome(s, inv.id)).toEqual({ member: 'disabled', invitations: ['accepted'], audit: ['active:application', 'disabled:application'] });
      } finally { disabler.release(); accepter.release(); await disabler.pool.end(); await accepter.pool.end(); }
    });
  });

  it('6c. F-3: 20 racing accept/disable pairs on fresh members never deadlock and always end disabled', async () => {
    await withScenario('s6c', async s => {
      const adm = await s.seed('workspace_admin', 'active', 'admin@rehearsal.invalid');
      const accepter = appStore(s, 'hv-accept'); const disabler = appStore(s, 'hv-disable');
      try {
        const outcomes: string[] = [];
        for (let i = 0; i < 20; i++) {
          const inv = await s.seed('contractor', 'invited', `race${i}@rehearsal.invalid`);
          await s.a.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
            VALUES ('thrivesource', $1, $2, 'contractor', 'pending', $3, now(), now() + interval '7 days')`, [inv.id, `race${i}@rehearsal.invalid`, adm.id]);
          const [a, d] = await Promise.all([settle(accepter.store.acceptInvitation(inv.id, new Date())), settle(disabler.store.disableMember(inv.id, adm.id, new Date()))]);
          expect(a.ok && d.ok).toBe(true); // no 40P01 deadlock, no other error
          const o = await membershipOutcome(s, inv.id);
          expect(o.member).toBe('disabled');
          expect(o.invitations.length).toBe(1);
          outcomes.push(o.invitations[0]!);
        }
        log('6c: invitation outcomes', JSON.stringify(outcomes.reduce<Record<string, number>>((m, x) => ({ ...m, [x]: (m[x] ?? 0) + 1 }), {})));
      } finally { disabler.release(); accepter.release(); await disabler.pool.end(); await accepter.pool.end(); }
    });
  });

  it('7a. F-2: on a real pooled connection a late sibling query is refused and the connection is reused clean', async () => {
    await withScenario('s7a', async s => {
      const app = appStore(s, 'hv-f2');
      try {
        let sibling: Promise<unknown> = Promise.resolve();
        const r = await settle(app.sql.transaction(async tx => {
          const denied = tx.query('SELECT * FROM auth_audit_events'); // permission denied for the runtime role
          sibling = (async () => { await sleep(50); return tx.query('SELECT current_user AS c'); })();
          await Promise.all([denied, sibling]);
        }));
        expect(r.ok).toBe(false);
        await expect(sibling).rejects.toBeInstanceOf(TransactionClosedError);
        const state = (await s.mon.query(`SELECT state FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'hv-f2'`)).rows[0];
        expect(state.state).toBe('idle'); // not "idle in transaction": ROLLBACK completed, nothing left open
        expect((await app.pool.query<{ c: string; s: string }>('SELECT current_user AS c, session_user AS s')).rows[0]).toEqual({ c: 'netlifydb_owner', s: 'netlifydb_owner' });
        expect((await app.sql.query<{ c: string }>('SELECT current_user AS c')).rows[0]!.c).toBe('hourvia_auth_runtime');
      } finally { await app.pool.end(); }
    });
  });

  it('7b. F-2: an un-awaited failing write rolls the whole transaction back and is reported as a failure', async () => {
    await withScenario('s7b', async s => {
      const app = appStore(s, 'hv-f2b');
      const hex = 'b'.repeat(64);
      try {
        // Background fact the lifecycle defends against: COMMIT of an aborted transaction "succeeds" with tag ROLLBACK.
        await s.b.query('BEGIN'); await s.b.query('SELECT 1/0').catch(() => undefined);
        expect((await s.b.query('COMMIT') as unknown as { command: string }).command).toBe('ROLLBACK');
        const r = await settle(app.sql.transaction(async tx => {
          await tx.query(`INSERT INTO auth_rate_limits (bucket, window_start, hits) VALUES ($1, now(), 1)`, [`rehearsal:${hex}`]);
          void tx.query(`INSERT INTO auth_rate_limits (bucket, window_start, hits) VALUES ($1, now(), 0)`, [`rehearsal:${hex}`]).catch(() => undefined); // violates hits > 0
          return 'would have reported success';
        }));
        log('7b:', JSON.stringify(r));
        expect(r.ok).toBe(false);
        expect((await s.mon.query(`SELECT count(*)::int n FROM auth_rate_limits`)).rows[0].n).toBe(0);
      } finally { await app.pool.end(); }
    });
  });
});
