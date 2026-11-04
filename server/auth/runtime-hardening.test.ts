// SPRINT 1.9C RUNTIME HARDENING TESTS. Embedded Postgres (PGlite) and in-memory fakes only, never a Netlify database.
//   G-1  store statement policy (statementGuardedSqlClient): one SELECT/INSERT/UPDATE, no role or setting changes.
//   G-2  pooled-connection hygiene in poolSqlClient: closed transaction handles, destroy on failed ROLLBACK, and no
//        SET LOCAL ROLE leakage across reuse of the same physical connection.
//   G-3  disableMember is atomic (member status and invitation revocation commit together or not at all).
//   G-4  HTTP fail-closed handling: broken or oversize bodies are 400, internal errors are 503 and logged without
//        their message.
import { PGlite } from '@electric-sql/pglite';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleAuthRequest } from './http';
import { poolSqlClient, TransactionClosedError } from './runtime';
import { AUTH_DB_ROLE, assertAllowedStatement, roleScopedSqlClient, SqlStatementRejectedError, statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { ORIGIN, ROLE_SQL, SCHEMA_SQL, applyMigration, asNetlifyOwner, createHarness, type Harness } from './testing/harness';
import type { SqlClient } from './types';

describe('G-1: store statement policy', () => {
  const rejected = [
    'RESET ROLE',
    'SET ROLE netlifydb_owner',
    `SET LOCAL ROLE ${AUTH_DB_ROLE}`,
    'SET SESSION AUTHORIZATION netlifydb_owner',
    'RESET ALL',
    'DISCARD ALL',
    'COMMIT',
    'BEGIN',
    'SELECT 1; RESET ROLE',
    'SELECT 1;',
    "SELECT set_config('role', 'netlifydb_owner', true)",
    "SELECT pg_catalog.set_config ('search_path', 'pg_temp', true)",
    'SELECT 1 -- hidden',
    '/* hidden */ SELECT 1',
    'DELETE FROM auth_sessions',
    'TRUNCATE auth_rate_limits',
    'DO $$ BEGIN RESET ROLE; END $$',
    'COPY auth_sessions TO STDOUT',
    'CALL anything()',
    'CREATE TEMP TABLE auth_sessions (x int)',
    'ALTER TABLE auth_audit_events DISABLE TRIGGER ALL',
    'WITH x AS (SELECT 1) SELECT * FROM x',
    'EXPLAIN SELECT 1',
    // Sprint 1.9C.1 (gate finding F-1): bypasses that passed the 1.9C policy.
    `SELECT "set_config"('role', 'netlifydb_owner', true)`,
    `SELECT pg_catalog."set_config"('role', 'netlifydb_owner', true)`,
    `SELECT U&"set\\005fconfig"('role', 'netlifydb_owner', true)`,
    `SELECT u&'\\0041'`,
    `SELECT SET_CONFIG('role', 'netlifydb_owner', true)`,
    `SELECT set_config`,
    `SELECT (pg_catalog.set_config)('role', 'x', true)`,
    `UPDATE pg_settings SET setting = 'netlifydb_owner' WHERE name = 'role'`,
    `UPDATE pg_catalog.pg_settings SET setting = 'pg_temp, public' WHERE name = 'search_path'`,
    `SELECT setting FROM PG_SETTINGS WHERE name = $1`,
    `SELECT * FROM "workspace_members"`,
  ];
  it.each(rejected)('rejects %s', text => {
    expect(() => assertAllowedStatement(text)).toThrow(SqlStatementRejectedError);
  });
  it.each(rejected)('rejects %s before the database is contacted, in query() and inside transaction()', async text => {
    const reached: string[] = [];
    const inner: SqlClient = {
      query: async <T>(t: string) => { reached.push(t); return { rows: [] as T[] }; },
      transaction: async fn => fn(inner),
    };
    const guarded = statementGuardedSqlClient(inner);
    await expect(guarded.query(text)).rejects.toThrow(SqlStatementRejectedError);
    await expect(guarded.transaction(async tx => tx.query(text))).rejects.toThrow(SqlStatementRejectedError);
    expect(reached).toEqual([]);
  });
  it('names the rule that fired for each F-1 bypass shape', () => {
    const reason = (t: string) => { try { assertAllowedStatement(t); return 'allowed'; } catch (e) { return (e as Error).message.replace('sql_statement_rejected:', ''); } };
    expect(reason(`SELECT "set_config"('role', 'x', true)`)).toBe('quoted_identifier');
    expect(reason(`SELECT U&'\\0041'`)).toBe('unicode_escape');
    expect(reason(`SELECT pg_catalog.set_config('role', 'x', true)`)).toBe('set_config');
    expect(reason(`UPDATE pg_settings SET setting = 'x' WHERE name = 'role'`)).toBe('pg_settings');
  });
  it('accepts the statement shapes the store uses, including UPDATE … SET role = …', () => {
    for (const text of ['  SELECT 1', '\n  INSERT INTO t (a) VALUES ($1)', `UPDATE workspace_members SET role = $3 WHERE id = $2`]) expect(() => assertAllowedStatement(text)).not.toThrow();
  });

  it('every statement PostgresAuthStore can issue passes the policy, and no input value ever reaches SQL text', async () => {
    const issued: { text: string; params: unknown[] }[] = [];
    const recorder: SqlClient = {
      query: async <T>(text: string, params: unknown[] = []) => { issued.push({ text, params }); return { rows: [{ id: 'x', hits: 1, o: null, p: null } as T] }; },
      transaction: async fn => fn(recorder),
    };
    const store = new PostgresAuthStore(statementGuardedSqlClient(recorder));
    const evil = "x'); RESET ROLE; --";
    const now = new Date('2026-11-04T00:00:00Z');
    await store.findMemberById(evil); await store.findMemberByEmail(evil); await store.findMemberByAuthUserId(evil);
    await store.listMembers(); await store.assignedContractorIds(evil); await store.platformPrivileges(evil);
    await store.platformOverview(evil); await store.platformAuditPage(evil, { beforeId: 5, limit: 10 });
    await store.upsertInvitation({ email: evil, role: 'contractor', displayName: evil, authUserId: evil, invitedBy: evil, now, expiresAt: now });
    await store.hasPendingInvitation(evil, now); await store.acceptInvitation(evil, now);
    await store.disableMember(evil, evil, now);
    await store.changeMemberRole({ memberId: evil, expectedRole: 'contractor', role: 'workspace_manager', changedBy: evil, now });
    await store.createSession({ tokenHash: evil, memberId: evil, now, idleExpiresAt: now, absoluteExpiresAt: now });
    await store.resolveSession(evil, now); await store.touchSession(evil, now, now);
    await store.revokeSession(evil, evil, now); await store.revokeMemberSessions(evil, evil, now, evil);
    await store.hitRateLimit(evil, now);
    await store.audit({ eventType: evil, outcome: 'denied', details: { reason: evil } }, now);
    expect(issued.length).toBeGreaterThanOrEqual(24);
    for (const { text, params } of issued) {
      expect(() => assertAllowedStatement(text)).not.toThrow();
      expect(text).not.toContain('RESET ROLE');
      expect(text).not.toContain(evil);
      expect(text).not.toMatch(/\$\{/);
      expect(params.length).toBeGreaterThan(0); // every store statement is parameterized
    }
  });

  describe('against real Postgres', () => {
    let h: Harness;
    beforeEach(async () => { h = await createHarness(); });
    it('documents the residual risk: through the raw role-scoped client RESET ROLE returns to the owner session user', async () => {
      const users = await h.sql.transaction(async tx => {
        await tx.query('RESET ROLE');
        return (await tx.query<{ u: string }>('SELECT current_user AS u')).rows[0]!.u;
      });
      expect(users).toBe('netlifydb_owner');
    });
    it('the guarded client used by the store refuses role escapes before they reach the database', async () => {
      const guarded = statementGuardedSqlClient(h.sql);
      await expect(guarded.query('RESET ROLE')).rejects.toThrow(/sql_statement_rejected:statement_kind/);
      await expect(guarded.query("SELECT set_config('role', 'netlifydb_owner', true)")).rejects.toThrow(/set_config/);
      await expect(guarded.transaction(async tx => { await tx.query('RESET ROLE'); })).rejects.toThrow(/statement_kind/);
      await expect(guarded.transaction(async tx => { await tx.query('SELECT 1; RESET ROLE'); })).rejects.toThrow(/multiple_statements/);
      expect((await guarded.query<{ u: string }>('SELECT current_user AS u')).rows[0]!.u).toBe(AUTH_DB_ROLE);
    });
    it('F-1: the quoted set_config bypass really escapes on the raw client, and the guarded client refuses it', async () => {
      const bypass = `SELECT "set_config"('role', 'netlifydb_owner', true)`;
      const escaped = await h.sql.transaction(async tx => { await tx.query(bypass); return (await tx.query<{ u: string }>('SELECT current_user AS u')).rows[0]!.u; });
      expect(escaped).toBe('netlifydb_owner'); // proves the probe exercises the real vector
      const guarded = statementGuardedSqlClient(h.sql);
      await expect(guarded.transaction(async tx => { await tx.query(bypass); })).rejects.toThrow(/quoted_identifier/);
      await expect(guarded.query(`UPDATE pg_settings SET setting = 'netlifydb_owner' WHERE name = 'role'`)).rejects.toThrow(/pg_settings/);
    });
    it('a guard rejection fails the request closed with 503 and no data', async () => {
      const bad = new PostgresAuthStore(statementGuardedSqlClient({ query: () => Promise.reject(new SqlStatementRejectedError('statement_kind')), transaction: () => Promise.reject(new SqlStatementRejectedError('statement_kind')) }));
      const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      // Login always reaches the store (rate limit first), so the rejection is exercised.
      const req = new Request(`${ORIGIN}/api/auth/login`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'a@t.test', password: 'x' }) });
      const res = await handleAuthRequest(req, '203.0.113.1', async () => ({ ...h.deps, store: bad }));
      errors.mockRestore();
      expect(res.status).toBe(503);
      expect(res.headers.get('set-cookie')).toBeNull();
      expect(h.provider.issued).toHaveLength(0); // the identity provider was never contacted
    });
  });
});

/** A pg-like pool over ONE PGlite connection, so every checkout reuses the same physical session (worst case). */
function singleConnectionPool(pg: PGlite, hooks: { failRollback?: boolean; releases?: unknown[] } = {}) {
  const query = async (text: string, params?: unknown[]) => {
    if (hooks.failRollback && text === 'ROLLBACK') throw new Error('connection lost');
    return { rows: (await pg.query(text, params)).rows as unknown[] };
  };
  return { query, connect: async () => ({ query, release: (destroy?: unknown) => { hooks.releases?.push(destroy); } }) };
}

describe('G-2: pooled connections never keep the runtime role or run stale transaction handles', () => {
  async function owner() { const pg = new PGlite(); await asNetlifyOwner(pg); await applyMigration(pg, SCHEMA_SQL); await applyMigration(pg, ROLE_SQL); return pg; }
  const whoami = async (pg: PGlite) => (await pg.query<{ c: string; s: string }>('SELECT current_user AS c, session_user AS s')).rows[0];

  it('SET LOCAL ROLE does not survive COMMIT, ROLLBACK after an application error, or a database error', async () => {
    const pg = await owner();
    const sql = roleScopedSqlClient(poolSqlClient(singleConnectionPool(pg)));
    expect((await sql.query<{ c: string }>('SELECT current_user AS c')).rows[0]!.c).toBe(AUTH_DB_ROLE);
    expect(await whoami(pg)).toEqual({ c: 'netlifydb_owner', s: 'netlifydb_owner' });
    await expect(sql.transaction(async tx => { await tx.query('SELECT 1'); throw new Error('app'); })).rejects.toThrow('app');
    expect(await whoami(pg)).toEqual({ c: 'netlifydb_owner', s: 'netlifydb_owner' });
    await expect(sql.query('SELECT * FROM auth_audit_events')).rejects.toThrow(/permission denied/);
    expect(await whoami(pg)).toEqual({ c: 'netlifydb_owner', s: 'netlifydb_owner' });
    // The very next checkout of the same connection is switched again, so it is never owner-level for store SQL.
    expect((await sql.query<{ c: string }>('SELECT current_user AS c')).rows[0]!.c).toBe(AUTH_DB_ROLE);
  });

  it('a transaction handle used after the transaction ended is refused and never reaches the pooled connection', async () => {
    const pg = await owner();
    const sql = roleScopedSqlClient(poolSqlClient(singleConnectionPool(pg)));
    let stale: SqlClient | null = null;
    await sql.transaction(async tx => { stale = tx; await tx.query('SELECT 1'); });
    // Without the guard this would run as netlifydb_owner on a connection back in the pool.
    await expect(stale!.query('SELECT * FROM auth_audit_events')).rejects.toThrow('transaction_closed');
    await expect(stale!.transaction(async () => undefined)).rejects.toThrow('nested_transaction');
  });

  it('destroys the connection when ROLLBACK fails, and returns it normally otherwise', async () => {
    const pg = await owner();
    const releases: unknown[] = [];
    const ok = poolSqlClient(singleConnectionPool(pg, { releases }));
    await ok.transaction(async tx => tx.query('SELECT 1'));
    await expect(ok.transaction(async () => { throw new Error('app'); })).rejects.toThrow('app');
    expect(releases).toEqual([undefined, undefined]);

    const broken: unknown[] = [];
    const failing = poolSqlClient(singleConnectionPool(pg, { failRollback: true, releases: broken }));
    await expect(failing.transaction(async () => { throw new Error('app'); })).rejects.toThrow('app'); // original error wins
    expect(broken).toHaveLength(1);
    expect(broken[0]).toBeInstanceOf(Error);
    await pg.query('ROLLBACK'); // clean up the emulated dead session
  });

  it('issues BEGIN, SET LOCAL ROLE, the statement and COMMIT in that order on one connection', async () => {
    const log: string[] = [];
    const client = { query: async (text: string) => { log.push(text); return { rows: [] }; }, release: () => { log.push('release'); } };
    const sql = roleScopedSqlClient(poolSqlClient({ query: async () => { log.push('pool.query'); return { rows: [] }; }, connect: async () => client }));
    await sql.query('SELECT 1');
    expect(log).toEqual(['BEGIN', `SET LOCAL ROLE ${AUTH_DB_ROLE}`, 'SELECT 1', 'COMMIT', 'release']);
    expect(log).not.toContain('pool.query'); // the role-scoped path never uses the owner-level pool.query
  });
});

/**
 * A pg-like pool whose single client executes statements strictly in FIFO order with a small delay per statement,
 * like node-postgres' per-client query queue. That reproduces the COMMIT/ROLLBACK window exactly: a statement handed
 * to the client while COMMIT is pending would run after it.
 */
function fifoPool(opts: { fail?: (text: string) => Error | null; commitTag?: string } = {}) {
  const log: string[] = [];
  const releases: unknown[] = [];
  let chain: Promise<unknown> = Promise.resolve();
  const query = (text: string) => {
    const run = chain.then(async () => {
      await new Promise(r => setTimeout(r, 3));
      log.push(text);
      const error = opts.fail?.(text);
      if (error) throw error;
      return { rows: [] as unknown[], command: text === 'COMMIT' ? (opts.commitTag ?? 'COMMIT') : text.split(' ')[0] };
    });
    chain = run.then(() => undefined, () => undefined);
    return run;
  };
  const client = { query, release: (destroy?: unknown) => { log.push('release'); releases.push(destroy); } };
  return { log, releases, pool: { query: async () => { log.push('pool.query'); return { rows: [] }; }, connect: async () => client } };
}
const pause = (ms: number) => new Promise(r => setTimeout(r, ms));
const HEAD = ['BEGIN', `SET LOCAL ROLE ${AUTH_DB_ROLE}`];

describe('G-2b (Sprint 1.9C.1, gate finding F-2): handles close when the callback settles, before COMMIT/ROLLBACK', () => {
  it('rejects a delayed query issued while COMMIT is in flight; it never reaches the connection', async () => {
    const f = fifoPool();
    const sql = roleScopedSqlClient(poolSqlClient(f.pool));
    let late: Promise<unknown> = Promise.resolve();
    await sql.transaction(async tx => {
      await tx.query('SELECT 1');
      late = pause(1).then(() => tx.query('SELECT late'));
    });
    await expect(late).rejects.toBeInstanceOf(TransactionClosedError);
    await pause(20);
    expect(f.log).toEqual([...HEAD, 'SELECT 1', 'COMMIT', 'release']);
  });

  it('rejects a delayed query issued while ROLLBACK is in flight', async () => {
    const f = fifoPool();
    const sql = roleScopedSqlClient(poolSqlClient(f.pool));
    let late: Promise<unknown> = Promise.resolve();
    await expect(sql.transaction(async tx => {
      await tx.query('SELECT 1');
      late = pause(1).then(() => tx.query('SELECT late'));
      throw new Error('app');
    })).rejects.toThrow('app');
    await expect(late).rejects.toBeInstanceOf(TransactionClosedError);
    await pause(20);
    expect(f.log).toEqual([...HEAD, 'SELECT 1', 'ROLLBACK', 'release']);
  });

  it('rejects a retained handle after completion', async () => {
    const f = fifoPool();
    let stale: SqlClient | null = null;
    await poolSqlClient(f.pool).transaction(async tx => { stale = tx; });
    await expect(stale!.query('SELECT 1')).rejects.toBeInstanceOf(TransactionClosedError);
    expect(f.log).toEqual(['BEGIN', 'COMMIT', 'release']);
  });

  it('concurrent Promise branches: a sibling still running after another branch threw cannot issue more SQL', async () => {
    const f = fifoPool();
    const sql = roleScopedSqlClient(poolSqlClient(f.pool));
    let sibling: Promise<unknown> = Promise.resolve();
    await expect(sql.transaction(async tx => {
      const failing = (async () => { await tx.query('SELECT a'); throw new Error('branch a failed'); })();
      sibling = (async () => { await pause(15); return tx.query('UPDATE b'); })();
      await Promise.all([failing, sibling]);
    })).rejects.toThrow('branch a failed');
    await expect(sibling).rejects.toBeInstanceOf(TransactionClosedError);
    await pause(30);
    expect(f.log).toEqual([...HEAD, 'SELECT a', 'ROLLBACK', 'release']);
  });

  it('concurrent Promise branches that all finish inside the callback run inside the transaction', async () => {
    const f = fifoPool();
    const sql = roleScopedSqlClient(poolSqlClient(f.pool));
    await sql.transaction(async tx => { await Promise.all([tx.query('SELECT a'), tx.query('SELECT b')]); });
    expect(f.log).toEqual([...HEAD, 'SELECT a', 'SELECT b', 'COMMIT', 'release']);
  });

  it('drains un-awaited queries before COMMIT, and rolls back (and throws) if one of them failed', async () => {
    const ok = fifoPool();
    await roleScopedSqlClient(poolSqlClient(ok.pool)).transaction(async tx => { void tx.query('UPDATE x'); });
    expect(ok.log).toEqual([...HEAD, 'UPDATE x', 'COMMIT', 'release']);

    const bad = fifoPool({ fail: t => (t === 'UPDATE x' ? new Error('write failed') : null) });
    await expect(roleScopedSqlClient(poolSqlClient(bad.pool)).transaction(async tx => { void tx.query('UPDATE x').catch(() => undefined); return 'reported success'; }))
      .rejects.toThrow('write failed');
    expect(bad.log).toEqual([...HEAD, 'UPDATE x', 'ROLLBACK', 'release']);
    expect(bad.log).not.toContain('COMMIT');
  });

  it('treats a COMMIT that the server reports as ROLLBACK as a failure', async () => {
    const f = fifoPool({ commitTag: 'ROLLBACK' });
    await expect(poolSqlClient(f.pool).transaction(async () => 'value')).rejects.toThrow('transaction_rolled_back');
  });

  it('still destroys the connection when ROLLBACK fails, and reports the original error', async () => {
    const f = fifoPool({ fail: t => (t === 'ROLLBACK' ? new Error('connection lost') : null) });
    await expect(poolSqlClient(f.pool).transaction(async () => { throw new Error('app'); })).rejects.toThrow('app');
    expect(f.releases).toHaveLength(1);
    expect(f.releases[0]).toBeInstanceOf(Error);
  });

  it('pooled reuse (real Postgres semantics, one physical connection): after a branch failure the connection is clean', async () => {
    const pg = new PGlite(); await asNetlifyOwner(pg); await applyMigration(pg, SCHEMA_SQL); await applyMigration(pg, ROLE_SQL);
    const sql = roleScopedSqlClient(poolSqlClient(singleConnectionPool(pg)));
    let sibling: Promise<unknown> = Promise.resolve();
    await expect(sql.transaction(async tx => {
      const denied = tx.query('SELECT * FROM auth_audit_events'); // permission denied as the runtime role
      sibling = (async () => { await pause(10); return tx.query('SELECT * FROM auth_audit_events'); })();
      await Promise.all([denied, sibling]);
    })).rejects.toThrow(/permission denied/);
    await expect(sibling).rejects.toBeInstanceOf(TransactionClosedError);
    expect((await pg.query<{ c: string }>('SELECT current_user AS c')).rows[0]!.c).toBe('netlifydb_owner');
    expect((await sql.query<{ c: string }>('SELECT current_user AS c')).rows[0]!.c).toBe(AUTH_DB_ROLE);
  });
});

describe('G-3b (Sprint 1.9C.1, gate finding F-3): one lock order for every membership write', () => {
  it('acceptInvitation, disableMember and upsertInvitation lock workspace_members before workspace_invitations', async () => {
    const issued: string[] = [];
    const recorder: SqlClient = {
      query: async <T>(text: string) => { issued.push(text.trim().replace(/\s+/g, ' ')); return { rows: [{ id: 'x' } as T] }; },
      transaction: async fn => fn(recorder),
    };
    const store = new PostgresAuthStore(statementGuardedSqlClient(recorder));
    const now = new Date();
    const firstTable = async (run: () => Promise<unknown>) => {
      issued.length = 0; await run();
      const members = issued.findIndex(t => /workspace_members/.test(t));
      const invitations = issued.findIndex(t => /workspace_invitations/.test(t));
      return { members, invitations, first: issued[0]! };
    };
    const accept = await firstTable(() => store.acceptInvitation('m', now));
    expect(accept.first).toMatch(/^SELECT id FROM workspace_members .* FOR NO KEY UPDATE$/);
    expect(accept.members).toBeLessThan(accept.invitations);
    const disable = await firstTable(() => store.disableMember('m', 'a', now));
    expect(disable.members).toBe(0); expect(disable.members).toBeLessThan(disable.invitations);
    const upsert = await firstTable(() => store.upsertInvitation({ email: 'e@t.test', role: 'contractor', displayName: '', authUserId: 'u', invitedBy: 'a', now, expiresAt: now }));
    expect(upsert.members).toBe(0); expect(upsert.members).toBeLessThan(upsert.invitations);
  });
  it('acceptInvitation semantics are unchanged: unknown member → false with no invitation write; normal accept still activates', async () => {
    const h = await createHarness();
    expect(await h.deps.store.acceptInvitation('00000000-0000-4000-8000-000000000000', new Date())).toBe(false);
    const admin = await h.login((await h.seedMember('a@t.test', 'workspace_admin')).email);
    const inv = await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'n@t.test', role: 'contractor' } });
    const id = inv.json!.member.id as string;
    expect(await h.deps.store.acceptInvitation(id, h.deps.now())).toBe(true);
    const { rows } = await h.pg.query<{ m: string; i: string }>(`SELECT m.status AS m, i.status AS i FROM workspace_members m JOIN workspace_invitations i ON i.member_id = m.id WHERE m.id = $1`, [id]);
    expect(rows).toEqual([{ m: 'active', i: 'accepted' }]);
    const audit = await h.pg.query<{ d: { to_status: string; source: string } }>(`SELECT details AS d FROM auth_audit_events WHERE subject_member_id = $1 AND event_type = 'membership_status_changed'`, [id]);
    expect(audit.rows.map(r => [r.d.to_status, r.d.source])).toEqual([['active', 'application']]);
  });
});

describe('G-3: disabling a member is atomic', () => {
  it('rolls the member back to active if revoking its invitations fails', async () => {
    const h = await createHarness();
    const admin = await h.login((await h.seedMember('a@t.test', 'workspace_admin')).email);
    const c = await h.seedMember('c@t.test', 'contractor');
    // Test-only fault injection in the embedded database: the runtime can no longer revoke invitations.
    await h.pg.exec('REVOKE UPDATE (status) ON workspace_invitations FROM hourvia_auth_runtime');
    const res = await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: admin.cookie });
    expect(res.status).toBe(503);
    const { rows } = await h.pg.query<{ status: string; disabled_at: unknown }>('SELECT status, disabled_at FROM workspace_members WHERE id = $1', [c.id]);
    expect(rows[0]).toEqual({ status: 'active', disabled_at: null });
    const audit = await h.pg.query(`SELECT 1 FROM auth_audit_events WHERE subject_member_id = $1 AND event_type = 'membership_status_changed'`, [c.id]);
    expect(audit.rows).toHaveLength(0);
  });
  it('still disables and revokes the pending invitation together on the normal path', async () => {
    const h = await createHarness();
    const admin = await h.login((await h.seedMember('a@t.test', 'workspace_admin')).email);
    const inv = await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'n@t.test', role: 'contractor' } });
    expect(inv.status).toBe(201);
    const id = inv.json!.member.id as string;
    expect((await h.call('POST', `/api/admin/members/${id}/disable`, { cookie: admin.cookie })).status).toBe(200);
    const { rows } = await h.pg.query<{ m: string; i: string }>(`SELECT m.status AS m, i.status AS i FROM workspace_members m JOIN workspace_invitations i ON i.member_id = m.id WHERE m.id = $1`, [id]);
    expect(rows).toEqual([{ m: 'disabled', i: 'revoked' }]);
  });
});

describe('G-4: HTTP fail-closed handling', () => {
  let errors: ReturnType<typeof vi.spyOn>;
  beforeEach(() => { errors = vi.spyOn(console, 'error').mockImplementation(() => undefined); });
  afterEach(() => { errors.mockRestore(); });
  const post = (body: BodyInit, headers: Record<string, string> = {}) => new Request(`${ORIGIN}/api/auth/login`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json', ...headers }, body, duplex: 'half' } as RequestInit);
  const neverDeps = async () => { throw new Error('deps must not be built'); };

  it('a broken request stream is a 400, not an unhandled exception', async () => {
    const stream = new ReadableStream({ pull(controller) { controller.error(new Error('client aborted')); } });
    const res = await handleAuthRequest(post(stream), '203.0.113.1', neverDeps);
    expect(res.status).toBe(400);
  });
  it('a declared oversize body is refused before it is buffered', async () => {
    const res = await handleAuthRequest(post('{}', { 'content-length': String(1024 * 1024) }), '203.0.113.1', neverDeps);
    expect(res.status).toBe(400);
  });
  it('internal errors are 503 with a generic body, and the log carries only class and SQLSTATE, never the message', async () => {
    const secretish = 'connect failed for postgresql://netlifydb_owner:hunter2@db.example/netlifydb';
    const failure = Object.assign(new Error(secretish), { code: '28P01' });
    const res = await handleAuthRequest(new Request(`${ORIGIN}/api/auth/session`), '203.0.113.1', async () => { throw failure; });
    expect(res.status).toBe(503);
    expect(await res.text()).not.toMatch(/hunter2|postgresql|netlifydb_owner/);
    const logged = errors.mock.calls.map(args => args.join(' ')).join('\n');
    expect(logged).toContain('"code":"28P01"');
    expect(logged).not.toMatch(/hunter2|postgresql|netlifydb_owner|connect failed/);
  });
  it('missing configuration stays 503 without touching the database', async () => {
    const res = await handleAuthRequest(new Request(`${ORIGIN}/api/auth/session`), '203.0.113.1', async () => ({ unavailable: 'not_configured' }));
    expect(res.status).toBe(503);
  });
});
