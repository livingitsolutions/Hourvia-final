// MIGRATION READINESS TESTS (Sprint 1.7). Disposable embedded PostgreSQL 18 (PGlite) only — no Netlify Database.
// The staged SQL is applied as a NON-superuser netlifydb_owner inside an emulation of the Netlify Database role
// catalog (see PLATFORM_ROLES_SQL), one transaction per file, the way Netlify's migration tooling applies it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';
import { roleScopedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { ROLE_SQL, SCHEMA_SQL, applyMigration, asNetlifyOwner, pgliteClient } from './testing/harness';

const AUTH_TABLES = ['workspace_members', 'manager_assignments', 'workspace_invitations', 'auth_sessions', 'auth_audit_events', 'auth_rate_limits'];
const ALL_TABLE_PRIVS = 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN';

async function migrated() {
  const pg = new PGlite();
  await asNetlifyOwner(pg);
  await applyMigration(pg, SCHEMA_SQL);
  await applyMigration(pg, ROLE_SQL);
  return pg;
}
const one = async <T>(pg: PGlite, text: string, params?: unknown[]) => (await pg.query<T>(text, params)).rows[0]!;

describe('migration ordering and the real (non-superuser) migration role', () => {
  it('applies 001 then 002 as netlifydb_owner, which is not a superuser', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    expect(await one(pg, `SELECT current_user AS u, rolsuper FROM pg_roles WHERE rolname = current_user`)).toEqual({ u: 'netlifydb_owner', rolsuper: false });
    await applyMigration(pg, SCHEMA_SQL);
    await applyMigration(pg, ROLE_SQL);
    const owners = await pg.query<{ o: string }>(`SELECT DISTINCT pg_get_userbyid(relowner) AS o FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'`);
    expect(owners.rows).toEqual([{ o: 'netlifydb_owner' }]);
  });
  it('rejects the wrong order: 002 cannot run before 001', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    await expect(applyMigration(pg, ROLE_SQL)).rejects.toThrow(/does not exist/);
    expect(await one(pg, `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = 'hourvia_auth_runtime'`)).toEqual({ n: 0 }); // rolled back
  });
  it('documents why the previous 002 was blocked: a non-superuser cannot name SUPERUSER/REPLICATION/BYPASSRLS', async () => {
    const pg = await migrated();
    await expect(pg.exec(`ALTER ROLE hourvia_auth_runtime NOSUPERUSER`)).rejects.toThrow(/permission denied/);
    await expect(pg.exec(`ALTER ROLE hourvia_auth_runtime NOREPLICATION`)).rejects.toThrow(/permission denied/);
  });
  it('creates the runtime role with safe attributes, no memberships, and a SET-only grant to netlifydb_owner', async () => {
    const pg = await migrated();
    expect(await one(pg, `SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = 'hourvia_auth_runtime'`))
      .toEqual({ rolsuper: false, rolinherit: false, rolcreaterole: false, rolcreatedb: false, rolcanlogin: false, rolreplication: false, rolbypassrls: false });
    expect(await one(pg, `SELECT count(*)::int AS n FROM pg_auth_members WHERE member = 'hourvia_auth_runtime'::regrole`)).toEqual({ n: 0 });
    expect(await one(pg, `SELECT pg_has_role('netlifydb_owner', 'hourvia_auth_runtime', 'SET') AS can_set, pg_has_role('netlifydb_owner', 'hourvia_auth_runtime', 'USAGE') AS inherits`))
      .toEqual({ can_set: true, inherits: false });
    expect(await one(pg, `SELECT pg_has_role('netlifydb_readonly', 'hourvia_auth_runtime', 'SET') AS ro_can_set`)).toEqual({ ro_can_set: false });
  });
  it('accepts a pre-existing safe role (preview branch copied from production) and aborts on an unsafe one', async () => {
    const ok = new PGlite();
    await asNetlifyOwner(ok);
    await ok.exec(`CREATE ROLE hourvia_auth_runtime NOLOGIN NOINHERIT`);
    await applyMigration(ok, SCHEMA_SQL);
    await applyMigration(ok, ROLE_SQL);

    const bad = new PGlite();
    await asNetlifyOwner(bad);
    await bad.exec(`CREATE ROLE hourvia_auth_runtime LOGIN NOINHERIT`);
    await applyMigration(bad, SCHEMA_SQL);
    await expect(applyMigration(bad, ROLE_SQL)).rejects.toThrow(/unsafe attributes/);

    const member = new PGlite();
    await asNetlifyOwner(member);
    await member.exec(`CREATE ROLE hourvia_auth_runtime NOLOGIN NOINHERIT; GRANT netlifydb_readonly TO hourvia_auth_runtime`);
    await applyMigration(member, SCHEMA_SQL);
    await expect(applyMigration(member, ROLE_SQL)).rejects.toThrow(/member of another role/);
  });
  it('aborts (and rolls back) when netlifydb_owner does not exist instead of silently skipping the grant', async () => {
    const pg = new PGlite();
    await applyMigration(pg, SCHEMA_SQL);
    await expect(applyMigration(pg, ROLE_SQL)).rejects.toThrow(/netlifydb_owner .* does not exist/);
    expect(await one(pg, `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = 'hourvia_auth_runtime'`)).toEqual({ n: 0 });
  });
});

describe('netlifydb_readonly cannot reach sensitive auth data (effective privileges)', () => {
  it('starts from the platform default ACL that would have exposed every new table', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    await pg.exec(`CREATE TABLE unrelated (x int)`);
    expect(await one(pg, `SELECT has_table_privilege('netlifydb_readonly', 'unrelated', 'SELECT') AS ro`)).toEqual({ ro: true });
  });
  it('has no table, column or sequence privilege on any auth table after 001 alone', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    await applyMigration(pg, SCHEMA_SQL);
    for (const t of AUTH_TABLES) {
      expect(await one(pg, `SELECT has_table_privilege('netlifydb_readonly', $1, '${ALL_TABLE_PRIVS}') AS t, has_any_column_privilege('netlifydb_readonly', $1, 'SELECT, INSERT, UPDATE, REFERENCES') AS c`, [t])).toEqual({ t: false, c: false });
    }
    expect(await one(pg, `SELECT has_sequence_privilege('netlifydb_readonly', 'auth_audit_events_id_seq', 'SELECT, USAGE, UPDATE') AS s`)).toEqual({ s: false });
  });
  it('is denied when actually querying session hashes, invitations, members, rate limits and audit records', async () => {
    const pg = await migrated();
    await pg.exec(`RESET SESSION AUTHORIZATION; SET SESSION AUTHORIZATION netlifydb_readonly`);
    for (const t of AUTH_TABLES) await expect(pg.query(`SELECT * FROM ${t} LIMIT 1`)).rejects.toThrow(/permission denied/);
    await expect(pg.query(`SELECT token_hash FROM auth_sessions`)).rejects.toThrow(/permission denied/);
    await expect(pg.query(`SELECT last_value FROM auth_audit_events_id_seq`)).rejects.toThrow(/permission denied/);
    await expect(pg.exec(`SET ROLE hourvia_auth_runtime`)).rejects.toThrow(/permission denied/);
    await expect(pg.exec(`SET ROLE netlifydb_owner`)).rejects.toThrow(/permission denied/);
  });
  it('PUBLIC has no access, and ACLs list only the owner and the runtime role', async () => {
    const pg = await migrated();
    const { rows } = await pg.query<{ relname: string; grantee: string }>(`
      SELECT c.relname, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee
      FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
      WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'S')
      UNION
      SELECT c.relname || '.' || at.attname, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
      FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid CROSS JOIN LATERAL aclexplode(at.attacl) a
      WHERE c.relnamespace = 'public'::regnamespace`);
    expect(new Set(rows.map(r => r.grantee))).toEqual(new Set(['netlifydb_owner', 'hourvia_auth_runtime']));
  });
  it('self-check aborts the migration if readonly gains access through an inherited role such as pg_read_all_data', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    await pg.exec(`RESET SESSION AUTHORIZATION; GRANT pg_read_all_data TO netlifydb_readonly; SET SESSION AUTHORIZATION netlifydb_owner`);
    await applyMigration(pg, SCHEMA_SQL);
    await expect(applyMigration(pg, ROLE_SQL)).rejects.toThrow(/netlifydb_readonly still has access/);
  });
  it('self-check aborts the migration if any other role (e.g. token_roles) holds a table or column grant', async () => {
    for (const grant of ['GRANT SELECT ON auth_sessions TO token_roles', 'GRANT SELECT (token_hash) ON auth_sessions TO token_roles']) {
      const pg = new PGlite();
      await asNetlifyOwner(pg);
      await pg.exec(`RESET SESSION AUTHORIZATION; CREATE ROLE token_roles NOLOGIN; SET SESSION AUTHORIZATION netlifydb_owner`);
      await applyMigration(pg, SCHEMA_SQL);
      await pg.exec(grant);
      await expect(applyMigration(pg, ROLE_SQL)).rejects.toThrow(/unexpected role/);
    }
  });
  it('trigger functions are not executable by PUBLIC but still fire for the runtime role', async () => {
    const pg = await migrated();
    expect(await one(pg, `SELECT has_function_privilege('netlifydb_readonly', 'hourvia_guard_member_update()', 'EXECUTE') AS a, has_function_privilege('hourvia_auth_runtime', 'hourvia_reject_audit_mutation()', 'EXECUTE') AS b`)).toEqual({ a: false, b: false });
    const store = new PostgresAuthStore(roleScopedSqlClient(pgliteClient(pg)));
    await store.audit({ eventType: 'login', outcome: 'success' }, new Date());
    const { rows } = await pg.query(`SELECT 1 FROM auth_audit_events`);
    expect(rows).toHaveLength(1);
  });
});

describe('restricted runtime role is the only path for auth SQL, and it fails closed', () => {
  it('every store query runs as hourvia_auth_runtime with netlifydb_owner as the session user', async () => {
    const pg = await migrated();
    const sql = roleScopedSqlClient(pgliteClient(pg));
    expect((await sql.query(`SELECT current_user AS c, session_user AS s`)).rows[0]).toEqual({ c: 'hourvia_auth_runtime', s: 'netlifydb_owner' });
    expect((await pg.query(`SELECT current_user AS c`)).rows[0]).toEqual({ c: 'netlifydb_owner' }); // SET LOCAL did not leak
  });
  it('fails closed if the grant to netlifydb_owner is revoked after promotion', async () => {
    const pg = await migrated();
    await pg.exec(`REVOKE hourvia_auth_runtime FROM netlifydb_owner`);
    const store = new PostgresAuthStore(roleScopedSqlClient(pgliteClient(pg)));
    await expect(store.findMemberByEmail('a@t.test')).rejects.toThrow(/permission denied to set role/);
  });
  it('fails closed if the function connects as netlifydb_readonly instead of netlifydb_owner', async () => {
    const pg = await migrated();
    await pg.exec(`RESET SESSION AUTHORIZATION; SET SESSION AUTHORIZATION netlifydb_readonly`);
    const store = new PostgresAuthStore(roleScopedSqlClient(pgliteClient(pg)));
    await expect(store.findMemberByEmail('a@t.test')).rejects.toThrow(/permission denied/);
  });
  it('production wiring wraps the platform pool with roleScopedSqlClient and nothing else touches the database', () => {
    const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
    const runtime = read('./runtime.ts');
    expect(runtime).toMatch(/new PostgresAuthStore\(roleScopedSqlClient\(poolSqlClient\(getDatabase\(\)\.pool/);
    expect(runtime.match(/getDatabase\(/g)).toHaveLength(1);
    expect(read('./sql-role.ts')).toMatch(/AUTH_DB_ROLE = 'hourvia_auth_runtime'/);
    expect(read('../../netlify/functions/auth-api.mts')).not.toMatch(/getDatabase|@netlify\/database/);
  });
});

describe('table constraints (invitation, session, membership, audit, rate limit)', () => {
  const ids = async (pg: PGlite) => {
    const m = await one<{ id: string }>(pg, `INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', gen_random_uuid(), 'i@t.test', 'contractor', 'invited') RETURNING id`);
    return m.id;
  };
  const hex = 'a'.repeat(64);
  it('membership', async () => {
    const pg = await migrated();
    const bad = [
      `('thrivesource', gen_random_uuid(), 'A@t.test', 'contractor', 'invited', NULL, NULL)`, // uppercase email
      `('thrivesource', gen_random_uuid(), 'x@t.test', 'owner', 'invited', NULL, NULL)`, // unknown role
      `('thrivesource', NULL, 'x@t.test', 'contractor', 'active', now(), NULL)`, // active without identity
      `('thrivesource', gen_random_uuid(), 'x@t.test', 'contractor', 'active', NULL, NULL)`, // active without activated_at
      `('thrivesource', gen_random_uuid(), 'x@t.test', 'contractor', 'disabled', NULL, NULL)`, // disabled without disabled_at
      `('other', gen_random_uuid(), 'x@t.test', 'contractor', 'invited', NULL, NULL)`, // other workspace
    ];
    for (const v of bad) await expect(pg.query(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status, activated_at, disabled_at) VALUES ${v}`)).rejects.toThrow(/violates/);
    const id = await ids(pg);
    await expect(pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('thrivesource', 'i@t.test', 'contractor', 'invited')`)).rejects.toThrow(/duplicate key/);
    await expect(pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now(), disabled_by = id WHERE id = $1`, [id])).rejects.toThrow(/violates/);
  });
  it('invitation', async () => {
    const pg = await migrated();
    const id = await ids(pg);
    const ins = (status: string, extra = '', vals = '') => pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, expires_at${extra}) VALUES ('thrivesource', $1, 'i@t.test', 'contractor', '${status}', now() + interval '1 day'${vals})`, [id]);
    await ins('pending');
    await expect(ins('pending')).rejects.toThrow(/duplicate key/); // one pending per member
    await expect(ins('accepted')).rejects.toThrow(/violates/); // accepted without accepted_at
    await expect(ins('revoked', ', accepted_at', ', now()')).rejects.toThrow(/violates/);
    await expect(pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, expires_at) VALUES ('thrivesource', $1, 'i@t.test', 'contractor', 'revoked', now() - interval '1 day')`, [id])).rejects.toThrow(/violates/);
    await expect(pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, expires_at) VALUES ('thrivesource', gen_random_uuid(), 'i@t.test', 'contractor', 'revoked', now() + interval '1 day')`)).rejects.toThrow(/foreign key/);
  });
  it('session', async () => {
    const pg = await migrated();
    const id = await ids(pg);
    const ins = (cols: string) => pg.query(`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason) VALUES ${cols}`, [id]);
    await expect(ins(`('NOTHEX', $1, now(), now(), now() + interval '1 hour', now() + interval '2 hour', NULL, NULL)`)).rejects.toThrow(/violates/);
    await expect(ins(`('${hex}', $1, now(), now(), now() + interval '3 hour', now() + interval '2 hour', NULL, NULL)`)).rejects.toThrow(/violates/); // idle > absolute
    await expect(ins(`('${hex}', $1, now(), now() - interval '1 hour', now() + interval '1 hour', now() + interval '2 hour', NULL, NULL)`)).rejects.toThrow(/violates/); // seen before created
    await expect(ins(`('${hex}', $1, now(), now(), now() + interval '1 hour', now() + interval '2 hour', NULL, 'logout')`)).rejects.toThrow(/violates/); // reason without revoked_at
    await ins(`('${hex}', $1, now(), now(), now() + interval '1 hour', now() + interval '2 hour', NULL, NULL)`);
    await expect(ins(`('${hex}', $1, now(), now(), now() + interval '1 hour', now() + interval '2 hour', NULL, NULL)`)).rejects.toThrow(/duplicate key/);
  });
  it('audit', async () => {
    const pg = await migrated();
    const ins = (cols: string, vals: string) => pg.query(`INSERT INTO auth_audit_events (workspace_id, occurred_at, outcome${cols}) VALUES ('thrivesource', now(), 'success'${vals})`);
    await expect(ins(', event_type', `, 'Login; DROP'`)).rejects.toThrow(/violates/);
    await expect(ins(', event_type, email_hmac', `, 'login', 'raw@email.test'`)).rejects.toThrow(/violates/);
    await expect(ins(', event_type, ip_hmac', `, 'login', '203.0.113.10'`)).rejects.toThrow(/violates/);
    await expect(ins(', event_type, details', `, 'login', '[1,2]'::jsonb`)).rejects.toThrow(/violates/);
    await expect(ins(', event_type, outcome', `, 'login', 'maybe'`)).rejects.toThrow();
    await ins(', event_type, email_hmac, ip_hmac', `, 'login', '${hex}', '${hex}'`);
    await expect(pg.query(`INSERT INTO auth_audit_events (id, workspace_id, occurred_at, event_type, outcome) VALUES (999, 'thrivesource', now(), 'login', 'success')`)).rejects.toThrow(/non-DEFAULT value/);
  });
  it('rate limit', async () => {
    const pg = await migrated();
    const ins = (bucket: string, hits: number) => pg.query(`INSERT INTO auth_rate_limits (bucket, window_start, hits) VALUES ($1, '2026-11-03T10:00:00Z', $2)`, [bucket, hits]);
    await expect(ins('login_email:someone@example.com', 1)).rejects.toThrow(/violates/); // raw value instead of HMAC
    await expect(ins(`login_email:${hex}`, 0)).rejects.toThrow(/violates/);
    await ins(`login_email:${hex}`, 1);
    await expect(ins(`login_email:${hex}`, 1)).rejects.toThrow(/duplicate key/);
  });
});
