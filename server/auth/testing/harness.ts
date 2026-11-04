// TEST-ONLY harness: embedded Postgres (PGlite) running the staged proposal SQL, plus a mocked Supabase provider.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { handleAuthRequest } from '../http';
import { roleScopedSqlClient } from '../sql-role';
import { PostgresAuthStore } from '../store-postgres';
import { ProviderConflictError, type AuthConfig, type AuthDeps, type IdentityProvider, type OtpVerification, type SqlClient } from '../types';

// Sprint 1.8: tests run the promoted migration files, i.e. exactly what the Netlify migration runner applies.
// migration-readiness.test.ts asserts they stay byte-identical to the reviewed proposals.
const migration = (name: string) => readFileSync(fileURLToPath(new URL(`../../../netlify/database/migrations/${name}`, import.meta.url)), 'utf8');
export const SCHEMA_SQL = migration('20261103170000_create-auth-foundation.sql');
export const ROLE_SQL = migration('20261103170100_restrict-auth-runtime-role.sql');
// 20261104120000 is applied on the preview branch and stays immutable; 20261104130000 corrects it (forward-only).
export const SUPER_ADMIN_SQL = migration('20261104120000_super-admin-role.sql');
export const PLATFORM_SQL = migration('20261104130000_platform-privileges-correction.sql');
// Sprint 1.8 Platform Administration foundation (forward-only, functions only).
export const PLATFORM_ADMIN_SQL = migration('20261104150000_platform-administration-read-access.sql');
const operation = (name: string) => readFileSync(fileURLToPath(new URL(`../../../db/operations/platform/${name}`, import.meta.url)), 'utf8');
export const GRANT_PLATFORM_SQL = operation('grant-platform-super-admin.sql');
export const REVOKE_PLATFORM_SQL = operation('revoke-platform-super-admin.sql');
export const REINSTATE_MEMBER_SQL = operation('reinstate-disabled-member.sql');
export const PLATFORM_EMAIL = 'livingitsolutions@gmail.com';
/** Fills quoted operator placeholders exactly as the runbook instructs, e.g. { SUPABASE_AUTH_UID: '…' }. */
export function fillOperatorSql(template: string, values: Record<string, string>) {
  let sql = template;
  for (const [key, value] of Object.entries({ APPROVAL_REF: 'CHG-2026-1104', ...values })) sql = sql.replaceAll(`'<${key}>'`, `'${value.replaceAll("'", "''")}'`);
  return sql;
}
export const ORIGIN = 'https://hourvia.test';

/**
 * Emulation of the Netlify Database role catalog, reproduced from read-only pg_roles / pg_auth_members /
 * pg_default_acl / pg_database queries on this project's database branch (PostgreSQL 18.6, 2026-11-03;
 * re-checked in Sprint 1.8: netlifydb_owner also has REPLICATION, and a NOLOGIN token_roles role exists).
 * PGlite's bootstrap superuser stands in for cloud_admin. Migrations and owner-side seeding run as the
 * NON-superuser netlifydb_owner, so a statement that only works for a superuser fails here too.
 * Not proven identical to Neon (which may patch role checks) — the promotion preview deploy is the real test.
 */
export const PLATFORM_ROLES_SQL = `
  CREATE ROLE neon_superuser NOLOGIN CREATEROLE CREATEDB BYPASSRLS;
  CREATE ROLE netlifydb_owner LOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;
  CREATE ROLE netlifydb_readonly LOGIN;
  CREATE ROLE token_roles NOLOGIN;
  GRANT neon_superuser TO netlifydb_owner;
  GRANT pg_read_all_data, pg_write_all_data, pg_monitor, pg_signal_backend TO neon_superuser WITH ADMIN OPTION;
  GRANT netlifydb_readonly TO netlifydb_owner WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
  DO $$ BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO netlifydb_owner', current_database()); END $$;
  GRANT USAGE ON SCHEMA public TO netlifydb_readonly;
  ALTER DEFAULT PRIVILEGES FOR ROLE netlifydb_owner IN SCHEMA public GRANT SELECT ON TABLES TO netlifydb_readonly;
`;

/** Creates the platform roles, then switches the whole connection to netlifydb_owner (not a superuser). */
export async function asNetlifyOwner(pg: PGlite) {
  await pg.exec(PLATFORM_ROLES_SQL);
  await pg.exec('SET SESSION AUTHORIZATION netlifydb_owner');
}

/** Applies one migration file the way Netlify's migration tooling does: one transaction per file. */
export const applyMigration = (pg: PGlite, sql: string) => pg.transaction(async tx => { await tx.exec(sql); });

export function pgliteClient(pg: PGlite): SqlClient {
  return {
    query: async <T>(text: string, params?: unknown[]) => ({ rows: (await pg.query<T>(text, params)).rows }),
    transaction: fn => pg.transaction(tx => fn({ query: async <T>(text: string, params?: unknown[]) => ({ rows: (await tx.query<T>(text, params)).rows }), transaction: () => Promise.reject(new Error('nested')) })),
  };
}

/** Mock of Supabase Auth behaviour Hourvia depends on. Not a substitute for the live tests. */
export class FakeSupabase implements IdentityProvider {
  users = new Map<string, { id: string; password: string | null; banned: boolean }>();
  inviteTokens = new Map<string, string>();
  recoveryCodes = new Map<string, string>();
  recoveryTokens = new Map<string, string>();
  issued: string[] = []; revoked: { token: string; scope: string }[] = []; invited: string[] = []; recoverySent: string[] = []; banned: string[] = [];
  private seq = 0;
  outage = false;
  addUser(email: string, password: string | null) { const id = `00000000-0000-4000-8000-${String(++this.seq).padStart(12, '0')}`; this.users.set(email, { id, password, banned: false }); return id; }
  private session(email: string) { const token = `sb-access-${++this.seq}-${email}`; this.issued.push(token); return { userId: this.users.get(email)!.id, accessToken: token }; }
  async signInWithPassword(email: string, password: string) {
    if (this.outage) throw new Error('outage');
    const user = this.users.get(email);
    return user && !user.banned && user.password !== null && user.password === password ? this.session(email) : null;
  }
  async verifyEmailOtp(p: OtpVerification) {
    let email: string | undefined;
    if ('code' in p) { if (this.recoveryCodes.get(p.email) === p.code) { email = p.email; this.recoveryCodes.delete(p.email); } }
    else { const map = p.type === 'invite' ? this.inviteTokens : this.recoveryTokens; email = map.get(p.tokenHash); map.delete(p.tokenHash); }
    return email ? this.session(email) : null;
  }
  async revokeSession(token: string, scope: 'local' | 'global') { this.revoked.push({ token, scope }); }
  async inviteUser(email: string) {
    const existing = this.users.get(email);
    if (existing?.password) throw new ProviderConflictError('identity_exists');
    const id = existing?.id ?? this.addUser(email, null);
    const token = `invite${'x'.repeat(20)}${++this.seq}`; this.inviteTokens.set(token, email); this.invited.push(email);
    return { userId: id };
  }
  async sendRecovery(email: string) { this.recoverySent.push(email); this.recoveryCodes.set(email, '482913'); this.recoveryTokens.set(`recovery${'y'.repeat(20)}${++this.seq}`, email); }
  async setPassword(userId: string, password: string) { for (const u of this.users.values()) if (u.id === userId) u.password = password; }
  async banUser(userId: string) { this.banned.push(userId); for (const u of this.users.values()) if (u.id === userId) u.banned = true; }
  tokenFor(email: string, map: Map<string, string>) { return [...map].find(([, e]) => e === email)?.[0]; }
}

export async function createHarness(options: { schema?: boolean; restrictedRole?: boolean; correction?: boolean; platformAdmin?: boolean; config?: Partial<AuthConfig>; now?: Date } = {}) {
  const pg = new PGlite();
  await asNetlifyOwner(pg);
  if (options.schema !== false) await applyMigration(pg, SCHEMA_SQL);
  if (options.schema !== false && options.restrictedRole !== false) await applyMigration(pg, ROLE_SQL);
  if (options.schema !== false && options.restrictedRole !== false && options.correction !== false) {
    await applyMigration(pg, SUPER_ADMIN_SQL);
    await applyMigration(pg, PLATFORM_SQL);
    if (options.platformAdmin !== false) await applyMigration(pg, PLATFORM_ADMIN_SQL);
  }
  // Like production: every store statement runs under SET LOCAL ROLE hourvia_auth_runtime. Seeding via `pg` runs
  // as netlifydb_owner (non-superuser), like the reviewed bootstrap.
  const sql = roleScopedSqlClient(pgliteClient(pg));
  const provider = new FakeSupabase();
  // The platform console functions check session expiry against the database clock (now()), so platform tests start
  // the application clock at real time with { now: new Date() }.
  const clock = { now: options.now ?? new Date('2026-11-03T10:00:00Z') };
  const sleeps: number[] = [];
  const config: AuthConfig = { hashKey: 'k'.repeat(48), appOrigin: ORIGIN, emailDeliveryAuthorized: true, idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200, invitationTtlSeconds: 7 * 86400, recoveryMinimumMs: 750, smokeTestEmails: null, ...options.config };
  const deps: AuthDeps = { store: new PostgresAuthStore(sql), provider, config, now: () => new Date(clock.now), sleep: async ms => { sleeps.push(ms); } };
  const advance = (seconds: number) => { clock.now = new Date(clock.now.getTime() + seconds * 1000); };

  async function call(method: 'GET' | 'POST', path: string, init: { body?: unknown; cookie?: string | null; headers?: Record<string, string>; ip?: string } = {}) {
    const headers: Record<string, string> = method === 'POST' ? { origin: ORIGIN, 'content-type': 'application/json' } : {};
    if (init.cookie) headers.cookie = `__Host-hourvia_session=${init.cookie}`;
    const res = await handleAuthRequest(new Request(ORIGIN + path, { method, headers: { ...headers, ...init.headers }, body: method === 'POST' ? JSON.stringify(init.body ?? {}) : undefined }), init.ip ?? '203.0.113.10', async () => deps);
    const text = await res.text();
    const setCookie = res.headers.get('set-cookie');
    return { status: res.status, text, json: text ? JSON.parse(text) as Record<string, any> : null, setCookie, headers: res.headers, cookie: setCookie?.match(/^__Host-hourvia_session=([^;]*)/)?.[1] || null };
  }

  /** Reviewed-bootstrap equivalent: an active admin linked to a Supabase identity. */
  async function seedMember(email: string, role: 'workspace_admin' | 'workspace_manager' | 'contractor', password = 'correct horse battery', extra: { approval?: boolean; status?: string } = {}) {
    const authUserId = provider.addUser(email, password);
    const { rows } = await pg.query<{ id: string }>(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status, approval_authorized, activated_at, disabled_at)
       VALUES ('thrivesource', $1, $2, $3, $4, $5, $6, CASE WHEN $5 <> 'invited' THEN now() END, CASE WHEN $5 = 'disabled' THEN now() END) RETURNING id`,
      [authUserId, email, email.split('@')[0], role, extra.status ?? 'active', extra.approval ?? false]);
    return { id: rows[0]!.id, email, password, authUserId };
  }
  /** The Living IT Solutions Administrator, then the approved platform grant. The membership role stays workspace_admin. */
  async function seedPlatformSuperAdmin(email = PLATFORM_EMAIL, password = 'correct horse battery') {
    const member = await seedMember(email, 'workspace_admin', password);
    await pg.exec(fillOperatorSql(GRANT_PLATFORM_SQL, { SUPABASE_AUTH_UID: member.authUserId, EXPECTED_MEMBER_ID: member.id }));
    return member;
  }
  async function login(email: string, password = 'correct horse battery', ip?: string) { return call('POST', '/api/auth/login', { body: { email, password }, ip }); }
  return { pg, sql, provider, deps, config, clock, advance, sleeps, call, seedMember, seedPlatformSuperAdmin, login };
}
export type Harness = Awaited<ReturnType<typeof createHarness>>;
