// TEST-ONLY harness: embedded Postgres (PGlite) running the staged proposal SQL, plus a mocked Supabase provider.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { handleAuthRequest } from '../http';
import { roleScopedSqlClient } from '../sql-role';
import { PostgresAuthStore } from '../store-postgres';
import { ProviderConflictError, type AuthConfig, type AuthDeps, type IdentityProvider, type OtpVerification, type SqlClient } from '../types';

const proposal = (name: string) => readFileSync(fileURLToPath(new URL(`../../../db/proposals/sprint-1.7-auth/${name}`, import.meta.url)), 'utf8');
export const SCHEMA_SQL = proposal('001_create_auth_foundation.sql');
export const ROLE_SQL = proposal('002_restricted_auth_runtime_role.sql');
export const ORIGIN = 'https://hourvia.test';

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

export async function createHarness(options: { schema?: boolean; restrictedRole?: boolean; config?: Partial<AuthConfig> } = {}) {
  const pg = new PGlite();
  if (options.schema !== false) await pg.exec(SCHEMA_SQL);
  if (options.schema !== false && options.restrictedRole !== false) await pg.exec(ROLE_SQL);
  // Like production: every store statement runs under SET LOCAL ROLE hourvia_auth_runtime. Seeding via `pg` runs
  // as the owner, like the reviewed bootstrap.
  const sql = roleScopedSqlClient(pgliteClient(pg));
  const provider = new FakeSupabase();
  const clock = { now: new Date('2026-11-03T10:00:00Z') };
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
    const { rows } = await pg.query<{ id: string }>(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status, approval_authorized) VALUES ('thrivesource', $1, $2, $3, $4, $5, $6) RETURNING id`, [authUserId, email, email.split('@')[0], role, extra.status ?? 'active', extra.approval ?? false]);
    return { id: rows[0]!.id, email, password, authUserId };
  }
  async function login(email: string, password = 'correct horse battery', ip?: string) { return call('POST', '/api/auth/login', { body: { email, password }, ip }); }
  return { pg, sql, provider, deps, config, clock, advance, sleeps, call, seedMember, login };
}
export type Harness = Awaited<ReturnType<typeof createHarness>>;
