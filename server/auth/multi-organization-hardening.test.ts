// SPRINT 3.0.1: adversarial regression tests for the independent Sprint 3.0 review (H2, H3, M1-M4, L1, L2, L4).
// Disposable embedded PostgreSQL (PGlite) with the M8 PROPOSAL applied on top of M1-M7, synthetic data only. PGlite runs
// one connection, so these tests prove the logic and the guards; real multi-connection concurrency is covered by
// multi-organization.rehearsal.test.ts on a disposable PostgreSQL 18 cluster.
import { describe, expect, it } from 'vitest';
import {
  THRIVESOURCE_ORGANIZATION_ID, mintMultiOrganizationCapabilityForOfflineTests, organizationContextForVerifiedMembership,
  type OrganizationContext, type OrganizationId,
} from '../../src/domain/organization';
import { sha256Hex } from './crypto';
import { IdentityDirectory } from './organization-directory';
import { OrganizationAccessService, type OrganizationServiceDeps } from './organization-service';
import { statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { PostgresTenancyStore } from './store-tenancy';
import { analyzeTenantStatement, assertTenantStatement, TenantStatementRejectedError } from './tenant-sql';
import { M8_PROPOSAL_SQL, ORGANIZATIONS_SQL, PLATFORM_EMAIL, applyMigration, createHarness, type Harness } from './testing/harness';

const TS = THRIVESOURCE_ORGANIZATION_ID;
const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const GLOBEX = '6c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f' as OrganizationId;
const DAY = 86400_000;
const HOUR = 3600_000;
const cookie = (c: string) => c.repeat(43);
const rows = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows;
const one = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await rows<T>(h, text, params))[0]!;
const cap = mintMultiOrganizationCapabilityForOfflineTests();
const contextFor = (org: OrganizationId, slug: string): OrganizationContext =>
  organizationContextForVerifiedMembership({ organizationId: org, workspaceId: slug }, { id: org, slug, status: 'active' }, cap);

async function provision(h: Harness, id: OrganizationId, slug: string, seats = 5) {
  await h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, $2, $3, 'customer', 'active')`, [id, slug, slug.toUpperCase()]);
  await h.pg.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref) VALUES ($1, 'customer', 'standard', $2, 'CHG-TEST-1')`, [id, seats]);
}
async function member(h: Harness, org: OrganizationId, slug: string, email: string, role: string, authUserId?: string) {
  const uid = authUserId ?? h.provider.addUser(email, 'correct horse battery');
  const { rows: r } = await h.pg.query<{ id: string }>(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
    VALUES ($1, $2, $3, $4, 'x', $5, 'active', now()) RETURNING id`, [org, slug, uid, email, role]);
  return { id: r[0]!.id, authUserId: uid };
}
type Transaction = OrganizationServiceDeps['transaction'];
function wiring(h: Harness, wrap?: (inner: Transaction) => Transaction) {
  const sql = statementGuardedSqlClient(h.sql);
  const storeFor = (c: OrganizationContext) => new PostgresAuthStore(sql, c);
  const transaction: Transaction = fn => sql.transaction(tx => fn(c => new PostgresAuthStore(tx, c)));
  const service = new OrganizationAccessService({
    capability: cap, directory: new IdentityDirectory(sql), storeFor, tenancyFor: c => new PostgresTenancyStore(sql, c),
    transaction: wrap ? wrap(transaction) : transaction,
    now: () => new Date(h.clock.now), session: { idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200 },
  });
  return { sql, storeFor, service, ts: storeFor(contextFor(TS, 'thrivesource')), acme: storeFor(contextFor(ACME, 'acme')) };
}
async function session(h: Harness, store: PostgresAuthStore, memberId: string, c: string, absoluteMs = 12 * HOUR) {
  const now = new Date(h.clock.now);
  await store.createSession({ tokenHash: sha256Hex(cookie(c)), memberId, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + absoluteMs) });
  return { ip: '203.0.113.10', sessionToken: cookie(c) };
}
const liveSessions = (h: Harness, org: OrganizationId) => one<{ n: number }>(h, `SELECT count(*)::int AS n FROM auth_sessions WHERE organization_id = $1 AND revoked_at IS NULL`, [org]).then(r => r.n);
const switchAudits = (h: Harness) => rows(h, `SELECT organization_id::text AS o, outcome, details->>'direction' AS d, details->>'reason' AS r FROM auth_audit_events WHERE event_type = 'organization_switch' ORDER BY id`);

/** Dana: Manager in ThriveSource, Contractor in Acme (one identity). A ThriveSource Administrator who can revoke Dana. */
async function setup(wrap?: (h: Harness) => (inner: Transaction) => Transaction, start = new Date()) {
  const h = await createHarness({ now: start, multiOrganization: true });
  await provision(h, ACME, 'acme');
  const tsAdmin = await h.seedMember('admin@thrivesource.test', 'workspace_admin');
  const danaTs = await h.seedMember('dana@example.test', 'workspace_manager');
  const danaAcme = await member(h, ACME, 'acme', 'dana@example.test', 'contractor', danaTs.authUserId);
  return { h, tsAdmin, danaTs, danaAcme, ...wiring(h, wrap?.(h)) };
}

// ---------------------------------------------------------------------------------------------------------------------
describe('H2: one source session yields at most one replacement', () => {
  it('concurrent switches with the same token: exactly one succeeds and exactly one replacement exists', async () => {
    const { h, service, ts, danaTs } = await setup();
    const meta = await session(h, ts, danaTs.id, 'D');
    const outcomes = await Promise.all(Array.from({ length: 5 }, () => service.selectOrganization({ organizationId: ACME }, meta)));
    expect(outcomes.map(o => o.status).sort()).toEqual([200, 401, 401, 401, 401]);
    expect(outcomes.filter(o => o.status === 401).every(o => o.cookie === 'clear')).toBe(true);
    expect(await liveSessions(h, ACME)).toBe(1);
    expect(await liveSessions(h, TS)).toBe(0);
    const audits = await switchAudits(h);
    expect(audits.filter(a => a.outcome === 'success')).toHaveLength(2); // one 'out' + one 'in'
    expect(audits.filter(a => a.r === 'session_not_current')).toHaveLength(4);
  });
  it('replaying the source token after a successful switch issues nothing', async () => {
    const { h, service, ts, danaTs } = await setup();
    const meta = await session(h, ts, danaTs.id, 'D');
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(200);
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(401);
    expect(await liveSessions(h, ACME)).toBe(1);
  });
  it('logout that lands between validation and the switch transaction wins; no replacement is issued', async () => {
    let logout: (() => Promise<unknown>) | null = null;
    const { h, service, ts, danaTs } = await setup(() => inner => async fn => { await logout?.(); return inner(fn); });
    const meta = await session(h, ts, danaTs.id, 'D');
    logout = () => ts.revokeSession(sha256Hex(meta.sessionToken), 'logout', new Date(h.clock.now));
    expect(await service.selectOrganization({ organizationId: ACME }, meta)).toMatchObject({ status: 401, cookie: 'clear' });
    expect(await liveSessions(h, ACME)).toBe(0);
    expect(await one(h, `SELECT revoked_reason FROM auth_sessions WHERE token_hash = $1`, [sha256Hex(meta.sessionToken)])).toEqual({ revoked_reason: 'logout' });
  });
  it('administrator revocation that lands mid-switch wins; no replacement is issued', async () => {
    let revoke: (() => Promise<unknown>) | null = null;
    const { h, service, ts, danaTs, tsAdmin } = await setup(() => inner => async fn => { await revoke?.(); return inner(fn); });
    const meta = await session(h, ts, danaTs.id, 'D');
    revoke = () => ts.revokeMemberSessions(danaTs.id, 'admin_revoked', new Date(h.clock.now), tsAdmin.id);
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(401);
    expect(await liveSessions(h, ACME)).toBe(0);
  });
  it('an expired source session cannot be exchanged even if it is still unrevoked', async () => {
    const { h, service, ts, danaTs } = await setup();
    const meta = await session(h, ts, danaTs.id, 'D');
    h.advance(31 * 60); // past the 30-minute idle timeout
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(401);
    expect(await liveSessions(h, ACME)).toBe(0);
  });
  it('a failure while issuing the replacement rolls back the revocation: the user keeps the old session, nothing partial remains', async () => {
    const { h, service, ts, danaTs } = await setup(() => inner => fn => inner(storeFor => fn(c => {
      const store = storeFor(c);
      if (c.organizationId === ACME) store.createSession = () => Promise.reject(new Error('injected_failure'));
      return store;
    })));
    const meta = await session(h, ts, danaTs.id, 'D');
    expect(await service.selectOrganization({ organizationId: ACME }, meta)).toMatchObject({ status: 503, body: { error: 'organization_switch_failed' } });
    expect(await ts.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).not.toBeNull();
    expect(await liveSessions(h, ACME)).toBe(0);
    expect((await switchAudits(h)).filter(a => a.outcome === 'success')).toEqual([]);
  });
  it('a failing audit write inside the switch also rolls everything back (audit integrity)', async () => {
    const { h, service, ts, danaTs } = await setup(() => inner => fn => inner(storeFor => fn(c => {
      const store = storeFor(c);
      if (c.organizationId === ACME) store.audit = () => Promise.reject(new Error('injected_audit_failure'));
      return store;
    })));
    const meta = await session(h, ts, danaTs.id, 'D');
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(503);
    expect(await ts.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).not.toBeNull();
    expect(await liveSessions(h, ACME)).toBe(0);
    expect((await switchAudits(h)).filter(a => a.outcome === 'success')).toEqual([]);
  });
});

describe('H3: switching never extends the absolute session lifetime', () => {
  // Sprint 3.0.2 (G2): the session insert guard refuses a created_at ahead of the database clock, so these tests start
  // the application clock in the past and advance it toward (never beyond) real time.
  const past = () => new Date(Date.now() - 13 * HOUR);
  it('the replacement inherits the source absolute expiry, and the cookie never outlives it', async () => {
    const { h, service, ts, danaTs } = await setup(undefined, past());
    const meta = await session(h, ts, danaTs.id, 'D');
    const original = await one<{ a: Date }>(h, `SELECT absolute_expires_at AS a FROM auth_sessions WHERE token_hash = $1`, [sha256Hex(meta.sessionToken)]);
    h.advance(20 * 60); // within the 30-minute idle timeout
    const out = await service.selectOrganization({ organizationId: ACME }, meta);
    const next = (out.cookie as { set: string; maxAge: number });
    const replacement = await one<{ a: Date; i: Date }>(h, `SELECT absolute_expires_at AS a, idle_expires_at AS i FROM auth_sessions WHERE token_hash = $1`, [sha256Hex(next.set)]);
    expect(new Date(replacement.a).getTime()).toBe(new Date(original.a).getTime());
    expect(new Date(replacement.i).getTime()).toBeLessThanOrEqual(new Date(replacement.a).getTime());
    expect(next.maxAge).toBe(12 * 3600 - 20 * 60);
  });
  it('repeated switching stops working at the original 12-hour limit', async () => {
    const { h, service, ts, danaTs } = await setup(undefined, past());
    let meta = await session(h, ts, danaTs.id, 'E');
    let current: OrganizationId = TS, hops = 0, last = 200;
    for (let i = 0; i < 40; i++) {
      h.advance(25 * 60);
      const target: OrganizationId = current === TS ? ACME : TS;
      const o = await service.selectOrganization({ organizationId: target }, meta);
      last = o.status;
      if (o.status !== 200) break;
      hops++; current = target; meta = { ip: meta.ip, sessionToken: (o.cookie as { set: string }).set };
    }
    // 28 hops of 25 minutes = 11h40m; the 29th (12h05m) is refused and nothing is left alive.
    expect(hops).toBe(28);
    expect(last).toBe(401);
    expect(await service.principal(meta)).toBeNull();
    // No session anywhere is still usable: every one is revoked or past its absolute expiry.
    expect(await one(h, `SELECT count(*)::int AS n FROM auth_sessions WHERE revoked_at IS NULL AND absolute_expires_at > $1`, [new Date(h.clock.now)])).toEqual({ n: 0 });
  });
  it('the database refuses any session whose absolute lifetime exceeds 24 hours', async () => {
    const { h, acme, danaAcme } = await setup();
    await expect(session(h, acme, danaAcme.id, 'L', 25 * HOUR)).rejects.toThrow(/absolute lifetime exceeds 24 hours/);
    await expect(h.pg.query(`INSERT INTO auth_sessions (organization_id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason)
      VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', now() + interval '2 hours', now(), 'x')`, [ACME, 'b'.repeat(64), danaAcme.id])).rejects.toThrow(/created unrevoked/);
  });
});

describe('M1: platform authority stays in the ThriveSource context', () => {
  async function holderInAcme() {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    await provision(h, ACME, 'acme');
    const holder = await h.seedPlatformSuperAdmin();
    const acmeHolder = await member(h, ACME, 'acme', PLATFORM_EMAIL, 'workspace_admin', holder.authUserId);
    const acmeAdmin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
    return { h, holder, acmeHolder, acmeAdmin, ...wiring(h) };
  }
  it('the holder is platform_super_admin only through the ThriveSource membership', async () => {
    const { h, holder, acmeHolder } = await holderInAcme();
    expect(await one(h, `SELECT hourvia_member_authority($1, 'thrivesource') AS a`, [holder.id])).toEqual({ a: 'platform_super_admin' });
    expect(await one(h, `SELECT hourvia_member_authority($1, 'acme') AS a`, [acmeHolder.id])).toEqual({ a: 'workspace_admin' });
    // A ThriveSource member id cannot be passed as authority for another organization's slug.
    expect(await one(h, `SELECT hourvia_member_authority($1, 'acme') AS a`, [holder.id])).toEqual({ a: null });
  });
  it('the holder cannot invite, promote, demote, disable or end sessions of Administrators inside a customer organization', async () => {
    const { h, acmeHolder, acmeAdmin, acme } = await holderInAcme();
    const now = new Date(h.clock.now);
    const uid = h.provider.addUser('boss@acme.test', null);
    await expect(acme.upsertInvitation({ email: 'boss@acme.test', role: 'workspace_admin', displayName: '', authUserId: uid, invitedBy: acmeHolder.id, now, expiresAt: new Date(now.getTime() + DAY) }))
      .rejects.toThrow(/not authorized to grant this role/);
    await expect(acme.changeMemberRole({ memberId: acmeAdmin.id, expectedRole: 'workspace_admin', role: 'contractor', changedBy: acmeHolder.id, now })).rejects.toThrow(/role change is not authorized/);
    await expect(acme.disableMember(acmeAdmin.id, acmeHolder.id, now)).rejects.toThrow(/disable is not authorized/);
    await session(h, acme, acmeAdmin.id, 'V');
    await expect(acme.revokeMemberSessions(acmeAdmin.id, 'admin_revoked', now, acmeHolder.id)).rejects.toThrow(/session revocation is not authorized/);
    // Ordinary Administrator authority over non-Administrators still works in the customer organization.
    await expect(acme.upsertInvitation({ email: 'boss@acme.test', role: 'contractor', displayName: '', authUserId: uid, invitedBy: acmeHolder.id, now, expiresAt: new Date(now.getTime() + DAY) })).resolves.toMatchObject({ organizationId: ACME });
  });
  it('the service never grants a platform privilege or administrators.manage outside ThriveSource', async () => {
    const { h, holder, acmeHolder, service, ts, acme } = await holderInAcme();
    const inAcme = await session(h, acme, acmeHolder.id, 'P');
    expect(await service.principal(inAcme)).toMatchObject({ organizationId: ACME, role: 'workspace_admin', platformPrivileges: [] });
    expect(await service.authorize(inAcme, 'administrators.manage', { organizationId: ACME })).toBe(false);
    expect(await service.authorize(inAcme, 'workspace.manage', { organizationId: ACME })).toBe(true);
    const inTs = await session(h, ts, holder.id, 'Q');
    expect(await service.principal(inTs)).toMatchObject({ organizationId: TS, platformPrivileges: ['platform_super_admin'] });
    expect(await service.authorize(inTs, 'administrators.manage', { organizationId: TS })).toBe(true);
    expect(await service.authorize(inTs, 'administrators.manage', { organizationId: ACME })).toBe(false);
  });
  it('a customer Administrator cannot gain or hand out the privilege, and the single designated holder is unchanged', async () => {
    const { h, holder, acmeAdmin } = await holderInAcme();
    await expect(h.sql.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES ($1, 'platform_super_admin', 'CHG-1-1')`, [acmeAdmin.authUserId])).rejects.toThrow(/permission denied/);
    await expect(h.pg.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES ($1, 'platform_super_admin', 'CHG-1-2')`, [acmeAdmin.authUserId])).rejects.toThrow(/only to the designated identity/);
    expect(await rows(h, `SELECT auth_user_id::text AS u FROM platform_privileges WHERE revoked_at IS NULL`)).toEqual([{ u: holder.authUserId }]);
    expect(await rows(h, `SELECT auth_user_id::text AS u FROM platform_super_admin_designation`)).toEqual([{ u: holder.authUserId }]);
  });
});

describe('M2: suspension revokes sessions; reactivation never restores them', () => {
  it('member suspension revokes every session of that membership only; reactivation needs a fresh sign-in', async () => {
    const { h, service, ts, acme, danaTs, danaAcme } = await setup();
    const a1 = await session(h, acme, danaAcme.id, 'A'), a2 = await session(h, acme, danaAcme.id, 'B');
    const t1 = await session(h, ts, danaTs.id, 'T');
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    expect(await rows(h, `SELECT revoked_reason AS r FROM auth_sessions WHERE member_id = $1 ORDER BY created_at`, [danaAcme.id])).toEqual([{ r: 'member_suspended' }, { r: 'member_suspended' }]);
    expect((await service.revalidate(t1)).status).toBe(200); // the ThriveSource membership of the same identity is untouched
    await h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id]);
    for (const m of [a1, a2]) expect((await service.revalidate(m)).status).toBe(401);
    expect((await service.revalidate(await session(h, acme, danaAcme.id, 'F'))).status).toBe(200);
    const audit = await rows(h, `SELECT details->>'reason' AS r, details->>'authority' AS a FROM auth_audit_events WHERE event_type = 'session_revocation' AND subject_member_id = $1`, [danaAcme.id]);
    expect(audit).toEqual([{ r: 'member_suspended', a: 'operator' }, { r: 'member_suspended', a: 'operator' }]);
  });
  it('organization suspension or closure revokes every session in it; reactivation restores none', async () => {
    for (const status of ['suspended', 'closed'] as const) {
      const { h, service, ts, acme, danaTs, danaAcme } = await setup();
      const acmeAdmin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
      const s1 = await session(h, acme, danaAcme.id, 'A'), s2 = await session(h, acme, acmeAdmin.id, 'B');
      const t1 = await session(h, ts, danaTs.id, 'T');
      await h.pg.query(status === 'suspended'
        ? `UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`
        : `UPDATE organizations SET status = 'closed' WHERE id = $1`, [ACME]);
      expect(await liveSessions(h, ACME)).toBe(0);
      expect(await liveSessions(h, TS)).toBe(2 - 1); // Dana's ThriveSource session survives (the admin seed has none)
      expect((await rows(h, `SELECT DISTINCT revoked_reason AS r FROM auth_sessions WHERE organization_id = $1`, [ACME]))).toEqual([{ r: `organization_${status}` }]);
      await h.pg.query(`UPDATE organizations SET status = 'active', suspended_at = NULL, suspended_reason = NULL WHERE id = $1`, [ACME]);
      for (const m of [s1, s2]) expect((await service.revalidate(m)).status).toBe(401);
      expect((await service.revalidate(t1)).status).toBe(200);
    }
  });
  it('the database refuses new sessions for a suspended member or in a suspended organization', async () => {
    const { h, acme, danaAcme } = await setup();
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    await expect(session(h, acme, danaAcme.id, 'X')).rejects.toThrow(/active member of an active organization/);
    await h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id]);
    await h.pg.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]);
    await expect(session(h, acme, danaAcme.id, 'Y')).rejects.toThrow(/active member of an active organization/);
  });
  it('a switch into a suspended membership is refused and leaves the source session usable', async () => {
    const { h, service, ts, danaTs, danaAcme } = await setup();
    const meta = await session(h, ts, danaTs.id, 'D');
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    expect((await service.selectOrganization({ organizationId: ACME }, meta)).status).toBe(403);
    expect((await service.revalidate(meta)).status).toBe(200);
  });
});

describe('M3: customer-organization INSERTs must bind organization_id to the server context', () => {
  const acme = contextFor(ACME, 'acme'), ts = contextFor(TS, 'thrivesource');
  const allow = { allowOrganizationInsert: true };
  it('a default (organization_id-free) INSERT is rejected outside ThriveSource by the analyzer and by the run-time check', () => {
    const plain = `INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome) VALUES ($1, $2, $3, $4)`;
    expect(() => analyzeTenantStatement(plain, allow)).toThrow(/organization_id_required/);
    expect(() => assertTenantStatement(plain, ['acme', new Date(), 'login', 'denied'], acme)).toThrow(/organization_id_required/);
    // ThriveSource keeps the legacy default-derived INSERT unchanged.
    expect(assertTenantStatement(plain, ['thrivesource', new Date(), 'login', 'denied'], ts)).toMatchObject({ kind: 'default_insert' });
  });
  it('malformed, cross-tenant, multi-row and smuggled INSERTs are rejected', () => {
    const p = (n: number) => Array.from({ length: n }, (_, i) => `$${i + 1}`).join(', ');
    const cases: Array<[string, unknown[]]> = [
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES (${p(3)})`, ['h', 'm', TS]], // cross-tenant id
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES (${p(3)})`, ['h', 'm', GLOBEX]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES (${p(3)})`, ['h', 'm', ACME.toUpperCase()]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3), ($4, $5, $6)`, ['h', 'm', ACME, 'h2', 'm2', TS]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3) , ($4, $5, $3)`, ['h', 'm', ACME, 'h', 'm']],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) SELECT $1, $2, $3`, ['h', 'm', ACME]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, (SELECT $3))`, ['h', 'm', ACME]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, coalesce($3, $4))`, ['h', 'm', ACME, TS]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3::uuid)`, ['h', 'm', ACME]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, '${ACME}')`, ['h', 'm']],
      [`INSERT INTO auth_sessions (token_hash, organization_id, organization_id) VALUES ($1, $2, $3)`, ['h', ACME, TS]],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2) `, ['h', 'm']], // arity mismatch
      [`INSERT INTO workspace_members AS m (email, organization_id) VALUES ($1, $2) ON CONFLICT (workspace_id, email) DO UPDATE SET organization_id = $3`, ['e', ACME, TS]],
      [`INSERT INTO auth_sessions (token_hash, member_id) VALUES ($1, $2)`, ['h', 'm']], // default insert
      [`INSERT INTO organizations (id, slug) VALUES ($1, $2)`, [ACME, 'acme']],
      [`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3) RETURNING (SELECT 1 FROM auth_sessions)`, ['h', 'm', ACME]],
    ];
    for (const [text, params] of cases) expect(() => assertTenantStatement(text, params, acme), text).toThrow(TenantStatementRejectedError);
    // Explicit organization_id stays forbidden in the ThriveSource context, even with the matching id.
    expect(() => assertTenantStatement(`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3)`, ['h', 'm', TS], ts)).toThrow(/organization_id_assignment/);
    expect(assertTenantStatement(`INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3) RETURNING id`, ['h', 'm', ACME], acme)).toMatchObject({ kind: 'organization_insert', organizationParams: [3] });
  });
  it('every INSERT the customer-context store issues is explicit and bound to that context', async () => {
    const { h, service, ts, danaTs } = await setup();
    const seen: string[] = [];
    const meta = await session(h, ts, danaTs.id, 'D');
    const spied = new OrganizationAccessService({
      ...(service as unknown as { deps: OrganizationServiceDeps }).deps,
      transaction: fn => statementGuardedSqlClient(h.sql).transaction(tx => fn(c => new PostgresAuthStore({ query: (t, p) => { if (c.organizationId === ACME) seen.push(t); return tx.query(t, p); }, transaction: tx.transaction }, c))),
    });
    expect((await spied.selectOrganization({ organizationId: ACME }, meta)).status).toBe(200);
    const inserts = seen.filter(t => /^\s*INSERT/i.test(t));
    expect(inserts.length).toBe(2); // session + audit
    expect(inserts.every(t => /organization_id/.test(t))).toBe(true);
  });
});

describe('M4: seat, session and suspension guards fail closed outside READ COMMITTED', () => {
  async function inTx(h: Harness, isolation: string, statements: Array<[string, unknown[]?]>, runtime = true) {
    return h.pg.transaction(async tx => {
      await tx.query(`SET TRANSACTION ISOLATION LEVEL ${isolation}`);
      if (runtime) await tx.query('SET LOCAL ROLE hourvia_auth_runtime');
      for (const [t, p] of statements) await tx.query(t, p);
    });
  }
  it('invitations, activations, reactivations, sessions and suspensions are refused under REPEATABLE READ and SERIALIZABLE', async () => {
    const { h, danaAcme } = await setup();
    const admin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
    const { rows: [invitee] } = await h.pg.query<{ id: string }>(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status)
      VALUES ($1, 'acme', gen_random_uuid(), 'i@acme.test', 'i', 'contractor', 'invited') RETURNING id`, [ACME]);
    const invite: [string, unknown[]] = [`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
      VALUES ($1, 'acme', $2, 'i@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, invitee!.id, admin.id]];
    const newSession: [string, unknown[]] = [`INSERT INTO auth_sessions (organization_id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
      VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', now() + interval '2 hours')`, [ACME, 'c'.repeat(64), danaAcme.id]];
    for (const level of ['REPEATABLE READ', 'SERIALIZABLE']) {
      await expect(inTx(h, level, [invite])).rejects.toThrow(/requires? READ COMMITTED/);
      await expect(inTx(h, level, [newSession])).rejects.toThrow(/requires? READ COMMITTED/);
      await expect(inTx(h, level, [[`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]]], false)).rejects.toThrow(/requires? READ COMMITTED/);
      await expect(inTx(h, level, [[`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]]], false)).rejects.toThrow(/requires? READ COMMITTED/);
    }
    // Operator reactivation of a suspended member is a seat consumer too.
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    await expect(inTx(h, 'REPEATABLE READ', [[`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id]]], false)).rejects.toThrow(/requires? READ COMMITTED/);
    // The same work succeeds under READ COMMITTED (the PostgreSQL default and what the application uses).
    await inTx(h, 'READ COMMITTED', [[`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id]]], false);
    await inTx(h, 'READ COMMITTED', [invite, newSession]);
  });
  it('ThriveSource internal_unlimited is preserved: no limit, no expiry, unaffected by the guards', async () => {
    const { h, ts } = await setup();
    for (let i = 0; i < 8; i++) await h.seedMember(`ts${i}@t.test`, 'contractor');
    const tenancy = new PostgresTenancyStore(statementGuardedSqlClient(h.sql), contextFor(TS, 'thrivesource'));
    expect(await tenancy.seatEntitlement()).toEqual({ organizationId: TS, plan: 'internal_unlimited', seatLimit: null, billingExpiresAt: null });
    expect(ts).toBeDefined();
    await expect(h.pg.query(`UPDATE organization_seat_entitlements SET plan = 'standard', seat_limit = 10 WHERE organization_id = $1`, [TS])).rejects.toThrow(/internal_unlimited/);
  });
});

describe('L1: runtime INSERTs that no foreign key ties to an authorized member', () => {
  it('actor-less application audit rows are refused outside ThriveSource; member-bound rows and ThriveSource rows are accepted', async () => {
    const { h, danaAcme } = await setup();
    const audit = `INSERT INTO auth_audit_events (organization_id, workspace_id, occurred_at, event_type, outcome, actor_member_id) VALUES ($1, $2, now(), 'login', 'success', $3)`;
    await expect(h.sql.query(audit, [ACME, 'acme', null])).rejects.toThrow(/must name a member of that organization/);
    await h.sql.query(audit, [ACME, 'acme', danaAcme.id]);
    await h.sql.query(`INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome) VALUES ('thrivesource', now(), 'login', 'denied')`);
  });
  it('a member row the runtime inserts without an authorized invitation is refused at COMMIT; the invitation flow and operator SQL still work', async () => {
    const { h, acme } = await setup();
    const admin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
    await expect(h.sql.query(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, created_at)
      VALUES ($1, 'acme', gen_random_uuid(), 'squat@acme.test', 'x', 'contractor', 'invited', now())`, [ACME])).rejects.toThrow(/need an authorized invitation/);
    expect(await rows(h, `SELECT 1 FROM workspace_members WHERE email = 'squat@acme.test'`)).toEqual([]);
    const now = new Date(h.clock.now);
    await expect(acme.upsertInvitation({ email: 'ok@acme.test', role: 'contractor', displayName: '', authUserId: h.provider.addUser('ok@acme.test', null), invitedBy: admin.id, now, expiresAt: new Date(now.getTime() + DAY) })).resolves.toMatchObject({ status: 'invited' });
    await h.pg.query(`INSERT INTO workspace_members (organization_id, workspace_id, email, display_name, role, status) VALUES ($1, 'acme', 'op@acme.test', 'x', 'contractor', 'invited')`, [ACME]);
  });
});

describe('L2: organization directory visibility', () => {
  it('memberships of closed or provisioning organizations are never listed; suspended ones are listed but not selectable', async () => {
    const { h, service, ts, danaTs } = await setup();
    await provision(h, GLOBEX, 'globex');
    await member(h, GLOBEX, 'globex', 'dana@example.test', 'contractor', danaTs.authUserId);
    const INITECH = '3a2b1c0d-9e8f-4a7b-8c6d-5e4f3a2b1c0d' as OrganizationId;
    await provision(h, INITECH, 'initech');
    await member(h, INITECH, 'initech', 'dana@example.test', 'contractor', danaTs.authUserId);
    await h.pg.query(`UPDATE organizations SET status = 'closed' WHERE id = $1`, [GLOBEX]);
    await h.pg.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [INITECH]);
    const meta = await session(h, ts, danaTs.id, 'D');
    const listed = (await service.listOrganizations(meta)).body as { organizations: Array<{ organizationId: string; selectable: boolean }> };
    expect(listed.organizations.map(o => [o.organizationId, o.selectable]).sort()).toEqual([[ACME, true], [INITECH, false], [TS, true]].sort());
    for (const org of [GLOBEX, INITECH]) expect((await service.selectOrganization({ organizationId: org }, meta)).status).toBe(403);
  });
});

describe('L4: tightened M8 preconditions', () => {
  async function m7() { return createHarness({ now: new Date(), multiOrganization: false }); }
  it('refuses when the runtime already holds an organization_id write privilege', async () => {
    const h = await m7();
    await h.pg.query(`GRANT INSERT (organization_id) ON auth_sessions TO hourvia_auth_runtime`);
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/already holds an organization_id write privilege/);
    expect(await one(h, `SELECT to_regclass('public.organization_seat_entitlements') AS t`)).toEqual({ t: null });
  });
  it('refuses when an M7 organization_id default was changed', async () => {
    const h = await m7();
    await h.pg.query(`ALTER TABLE auth_audit_events ALTER COLUMN organization_id DROP DEFAULT`);
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/organization_id defaults are not in their reviewed state/);
  });
  it('refuses when a dropped constraint name exists only on a different table', async () => {
    const h = await m7();
    await h.pg.query(`ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_auth_user_id_key`);
    await h.pg.query(`ALTER TABLE auth_rate_limits ADD CONSTRAINT workspace_members_auth_user_id_key UNIQUE (bucket, window_start, hits)`);
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/single-organization constraints are not in their reviewed state/);
  });
  it('the M7 file the harness applies is still the pinned one', () => {
    expect(ORGANIZATIONS_SQL).toContain('organizations_single_tenant_m7');
  });
});
