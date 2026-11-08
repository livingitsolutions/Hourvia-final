// SPRINT 3.0: organization-first multi-tenancy. Disposable embedded PostgreSQL (PGlite) with the M8 PROPOSAL applied
// on top of M1-M7, synthetic data only. No Netlify Database, no Supabase, no real identity, no network.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  THRIVESOURCE_ORGANIZATION_ID, mintMultiOrganizationCapabilityForOfflineTests, organizationContextForVerifiedMembership,
  parseOrganizationId, type OrganizationContext, type OrganizationId,
} from '../../src/domain/organization';
import { sha256Hex } from './crypto';
import { IdentityDirectory, IdentityStatementRejectedError, IDENTITY_MEMBERSHIPS_SQL, LOCATE_SESSION_SQL, identityScopedSqlClient } from './organization-directory';
import { OrganizationAccessService } from './organization-service';
import { MIGRATIONS, MIGRATION_DIGESTS } from './production-database';
import { statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { PostgresTenancyStore } from './store-tenancy';
import { analyzeTenantStatement, assertTenantStatement, TenantStatementRejectedError } from './tenant-sql';
import { M8_PROPOSAL_SQL, PLATFORM_EMAIL, applyMigration, createHarness, type Harness } from './testing/harness';

const TS = THRIVESOURCE_ORGANIZATION_ID;
const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const GLOBEX = '6c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f' as OrganizationId;
const rows = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows;
const one = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await rows<T>(h, text, params))[0]!;
const cookie = (c: string) => c.repeat(43);
const hashOf = (c: string) => sha256Hex(cookie(c));
const DAY = 86400_000;

/** Operator-side provisioning (owner SQL): a customer organization with a standard seat entitlement. */
async function provision(h: Harness, id: OrganizationId, slug: string, seats: number | null = 5, billingExpiresAt: Date | null = null) {
  await h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, $2, $3, 'customer', 'active')`, [id, slug, slug.toUpperCase()]);
  if (seats !== null) {
    await h.pg.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, billing_expires_at, approval_ref)
      VALUES ($1, 'customer', 'standard', $2, $3, 'CHG-TEST-1')`, [id, seats, billingExpiresAt]);
  }
}
/** Owner-side membership row in any organization (bootstrap equivalent). authUserId reuses an identity when given. */
async function member(h: Harness, org: OrganizationId, slug: string, email: string, role: 'workspace_admin' | 'workspace_manager' | 'contractor', opts: { authUserId?: string; status?: string } = {}) {
  const authUserId = opts.authUserId ?? h.provider.addUser(email, 'correct horse battery');
  const status = opts.status ?? 'active';
  const { rows: r } = await h.pg.query<{ id: string }>(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 <> 'invited' THEN now() END) RETURNING id`, [org, slug, authUserId, email, email.split('@')[0], role, status]);
  return { id: r[0]!.id, authUserId, email };
}
const cap = mintMultiOrganizationCapabilityForOfflineTests();
function contextFor(org: OrganizationId, slug: string): OrganizationContext {
  return organizationContextForVerifiedMembership({ organizationId: org, workspaceId: slug }, { id: org, slug, status: 'active' }, cap);
}
function wiring(h: Harness, capability: typeof cap | null = cap) {
  const sql = statementGuardedSqlClient(h.sql);
  const storeFor = (c: OrganizationContext) => new PostgresAuthStore(sql, c);
  const service = new OrganizationAccessService({
    capability, directory: new IdentityDirectory(sql), storeFor, tenancyFor: c => new PostgresTenancyStore(sql, c),
    transaction: fn => sql.transaction(tx => fn(c => new PostgresAuthStore(tx, c))),
    now: () => new Date(h.clock.now), session: { idleTimeoutSeconds: 1800, absoluteTimeoutSeconds: 43200 },
  });
  return { sql, storeFor, service };
}
async function session(h: Harness, store: PostgresAuthStore, memberId: string, c: string) {
  const now = new Date(h.clock.now);
  await store.createSession({ tokenHash: hashOf(c), memberId, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 43200_000) });
  return { ip: '203.0.113.10', sessionToken: cookie(c) };
}
async function m8() { return createHarness({ now: new Date(), multiOrganization: true }); }
/** One identity (Dana) that is Administrator in ThriveSource and Contractor in Acme, plus an Acme Administrator. */
async function twoOrganizations() {
  const h = await m8();
  await provision(h, ACME, 'acme', 5);
  const danaTs = await h.seedMember('dana@example.test', 'workspace_admin');
  const danaAcme = await member(h, ACME, 'acme', 'dana@example.test', 'contractor', { authUserId: danaTs.authUserId });
  const acmeAdmin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
  const w = wiring(h);
  const tsStore = w.storeFor(contextFor(TS, 'thrivesource'));
  const acmeStore = w.storeFor(contextFor(ACME, 'acme'));
  return { h, ...w, danaTs, danaAcme, acmeAdmin, tsStore, acmeStore };
}

// ---------------------------------------------------------------------------------------------------------------------
describe('M8 proposal location and M1-M7 integrity', () => {
  const dir = fileURLToPath(new URL('../../netlify/database/migrations/', import.meta.url));
  it('is staged only under db/proposals/sprint-3.0/, never in the auto-applied migrations directory', () => {
    expect(readdirSync(dir).sort()).toEqual(MIGRATIONS.map(m => `${m}.sql`));
    expect(readdirSync(dir).some(f => /multi-organization|20261106/.test(f))).toBe(false);
    expect(readdirSync(fileURLToPath(new URL('../../db/proposals/sprint-3.0/', import.meta.url))).sort())
      .toEqual(['20261106120000_multi-organization-memberships.sql', 'README.md']);
  });
  it('M1-M7 are byte-identical to the pinned SHA-256 digests', () => {
    for (const m of MIGRATIONS) {
      expect(createHash('sha256').update(readFileSync(`${dir}${m}.sql`)).digest('hex')).toBe(MIGRATION_DIGESTS[m]);
    }
  });
  it('is forward-only and narrowly privileged: no RLS, no role, no SECURITY DEFINER, no data rewrite, exactly two GRANTs', () => {
    const code = M8_PROPOSAL_SQL.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').replace(/'(?:[^']|'')*'/g, "''");
    expect(code).not.toMatch(/ROW LEVEL SECURITY|CREATE POLICY|ALTER ROLE|CREATE ROLE|OWNER TO|SECURITY DEFINER|DISABLE TRIGGER/i);
    expect(code).not.toMatch(/\bDROP TABLE (?!pg_temp\.hourvia_m8_baseline;)/i);
    expect(code).not.toMatch(/\bDROP\s+(?:COLUMN|FUNCTION|TRIGGER|INDEX)\b/i);
    // No top-level data rewrite. Function bodies are excluded from that scan, and (Sprint 3.0.1) the only UPDATEs they
    // contain are the two suspension revocations of auth_sessions; no function body deletes or truncates.
    const bodies = [...code.matchAll(/CREATE (?:OR REPLACE )?FUNCTION[\s\S]*?AS \$\$([\s\S]*?)\n\$\$;/g)].map(m => m[1]!);
    const topLevel = code.replace(/CREATE (?:OR REPLACE )?FUNCTION[\s\S]*?AS \$\$[\s\S]*?\n\$\$;/g, '');
    expect(topLevel).not.toMatch(/^\s*(?:UPDATE|DELETE FROM|TRUNCATE)\b/im);
    expect(bodies.join('\n')).not.toMatch(/\b(?:DELETE FROM|TRUNCATE)\b/i);
    expect(bodies.flatMap(b => [...b.matchAll(/^\s*UPDATE ([a-z_]+) SET/gim)].map(m => m[1]))).toEqual(['auth_sessions', 'auth_sessions']);
    expect(code.match(/^GRANT .*$/gm)).toEqual([
      'GRANT SELECT (organization_id, plan, seat_limit, billing_expires_at) ON organization_seat_entitlements TO hourvia_auth_runtime;',
      'GRANT INSERT (organization_id) ON workspace_members, workspace_invitations, auth_sessions, auth_audit_events TO hourvia_auth_runtime;',
    ]);
    // Only the reviewed single-organization constraints are dropped.
    expect([...code.matchAll(/DROP CONSTRAINT ([a-z0-9_]+)/g)].map(m => m[1]).sort()).toEqual([
      'auth_audit_events_workspace_id_check', 'manager_assignments_workspace_id_check', 'organizations_single_tenant_m7',
      'workspace_invitations_workspace_id_check', 'workspace_members_auth_user_id_key', 'workspace_members_status_check',
      'workspace_members_workspace_id_check']);
    expect(new Set(M8_PROPOSAL_SQL.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g))).toEqual(new Set([TS]));
  });
  it('pins every function search_path with pg_temp last', () => {
    const fns = [...M8_PROPOSAL_SQL.matchAll(/CREATE (?:OR REPLACE )?FUNCTION ([a-z_]+)\([^)]*\)[^$]*?SET search_path = ([^$]+?) AS \$\$/g)];
    expect(fns.length).toBe(M8_PROPOSAL_SQL.match(/CREATE (?:OR REPLACE )?FUNCTION/g)!.length);
    expect(new Set(fns.map(f => f[2]!.trim()))).toEqual(new Set(['pg_catalog, public, pg_temp']));
  });
});

describe('M8 application, preconditions and rollback', () => {
  it('applies to a populated M7 database and preserves every existing row', async () => {
    const h = await createHarness({ now: new Date() });
    const holder = await h.seedPlatformSuperAdmin();
    await h.seedMember('admin@t.test', 'workspace_admin');
    await h.seedMember('gone@t.test', 'contractor', undefined, { status: 'disabled' });
    const snapshot = async () => {
      const out: Record<string, unknown> = {};
      for (const t of ['workspace_members', 'workspace_invitations', 'auth_sessions', 'auth_audit_events', 'platform_privileges', 'platform_audit_events']) {
        out[t] = await rows(h, `SELECT xmin::text AS x, ctid::text AS c, to_jsonb(r) AS row FROM ${t} r ORDER BY ctid`);
      }
      return out;
    };
    const before = await snapshot();
    await applyMigration(h.pg, M8_PROPOSAL_SQL);
    expect(await snapshot()).toEqual(before);
    expect(await rows(h, `SELECT organization_id::text, plan, seat_limit, billing_expires_at FROM organization_seat_entitlements`))
      .toEqual([{ organization_id: TS, plan: 'internal_unlimited', seat_limit: null, billing_expires_at: null }]);
    expect(await one(h, `SELECT hourvia_is_verified_platform_candidate($1) AS ok`, [holder.authUserId])).toEqual({ ok: true });
    expect(await one(h, `SELECT to_regclass('pg_temp.hourvia_m8_baseline') AS t`)).toEqual({ t: null });
  });
  it('refuses to run twice or before M7, and rolls back completely', async () => {
    const h = await m8();
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/already exists/);
    const pre = await createHarness({ organizations: false });
    await expect(applyMigration(pre.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/apply M7/);
    expect(await one(pre, `SELECT to_regclass('public.organization_seat_entitlements') AS t`)).toEqual({ t: null });
  });
  it('refuses on an unexpected hourvia_* function or a second organization, leaving M7 intact', async () => {
    const h = await createHarness();
    await h.pg.exec(`CREATE FUNCTION hourvia_unreviewed() RETURNS int LANGUAGE sql SET search_path = pg_catalog, public, pg_temp AS 'SELECT 1'`);
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/unexpected hourvia_\* functions before M8/);
    expect(await one(h, `SELECT count(*)::int AS n FROM pg_constraint WHERE conname IN ('organizations_single_tenant_m7', 'workspace_members_auth_user_id_key')`)).toEqual({ n: 2 });
  });
  it('the self-check aborts the whole migration on a privilege surprise', async () => {
    const h = await createHarness();
    await h.pg.exec(`ALTER DEFAULT PRIVILEGES FOR ROLE netlifydb_owner IN SCHEMA public GRANT INSERT ON TABLES TO PUBLIC`);
    const tampered = M8_PROPOSAL_SQL.replace('REVOKE ALL ON organization_seat_entitlements FROM PUBLIC;', '');
    await expect(applyMigration(h.pg, tampered)).rejects.toThrow(/self-check failed: public has access to organization_seat_entitlements/);
    expect(await one(h, `SELECT to_regclass('public.organization_seat_entitlements') AS t, (SELECT count(*)::int FROM pg_constraint WHERE conname = 'organizations_single_tenant_m7') AS c`)).toEqual({ t: null, c: 1 });
  });
});

describe('M8 schema: organizations, global identities and tenant binding', () => {
  it('allows customer organizations; ThriveSource keeps its UUID, slug, internal kind and unlimited entitlement', async () => {
    const h = await m8();
    await provision(h, ACME, 'acme');
    await expect(h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'thrivesource', 'Fake', 'customer', 'active')`, [GLOBEX])).rejects.toThrow();
    await expect(h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'globex', 'Globex', 'internal', 'active')`, [GLOBEX])).rejects.toThrow(/organizations_internal_is_thrivesource/);
    await expect(h.pg.query(`UPDATE organization_seat_entitlements SET plan = 'standard', seat_limit = 3 WHERE organization_id = $1`, [TS])).rejects.toThrow();
    await expect(h.pg.query(`DELETE FROM organization_seat_entitlements WHERE organization_id = $1`, [TS])).rejects.toThrow(/cannot be deleted/);
    await expect(h.pg.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref) VALUES ($1, 'customer', 'internal_unlimited', NULL, 'CHG-X-1')`, [GLOBEX])).rejects.toThrow();
    const before = await one<{ u: Date }>(h, `SELECT updated_at AS u FROM organizations WHERE id = $1`, [ACME]);
    await h.pg.query(`UPDATE organizations SET name = 'Acme Inc' WHERE id = $1`, [ACME]);
    const after = await one<{ u: Date }>(h, `SELECT updated_at AS u FROM organizations WHERE id = $1`, [ACME]);
    expect(after.u.getTime()).toBeGreaterThanOrEqual(before.u.getTime());
  });
  it('one global identity can be a member of several organizations, once per organization', async () => {
    const { h, danaTs } = await twoOrganizations();
    expect(await rows(h, `SELECT organization_id::text AS o, role FROM workspace_members WHERE auth_user_id = $1 ORDER BY role`, [danaTs.authUserId]))
      .toEqual([{ o: ACME, role: 'contractor' }, { o: TS, role: 'workspace_admin' }]);
    await expect(member(h, ACME, 'acme', 'dana2@example.test', 'contractor', { authUserId: danaTs.authUserId })).rejects.toThrow(/workspace_members_organization_auth_user_key/);
  });
  it('the workspace key always matches the organization slug, and composite keys block cross-organization references', async () => {
    const { h, danaTs, acmeAdmin } = await twoOrganizations();
    await expect(h.pg.query(`INSERT INTO workspace_members (organization_id, workspace_id, email, role, status) VALUES ($1, 'thrivesource', 'x@t.test', 'contractor', 'invited')`, [ACME])).rejects.toThrow(/organization_workspace_fk|legacy_organization/);
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('acme', 'y@t.test', 'contractor', 'invited')`)).rejects.toThrow(/organization_workspace_fk/);
    // A session in Acme for a ThriveSource member, or an Acme invitation sent by a ThriveSource admin.
    await expect(h.pg.query(`INSERT INTO auth_sessions (organization_id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
      VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', now() + interval '2 hours')`, [ACME, 'a'.repeat(64), danaTs.id])).rejects.toThrow(/auth_sessions_member_org_fk|active member of an active organization/);
    await expect(h.pg.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, expires_at)
      VALUES ($1, 'acme', $2, 'owner@acme.test', 'workspace_admin', 'accepted', $3, now() + interval '1 day')`, [ACME, acmeAdmin.id, danaTs.id])).rejects.toThrow(/invited_by_org_fk|inviter is not authorized/);
  });
  it('organization_id is immutable for everyone; the runtime cannot create organizations or entitlements', async () => {
    const { h, danaAcme } = await twoOrganizations();
    await expect(h.pg.query(`UPDATE workspace_members SET organization_id = $1, workspace_id = 'thrivesource' WHERE id = $2`, [TS, danaAcme.id])).rejects.toThrow(/immutable/);
    await expect(h.sql.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id])).resolves.toBeDefined();
    await expect(h.sql.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'globex', 'G', 'customer', 'active')`, [GLOBEX])).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref) VALUES ($1, 'customer', 'standard', 9, 'CHG-1-2')`, [ACME])).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`UPDATE organization_seat_entitlements SET seat_limit = 999 WHERE organization_id = $1`, [ACME])).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`SELECT approval_ref FROM organization_seat_entitlements`)).rejects.toThrow(/permission denied/);
  });
  it('suspension is operator-only, needs a previously active member, and removes access', async () => {
    const { h, danaAcme, acmeStore } = await twoOrganizations();
    const meta = await session(h, acmeStore, danaAcme.id, 'D');
    await expect(h.sql.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id])).rejects.toThrow(/not permitted/);
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    expect(await acmeStore.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).toBeNull();
    await expect(h.pg.query(`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, role, status) VALUES ($1, 'acme', $2, 'never@acme.test', 'contractor', 'suspended')`,
      [ACME, h.provider.addUser('never@acme.test', null)])).rejects.toThrow(/workspace_members_suspended_was_active/);
  });
});

describe('Platform Super Admin preservation under M8', () => {
  it('only the ThriveSource membership of the designated mailbox can be a platform candidate', async () => {
    const h = await m8();
    await provision(h, ACME, 'acme');
    const impostor = await member(h, ACME, 'acme', PLATFORM_EMAIL, 'workspace_admin');
    expect(await one(h, `SELECT hourvia_is_verified_platform_candidate($1) AS ok`, [impostor.authUserId])).toEqual({ ok: false });
    await expect(h.pg.query(`INSERT INTO platform_super_admin_designation (auth_user_id, approval_ref) VALUES ($1, 'CHG-EVIL-1')`, [impostor.authUserId])).rejects.toThrow(/only the verified Living IT Solutions identity/);
  });
  it('organization Administrators cannot grant Administrator or any platform privilege, in any organization', async () => {
    const { h, acmeAdmin, acmeStore } = await twoOrganizations();
    const now = new Date(h.clock.now);
    const uid = h.provider.addUser('new@acme.test', null);
    await expect(acmeStore.upsertInvitation({ email: 'new@acme.test', role: 'workspace_admin', displayName: '', authUserId: uid, invitedBy: acmeAdmin.id, now, expiresAt: new Date(now.getTime() + DAY) }))
      .rejects.toThrow(/not authorized to grant this role/);
    await expect(h.sql.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES ($1, 'platform_super_admin', 'CHG-1-1')`, [acmeAdmin.authUserId])).rejects.toThrow(/permission denied/);
    await expect(acmeStore.upsertInvitation({ email: 'new@acme.test', role: 'contractor', displayName: '', authUserId: uid, invitedBy: acmeAdmin.id, now, expiresAt: new Date(now.getTime() + DAY) })).resolves.toMatchObject({ organizationId: ACME, workspaceId: 'acme' });
  });
  it('the platform console stays bound to the ThriveSource session of the holder', async () => {
    const h = await m8();
    await provision(h, ACME, 'acme');
    const holder = await h.seedPlatformSuperAdmin();
    const acmeHolder = await member(h, ACME, 'acme', PLATFORM_EMAIL, 'workspace_admin', { authUserId: holder.authUserId });
    const w = wiring(h);
    const ts = await session(h, w.storeFor(contextFor(TS, 'thrivesource')), holder.id, 'H');
    const acme = await session(h, w.storeFor(contextFor(ACME, 'acme')), acmeHolder.id, 'I');
    const store = w.storeFor(contextFor(TS, 'thrivesource'));
    expect(await store.platformOverview(sha256Hex(ts.sessionToken))).not.toBeNull();
    expect(await store.platformOverview(sha256Hex(acme.sessionToken))).toBeNull();
    expect(await one(h, `SELECT count(*)::int AS n FROM platform_privileges WHERE revoked_at IS NULL`)).toEqual({ n: 1 });
  });
});

describe('seat entitlements (database-enforced)', () => {
  async function seats(limit: number, billing: Date | null = null) {
    const h = await m8();
    await provision(h, ACME, 'acme', limit, billing);
    const admin = await member(h, ACME, 'acme', 'owner@acme.test', 'workspace_admin');
    const w = wiring(h);
    const ctx = contextFor(ACME, 'acme');
    const store = w.storeFor(ctx), tenancy = new PostgresTenancyStore(w.sql, ctx);
    const ids = new Map<string, string>();
    const invite = (email: string) => {
      const now = new Date(h.clock.now);
      if (!ids.has(email)) ids.set(email, h.provider.addUser(email, null));
      return store.upsertInvitation({ email, role: 'contractor', displayName: '', authUserId: ids.get(email)!, invitedBy: admin.id, now, expiresAt: new Date(now.getTime() + DAY) });
    };
    return { h, admin, store, tenancy, invite };
  }
  it('active members consume and pending invitations reserve; the database refuses over-allocation', async () => {
    const { h, tenancy, invite } = await seats(3);
    await invite('a@acme.test');
    await invite('b@acme.test');
    expect(await tenancy.seatCounts(new Date(h.clock.now))).toEqual({ activeMembers: 1, pendingInvitations: 2 });
    await expect(invite('c@acme.test')).rejects.toThrow(/no seat is available/);
    // Re-sending an existing invitation replaces its reservation instead of taking a second seat.
    await invite('a@acme.test');
    expect(await tenancy.seatCounts(new Date(h.clock.now))).toEqual({ activeMembers: 1, pendingInvitations: 2 });
  });
  it('suspended and disabled members free their seats; reactivation into a full organization is refused', async () => {
    const { h, admin, store, invite } = await seats(2);
    const worker = await member(h, ACME, 'acme', 'w@acme.test', 'contractor');
    await expect(invite('c@acme.test')).rejects.toThrow(/no seat is available/);
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [worker.id]);
    await invite('c@acme.test');
    await expect(h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [worker.id])).rejects.toThrow(/no seat is available/);
    const c = await store.findMemberByEmail('c@acme.test');
    expect(await store.disableMember(c!.id, admin.id, new Date(h.clock.now))).toBe(true);
    await h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [worker.id]);
  });
  it('expired invitations stop reserving; an expired billing entitlement refuses new seats', async () => {
    const { h, tenancy, invite } = await seats(2);
    await invite('a@acme.test');
    h.advance(2 * 86400);
    expect(await tenancy.seatCounts(new Date(h.clock.now))).toEqual({ activeMembers: 1, pendingInvitations: 0 });
    const expired = await seats(10, new Date(Date.now() + DAY));
    await expired.h.pg.query(`UPDATE organization_seat_entitlements SET billing_expires_at = now() - interval '1 minute' WHERE organization_id = $1`, [ACME]);
    await expect(expired.invite('x@acme.test')).rejects.toThrow(/entitlement has expired/);
  });
  it('an organization without an entitlement cannot invite or activate anyone (fail closed)', async () => {
    const h = await m8();
    await provision(h, GLOBEX, 'globex', null);
    await expect(member(h, GLOBEX, 'globex', 'a@globex.test', 'workspace_admin')).rejects.toThrow(/no seat entitlement/);
  });
  it('ThriveSource is unlimited, and memberships in different organizations are counted independently', async () => {
    const { h, danaTs } = await twoOrganizations();
    for (let i = 0; i < 12; i++) await h.seedMember(`ts${i}@t.test`, 'contractor');
    const w = wiring(h);
    const ts = new PostgresTenancyStore(w.sql, contextFor(TS, 'thrivesource'));
    const acme = new PostgresTenancyStore(w.sql, contextFor(ACME, 'acme'));
    const now = new Date(h.clock.now);
    expect(await ts.seatEntitlement()).toEqual({ organizationId: TS, plan: 'internal_unlimited', seatLimit: null, billingExpiresAt: null });
    expect(await ts.seatCounts(now)).toEqual({ activeMembers: 13, pendingInvitations: 0 });
    expect(await acme.seatCounts(now)).toEqual({ activeMembers: 2, pendingInvitations: 0 });
    expect(danaTs).toBeDefined();
  });
});

describe('organization context, switching and tenant isolation (service contracts)', () => {
  it('every contract is explicitly unavailable without the multi-organization capability', async () => {
    const { h, tsStore, danaTs } = await twoOrganizations();
    const meta = await session(h, tsStore, danaTs.id, 'D');
    const { service } = wiring(h, null);
    for (const outcome of [await service.listOrganizations(meta), await service.revalidate(meta), await service.selectOrganization({ organizationId: ACME }, meta), await service.seats(meta)]) {
      expect(outcome).toMatchObject({ status: 503, body: { error: 'multi_organization_unavailable' } });
    }
    expect(await service.authorize(meta, 'workspace.manage', { organizationId: TS })).toBe(false);
    expect(await service.principal(meta)).toBeNull();
  });
  it('lists the identity organizations with independent roles; suspended memberships are listed but not selectable', async () => {
    const { h, service, tsStore, danaTs } = await twoOrganizations();
    await provision(h, GLOBEX, 'globex');
    const g = await member(h, GLOBEX, 'globex', 'dana@example.test', 'workspace_manager', { authUserId: danaTs.authUserId });
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [g.id]);
    const meta = await session(h, tsStore, danaTs.id, 'D');
    const out = await service.listOrganizations(meta);
    expect(out.status).toBe(200);
    expect((out.body as { organizations: unknown[] }).organizations).toEqual([
      expect.objectContaining({ organizationId: ACME, role: 'contractor', selectable: true, current: false }),
      expect.objectContaining({ organizationId: GLOBEX, role: 'workspace_manager', status: 'suspended', selectable: false, current: false }),
      expect.objectContaining({ organizationId: TS, role: 'workspace_admin', selectable: true, current: true }),
    ]);
  });
  it('switching rotates the session into the target membership; the role follows the organization', async () => {
    const { h, service, tsStore, acmeStore, danaTs, danaAcme } = await twoOrganizations();
    const meta = await session(h, tsStore, danaTs.id, 'D');
    expect(await service.principal(meta)).toMatchObject({ organizationId: TS, role: 'workspace_admin' });
    const out = await service.selectOrganization({ organizationId: ACME }, meta);
    expect(out).toMatchObject({ status: 200, body: { organization: { organizationId: ACME, role: 'contractor', current: true } } });
    const next = (out.cookie as { set: string }).set;
    expect(next).not.toBe(meta.sessionToken);
    expect(await tsStore.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).toBeNull();
    expect((await acmeStore.resolveSession(sha256Hex(next), new Date(h.clock.now)))?.member.id).toBe(danaAcme.id);
    const principal = await service.principal({ ip: meta.ip, sessionToken: next });
    expect(principal).toMatchObject({ organizationId: ACME, role: 'contractor' });
    expect(await service.authorize({ ip: meta.ip, sessionToken: next }, 'workspace.manage', { organizationId: ACME })).toBe(false);
    expect(await rows(h, `SELECT organization_id::text AS o, outcome, details->>'direction' AS d FROM auth_audit_events WHERE event_type = 'organization_switch' ORDER BY id`))
      .toEqual([{ o: TS, outcome: 'success', d: 'out' }, { o: ACME, outcome: 'success', d: 'in' }]);
  });
  it('rejects unauthorized organization selection identically (non-member, suspended, malformed, inactive)', async () => {
    const { h, service, tsStore, danaTs, danaAcme } = await twoOrganizations();
    await provision(h, GLOBEX, 'globex');
    const meta = await session(h, tsStore, danaTs.id, 'D');
    const bodies = [];
    for (const organizationId of [GLOBEX, 'ACME', '00000000-0000-0000-0000-000000000000', ACME.toUpperCase()]) {
      bodies.push(await service.selectOrganization({ organizationId }, meta));
    }
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [danaAcme.id]);
    bodies.push(await service.selectOrganization({ organizationId: ACME }, meta));
    await h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [danaAcme.id]);
    await h.pg.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]);
    bodies.push(await service.selectOrganization({ organizationId: ACME }, meta));
    for (const b of bodies) expect(b).toEqual({ status: 403, body: { error: 'organization_not_available', message: expect.any(String) } });
    expect(await service.selectOrganization({ organizationId: ACME, role: 'workspace_admin' }, meta)).toMatchObject({ status: 400 });
    // The current session was never revoked by a rejected switch.
    expect(await tsStore.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).not.toBeNull();
  });
  it('a revoked or suspended membership, or a suspended organization, loses its context immediately', async () => {
    const { h, service, acmeStore, acmeAdmin, danaAcme } = await twoOrganizations();
    const meta = await session(h, acmeStore, danaAcme.id, 'E');
    expect((await service.revalidate(meta)).status).toBe(200);
    expect(await acmeStore.disableMember(danaAcme.id, acmeAdmin.id, new Date(h.clock.now))).toBe(true);
    expect(await service.revalidate(meta)).toMatchObject({ status: 401, cookie: 'clear' });
    const adminMeta = await session(h, acmeStore, acmeAdmin.id, 'F');
    await h.pg.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]);
    expect((await service.revalidate(adminMeta)).status).toBe(401);
    expect(await service.principal(adminMeta)).toBeNull();
  });
  it('cross-organization access is denied at every layer', async () => {
    const { h, service, tsStore, acmeStore, danaTs, acmeAdmin } = await twoOrganizations();
    // Store layer: a store bound to Acme cannot see ThriveSource rows, even by exact id.
    expect(await acmeStore.findMemberById(danaTs.id)).toBeNull();
    expect((await acmeStore.listMembers()).every(m => m.organizationId === ACME)).toBe(true);
    expect(await acmeStore.disableMember(danaTs.id, acmeAdmin.id, new Date(h.clock.now))).toBe(false);
    // A ThriveSource session token never resolves through the Acme store.
    const meta = await session(h, tsStore, danaTs.id, 'D');
    expect(await acmeStore.resolveSession(sha256Hex(meta.sessionToken), new Date(h.clock.now))).toBeNull();
    // Statement layer: an Acme-bound statement with ThriveSource's id is rejected before the database.
    expect(() => assertTenantStatement(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1`, [TS], contextFor(ACME, 'acme'))).toThrow(TenantStatementRejectedError);
    // Authorization layer: an Acme Administrator has no authority over ThriveSource resources.
    const adminMeta = await session(h, acmeStore, acmeAdmin.id, 'G');
    expect(await service.authorize(adminMeta, 'workspace.manage', { organizationId: ACME })).toBe(true);
    for (const organizationId of [TS, GLOBEX, 'acme', undefined, null]) {
      expect(await service.authorize(adminMeta, 'workspace.manage', { organizationId })).toBe(false);
    }
  });
  it('seat usage is visible to organization Administrators only', async () => {
    const { h, service, acmeStore, acmeAdmin, danaAcme } = await twoOrganizations();
    const admin = await session(h, acmeStore, acmeAdmin.id, 'A');
    expect(await service.seats(admin)).toMatchObject({ status: 200, body: { seats: { organizationId: ACME, plan: 'standard', activeMembers: 2, consumed: 2, limit: 5, available: 3, canInvite: true } } });
    const contractor = await session(h, acmeStore, danaAcme.id, 'B');
    expect(await service.seats(contractor)).toMatchObject({ status: 403 });
  });
  it('the existing ThriveSource authentication flow keeps working on an M8 database (regression)', async () => {
    const h = await m8();
    await h.seedMember('admin@t.test', 'workspace_admin');
    const login = await h.login('admin@t.test');
    expect(login.status).toBe(200);
    expect((await h.call('GET', '/api/admin/members', { cookie: login.cookie })).status).toBe(200);
    expect(await one(h, `SELECT organization_id::text AS o FROM auth_sessions`)).toEqual({ o: TS });
  });
});

describe('identity directory and tenant statement policy', () => {
  it('the identity client accepts only the two fixed statements with well-formed parameters', async () => {
    const calls: string[] = [];
    const client = identityScopedSqlClient({ query: async t => { calls.push(t); return { rows: [] }; }, transaction: async () => { throw new Error('x'); } });
    await expect(client.query(LOCATE_SESSION_SQL, ['a'.repeat(64), new Date()])).resolves.toEqual({ rows: [] });
    await expect(client.query(IDENTITY_MEMBERSHIPS_SQL, [ACME])).resolves.toEqual({ rows: [] });
    for (const [text, params] of [
      [`SELECT * FROM workspace_members`, []], [LOCATE_SESSION_SQL + ' ', ['a'.repeat(64), new Date()]], [LOCATE_SESSION_SQL, ['not-a-hash', new Date()]],
      [IDENTITY_MEMBERSHIPS_SQL, ['dana@example.test']], [IDENTITY_MEMBERSHIPS_SQL, [ACME, TS]],
    ] as const) {
      await expect(client.query(text, [...params])).rejects.toBeInstanceOf(Error);
    }
    await expect(client.transaction(async () => 1)).rejects.toBeInstanceOf(IdentityStatementRejectedError);
    expect(calls).toHaveLength(2);
  });
  it('explicit organization INSERTs must bind organization_id to a bare parameter equal to the context', () => {
    const acme = contextFor(ACME, 'acme');
    const ok = `INSERT INTO auth_sessions (token_hash, member_id, organization_id) VALUES ($1, $2, $3)`;
    const allow = { allowOrganizationInsert: true };
    // Off by default: the ThriveSource store keeps the Sprint 2.0B rule that organization_id is never written.
    expect(() => analyzeTenantStatement(ok)).toThrow(/organization_id_assignment/);
    expect(analyzeTenantStatement(ok, allow)).toEqual({ kind: 'organization_insert', tables: ['auth_sessions'], organizationParams: [3] });
    expect(() => assertTenantStatement(ok, ['h', 'm', ACME], acme)).not.toThrow();
    expect(() => assertTenantStatement(ok, ['h', 'm', TS], acme)).toThrow(/organization_parameter/);
    // Never in the ThriveSource context, even with the matching id.
    expect(() => assertTenantStatement(ok, ['h', 'm', TS], contextFor(TS, 'thrivesource'))).toThrow(/organization_id_assignment/);
    for (const bad of [
      `INSERT INTO auth_sessions (token_hash, organization_id) VALUES ($1, '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10')`,
      `INSERT INTO auth_sessions (token_hash, organization_id) VALUES ($1, $2::uuid)`,
      `INSERT INTO auth_sessions (token_hash, organization_id) SELECT $1, $2`,
      `INSERT INTO auth_sessions (token_hash, organization_id, organization_id) VALUES ($1, $2, $3)`,
      `INSERT INTO auth_sessions (token_hash, organization_id) VALUES ($1, $2), ($3, $4)`,
    ]) expect(() => analyzeTenantStatement(bad, allow), bad).toThrow(TenantStatementRejectedError);
  });
  it('M8 and reserved business tables (projects, time records, timesheets, billing) require organization predicates', () => {
    for (const t of ['organization_seat_entitlements', 'projects', 'time_entries', 'timesheets', 'clients', 'invoices', 'billing_rates']) {
      expect(() => analyzeTenantStatement(`SELECT x.id FROM ${t} x WHERE x.id = $1`)).toThrow(/missing_tenant_predicate/);
      expect(analyzeTenantStatement(`SELECT x.id FROM ${t} x WHERE x.organization_id = $1`)).toMatchObject({ kind: 'scoped', organizationParams: [1] });
    }
  });
  it('the ThriveSource store keeps default-derived INSERTs (compatible with the current M7 production grants)', async () => {
    const h = await createHarness({ now: new Date() });
    const admin = await h.seedMember('admin@t.test', 'workspace_admin');
    const seen: string[] = [];
    const spy = { query: (t: string, p?: unknown[]) => { seen.push(t); return h.sql.query(t, p); }, transaction: h.sql.transaction };
    const store = new PostgresAuthStore(statementGuardedSqlClient(spy as typeof h.sql));
    const uid = h.provider.addUser('i@t.test', null);
    const now = new Date(h.clock.now);
    await store.upsertInvitation({ email: 'i@t.test', role: 'contractor', displayName: '', authUserId: uid, invitedBy: admin.id, now, expiresAt: new Date(now.getTime() + DAY) });
    await store.audit({ eventType: 'login', outcome: 'denied' }, now);
    expect(seen.filter(t => /^\s*INSERT/i.test(t)).every(t => !/organization_id/.test(t))).toBe(true);
  });
});

describe('production wiring stays single-organization', () => {
  const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
  const files = (d: string): string[] => readdirSync(fileURLToPath(new URL(d, import.meta.url)), { withFileTypes: true })
    .flatMap(e => e.isDirectory() ? files(`${d}${e.name}/`) : [`${d}${e.name}`]);
  it('only offline tests mint the multi-organization capability', () => {
    const users = [...files('../../server/'), ...files('../../src/'), ...files('../../netlify/')]
      .filter(f => /\.(ts|tsx|mts)$/.test(f) && src(f).includes('mintMultiOrganizationCapabilityForOfflineTests'))
      .map(f => f.replace(/^(\.\.\/)+/, ''));
    expect(users.sort()).toEqual([
      'server/auth/disable-lock-order.rehearsal.test.ts', // Sprint 3.0.3, disposable PostgreSQL only
      'server/auth/m8-invitation-and-lock-pins.test.ts', // Sprint 3.0.5, offline PGlite only
      'server/auth/multi-organization-hardening.test.ts', 'server/auth/multi-organization.rehearsal.test.ts', 'server/auth/multi-organization.test.ts',
      'src/domain/organization.ts', 'src/domain/tenancy.test.ts']);
  });
  it('no HTTP route, function or runtime path uses the multi-organization service or directory', () => {
    for (const f of ['../../netlify/functions/auth-api.mts', './http.ts', './runtime.ts', './service.ts', './config.ts', './store-postgres.ts']) {
      expect(src(f)).not.toMatch(/organization-service|organization-directory|PostgresTenancyStore|store-tenancy|organizationContextForVerifiedMembership/);
    }
    expect(src('./http.ts')).not.toMatch(/\/api\/organizations/);
    expect(readdirSync(fileURLToPath(new URL('../../netlify/functions/', import.meta.url)))).toEqual(['auth-api.mts']);
  });
  it('the production evidence gate still pins exactly M1-M7, so an M8 database is not accepted without a reviewed update', () => {
    expect(MIGRATIONS).toHaveLength(7);
    expect(parseOrganizationId(TS)).toBe(TS);
  });
});
