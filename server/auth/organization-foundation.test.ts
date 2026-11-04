// SPRINT 2.0B: M7 organization foundation. Disposable embedded PostgreSQL (PGlite) with synthetic data only. No Netlify
// Database, no Supabase, no real identity. Covers migration application, schema integrity, existing-data preservation,
// compatibility with the deployed 799f042 store, tenant-context validation and static tenant predicates.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  OrganizationContextError, SUPPORTED_ORGANIZATION_IDS, THRIVESOURCE_ORGANIZATION_ID, THRIVESOURCE_SYSTEM_CONTEXT, belongsToOrganization,
  isOrganizationId, organizationContextForMembership, parseOrganizationId, type OrganizationContext,
} from '../../src/domain/organization';
import { sha256Hex } from './crypto';
import { SqlStatementRejectedError, statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { analyzeTenantStatement, assertTenantStatement, organizationScopedSqlClient, TenantStatementRejectedError, TENANT_TABLES } from './tenant-sql';
import { LegacyPostgresAuthStore799f042 } from './testing/legacy-store-799f042';
import { ORGANIZATIONS_SQL, PLATFORM_EMAIL, applyMigration, createHarness, type Harness } from './testing/harness';
import type { SqlClient } from './types';

const TS = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6';
const OTHER = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10';
const TABLES = [...TENANT_TABLES];
const rows = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows;
const one = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await rows<T>(h, text, params))[0]!;
const cookieFor = (n: number) => String.fromCharCode(65 + n).repeat(43);

/** A pre-M7 database populated through the exact 799f042 store SQL, the way production data was written. */
async function legacyDatabase() {
  const h = await createHarness({ now: new Date(), organizations: false });
  const legacy = new LegacyPostgresAuthStore799f042(statementGuardedSqlClient(h.sql));
  const now = new Date();
  const later = new Date(now.getTime() + 7 * 86400_000);
  const holder = await h.seedPlatformSuperAdmin();
  const admin = await h.seedMember('admin@thrivesource.test', 'workspace_admin');
  const manager = await h.seedMember('manager@t.test', 'workspace_manager', undefined, { approval: true });
  await h.pg.query(`INSERT INTO manager_assignments (workspace_id, manager_member_id, contractor_member_id, created_by)
    SELECT 'thrivesource', $1, m.id, $2 FROM workspace_members m WHERE false`, [manager.id, admin.id]);
  const invitedId = h.provider.addUser('invitee@t.test', null);
  h.provider.inviteTokens.set(`invite${'z'.repeat(24)}`, 'invitee@t.test'); // the email link the 799f042 invite flow sent
  const invited = await legacy.upsertInvitation({ email: 'invitee@t.test', role: 'contractor', displayName: 'Invitee', authUserId: invitedId, invitedBy: admin.id, now, expiresAt: later });
  const accepterId = h.provider.addUser('accepted@t.test', 'correct horse battery');
  const accepter = await legacy.upsertInvitation({ email: 'accepted@t.test', role: 'contractor', displayName: 'Accepted', authUserId: accepterId, invitedBy: admin.id, now, expiresAt: later });
  expect(await legacy.acceptInvitation(accepter.id, now)).toBe(true);
  await h.pg.query(`INSERT INTO manager_assignments (workspace_id, manager_member_id, contractor_member_id, created_by) VALUES ('thrivesource', $1, $2, $3)`, [manager.id, accepter.id, admin.id]);
  const victim = await h.seedMember('disabled@t.test', 'contractor');
  expect(await legacy.disableMember(victim.id, admin.id, now)).toBe(true);
  const promoted = await h.seedMember('promoted@t.test', 'contractor');
  expect(await legacy.changeMemberRole({ memberId: promoted.id, expectedRole: 'contractor', role: 'workspace_manager', changedBy: admin.id, now })).toBe(true);
  // Live sessions (one per active member), plus one self-revoked and one admin-revoked session.
  const idle = new Date(now.getTime() + 1800_000); const absolute = new Date(now.getTime() + 43200_000);
  const live = [holder, admin, manager, { id: accepter.id }];
  for (const [i, m] of live.entries()) await legacy.createSession({ tokenHash: sha256Hex(cookieFor(i)), memberId: m.id, now, idleExpiresAt: idle, absoluteExpiresAt: absolute });
  await legacy.createSession({ tokenHash: sha256Hex(cookieFor(10)), memberId: admin.id, now, idleExpiresAt: idle, absoluteExpiresAt: absolute });
  await legacy.revokeSession(sha256Hex(cookieFor(10)), 'logout', now);
  await legacy.createSession({ tokenHash: sha256Hex(cookieFor(11)), memberId: promoted.id, now, idleExpiresAt: idle, absoluteExpiresAt: absolute });
  await legacy.revokeMemberSessions(promoted.id, 'admin_revoked', now, admin.id);
  await legacy.audit({ eventType: 'login', outcome: 'success', actorMemberId: admin.id, subjectMemberId: admin.id, emailHmac: 'a'.repeat(64), ipHmac: 'b'.repeat(64), details: { stage: 'general' } }, now);
  await legacy.audit({ eventType: 'login', outcome: 'denied', emailHmac: 'c'.repeat(64), details: {} }, now);
  // A platform audit read by the holder (SECURITY DEFINER path) so platform_audit_events holds application rows too.
  expect(await legacy.platformAuditPage(sha256Hex(cookieFor(0)), { beforeId: null, limit: 5 })).not.toBeNull();
  return { h, legacy, holder, admin, manager, invited, accepter, victim, promoted, cookies: { holder: cookieFor(0), admin: cookieFor(1), manager: cookieFor(2), accepter: cookieFor(3) } };
}

/** Every row of every table, without the new organization_id column, plus the physical row version (xmin, ctid). */
async function snapshot(h: Harness) {
  const out: Record<string, unknown> = {};
  for (const t of [...TABLES, 'auth_rate_limits', 'platform_privileges', 'platform_super_admin_designation', 'platform_audit_events']) {
    out[t] = await rows(h, `SELECT xmin::text AS _xmin, ctid::text AS _ctid, to_jsonb(x) - 'organization_id' AS row FROM ${t} x ORDER BY ctid`);
  }
  return out;
}

async function runtimePrivileges(h: Harness) {
  return {
    tables: await rows(h, `SELECT table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = 'hourvia_auth_runtime' ORDER BY 1, 2`),
    columns: await rows(h, `SELECT table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee = 'hourvia_auth_runtime' ORDER BY 1, 2, 3`),
    functions: await rows(h, `SELECT p.oid::regprocedure::text AS f FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND has_function_privilege('hourvia_auth_runtime', p.oid, 'EXECUTE') AND p.proname LIKE 'hourvia\\_%' ORDER BY 1`),
  };
}

describe('M7 migration file', () => {
  const sql = readFileSync(fileURLToPath(new URL('../../netlify/database/migrations/20261104170000_organizations-expand.sql', import.meta.url)), 'utf8');
  it('records the stable ThriveSource UUID consistently in the migration, the shared constant and the architecture docs', () => {
    expect(THRIVESOURCE_ORGANIZATION_ID).toBe(TS);
    const docs = readFileSync(fileURLToPath(new URL('../../docs/architecture.md', import.meta.url)), 'utf8');
    expect(docs).toContain(TS);
    const uuids = new Set(sql.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g));
    expect([...uuids]).toEqual([TS]);
  });
  it('is additive: no DROP, no RLS, no UPDATE/DELETE/TRUNCATE of existing tables, no role or ownership change', () => {
    // Comments and string literals (exception messages) removed; only executable SQL is scanned.
    const code = sql.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').replace(/'(?:[^']|'')*'/g, "''");
    expect(code).not.toMatch(/\bDROP\s+(?:CONSTRAINT|COLUMN|INDEX|FUNCTION|TRIGGER|POLICY)\b/i);
    expect(code).not.toMatch(/\bDROP TABLE (?!pg_temp\.hourvia_m7_baseline;)/i);
    expect(code).not.toMatch(/ROW LEVEL SECURITY|CREATE POLICY|ALTER ROLE|CREATE ROLE|OWNER TO|SECURITY DEFINER|DISABLE TRIGGER/i);
    expect(code).not.toMatch(/^\s*(?:UPDATE|DELETE FROM|TRUNCATE)\b/im);
    expect(code).not.toMatch(/GRANT\s+(?:INSERT|UPDATE|DELETE|TRUNCATE|ALL)/i);
    expect(code.match(/^GRANT .*$/gm)).toEqual(['GRANT SELECT (id, slug, name, kind, status) ON organizations TO hourvia_auth_runtime;']);
  });
  it('pins every new function search_path with pg_temp last', () => {
    const functions = [...sql.matchAll(/CREATE (?:OR REPLACE )?FUNCTION ([a-z_]+)\([^)]*\)[^$]*?SET search_path = ([^$]+?) AS \$\$/g)];
    expect(functions.map(f => [f[1], f[2]!.trim()])).toEqual([['hourvia_guard_organization', 'pg_catalog, public, pg_temp']]);
    expect(sql.match(/CREATE (?:OR REPLACE )?FUNCTION/g)).toHaveLength(1);
  });
});

describe('M7 application, preconditions and self-checks', () => {
  it('applies as the non-superuser netlifydb_owner and seeds exactly the active internal ThriveSource organization', async () => {
    const h = await createHarness();
    expect(await rows(h, `SELECT id::text, slug, name, kind, status, created_by_auth_user_id, suspended_at, suspended_reason FROM organizations`)).toEqual([
      { id: TS, slug: 'thrivesource', name: 'ThriveSource', kind: 'internal', status: 'active', created_by_auth_user_id: null, suspended_at: null, suspended_reason: null },
    ]);
    expect(await one(h, `SELECT pg_get_userbyid(relowner) AS o FROM pg_class WHERE oid = 'public.organizations'::regclass`)).toEqual({ o: 'netlifydb_owner' });
    expect(await one(h, `SELECT to_regclass('pg_temp.hourvia_m7_baseline') AS t`)).toEqual({ t: null });
  });
  it('refuses to run twice, and rolls back completely', async () => {
    const h = await createHarness();
    await expect(applyMigration(h.pg, ORGANIZATIONS_SQL)).rejects.toThrow(/organizations already exists/);
    expect(await one(h, `SELECT count(*)::int AS n FROM organizations`)).toEqual({ n: 1 });
  });
  it('refuses to run before 20261104160000 (unpinned functions) and leaves nothing behind', async () => {
    const h = await createHarness({ searchPathFix: false });
    await expect(applyMigration(h.pg, ORGANIZATIONS_SQL)).rejects.toThrow(/pinned search_path; apply 20261104160000 first/);
    expect(await one(h, `SELECT to_regclass('public.organizations') AS t, (SELECT count(*)::int FROM pg_attribute WHERE attname = 'organization_id' AND NOT attisdropped) AS c`)).toEqual({ t: null, c: 0 });
  });
  it('refuses on an unexpected hourvia_* function', async () => {
    const h = await createHarness({ organizations: false });
    await h.pg.exec(`CREATE FUNCTION hourvia_unreviewed() RETURNS int LANGUAGE sql SET search_path = pg_catalog, public, pg_temp AS 'SELECT 1'`);
    await expect(applyMigration(h.pg, ORGANIZATIONS_SQL)).rejects.toThrow(/unexpected hourvia_\* functions before M7/);
    expect(await one(h, `SELECT to_regclass('public.organizations') AS t`)).toEqual({ t: null });
  });
  it('the self-check aborts the whole migration on a privilege surprise (runtime pre-granted organization_id writes)', async () => {
    const h = await createHarness({ organizations: false });
    // Simulate drift: a broad default privilege that would hand the runtime role write access to new tables.
    await h.pg.exec(`ALTER DEFAULT PRIVILEGES FOR ROLE netlifydb_owner IN SCHEMA public GRANT INSERT ON TABLES TO PUBLIC`);
    const tampered = ORGANIZATIONS_SQL.replace('REVOKE ALL ON organizations FROM PUBLIC;', '');
    await expect(applyMigration(h.pg, tampered)).rejects.toThrow(/self-check failed: public has access to organizations/);
    expect(await one(h, `SELECT to_regclass('public.organizations') AS t`)).toEqual({ t: null });
  });
});

describe('M7 schema integrity', () => {
  it('adds organization_id NOT NULL with the constant ThriveSource default to exactly the five tenant tables', async () => {
    const h = await createHarness();
    expect(await rows(h, `SELECT table_name, is_nullable, data_type, column_default FROM information_schema.columns
      WHERE table_schema = 'public' AND column_name = 'organization_id' ORDER BY 1`)).toEqual(TABLES.slice().sort().map(t => ({
      table_name: t, is_nullable: 'NO', data_type: 'uuid', column_default: `'${TS}'::uuid`,
    })));
  });
  it('preserves primary keys, the original single-column foreign keys and every single-organization and role constraint', async () => {
    const before = await createHarness({ organizations: false });
    const after = await createHarness();
    const constraints = (h: Harness) => rows(h, `SELECT conrelid::regclass::text AS t, conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
      WHERE connamespace = 'public'::regnamespace AND contype <> 'n' ORDER BY 1, 2`);
    const b = await constraints(before); const a = await constraints(after);
    expect(a).toEqual(expect.arrayContaining(b)); // nothing removed or redefined
    const added = a.filter(x => !b.some(y => JSON.stringify(y) === JSON.stringify(x))).map(x => (x as { conname: string }).conname).sort();
    expect(added).toEqual([
      'auth_audit_events_actor_org_fk', 'auth_audit_events_legacy_organization', 'auth_audit_events_organization_fk', 'auth_audit_events_subject_org_fk',
      'auth_sessions_member_org_fk', 'auth_sessions_organization_fk', 'auth_sessions_revoked_by_org_fk',
      'manager_assignments_contractor_org_fk', 'manager_assignments_created_by_org_fk', 'manager_assignments_legacy_organization', 'manager_assignments_manager_org_fk', 'manager_assignments_organization_fk',
      'organizations_kind_check', 'organizations_name_check', 'organizations_pkey', 'organizations_single_tenant_m7', 'organizations_slug_check', 'organizations_slug_key',
      'organizations_status_check', 'organizations_suspended_after_creation', 'organizations_suspended_reason_check', 'organizations_suspension_metadata', 'organizations_suspension_reason',
      'workspace_invitations_invited_by_org_fk', 'workspace_invitations_legacy_organization', 'workspace_invitations_member_org_fk', 'workspace_invitations_organization_fk',
      'workspace_members_disabled_by_org_fk', 'workspace_members_legacy_organization', 'workspace_members_organization_fk', 'workspace_members_organization_member_key', 'workspace_members_role_changed_by_org_fk',
    ]);
    expect(await rows(after, `SELECT conname FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND NOT convalidated`)).toEqual([]);
    // The single-organization CHECK, the global identity uniqueness and the role vocabulary still reject what they rejected.
    const id = '00000000-0000-4000-8000-00000000aaaa';
    await expect(after.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('other', 'x@t.test', 'contractor', 'invited')`)).rejects.toThrow(/workspace_id_check/);
    await expect(after.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('thrivesource', 'x@t.test', 'owner', 'invited')`)).rejects.toThrow(/role_check/);
    await after.pg.query(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', $1, 'a@t.test', 'contractor', 'invited')`, [id]);
    await expect(after.pg.query(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', $1, 'b@t.test', 'contractor', 'invited')`, [id])).rejects.toThrow(/auth_user_id_key/);
  });
  it('refuses a second organization, even for the owner', async () => {
    const h = await createHarness();
    await expect(h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'Acme', 'customer', 'active')`, [OTHER])).rejects.toThrow(/organizations_single_tenant_m7/);
    await expect(h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'thrivesource', 'X', 'customer', 'active')`, [OTHER])).rejects.toThrow(/organizations_single_tenant_m7|duplicate key/);
  });
  it('organizations are never deleted or truncated and their identity is immutable; suspension metadata must be consistent', async () => {
    const h = await createHarness();
    await expect(h.pg.query(`DELETE FROM organizations`)).rejects.toThrow(/cannot be deleted or truncated/);
    await expect(h.pg.query(`TRUNCATE organizations CASCADE`)).rejects.toThrow(/cannot be deleted or truncated|permission denied/);
    await expect(h.pg.query(`UPDATE organizations SET slug = 'other'`)).rejects.toThrow(/identity columns are immutable/);
    await expect(h.pg.query(`UPDATE organizations SET kind = 'customer'`)).rejects.toThrow(/identity columns are immutable/);
    await expect(h.pg.query(`UPDATE organizations SET status = 'suspended'`)).rejects.toThrow(/organizations_suspension_metadata/);
    await expect(h.pg.query(`UPDATE organizations SET suspended_at = now(), status = 'suspended'`)).rejects.toThrow(/organizations_suspension_reason/);
    expect(await one(h, `SELECT status FROM organizations`)).toEqual({ status: 'active' });
  });
  it('composite foreign keys block cross-organization references even with the single-tenant guards removed (test-only)', async () => {
    const h = await createHarness();
    const a = await h.seedMember('a@t.test', 'workspace_admin');
    await h.pg.exec(`ALTER TABLE organizations DROP CONSTRAINT organizations_single_tenant_m7;
      ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_legacy_organization;
      ALTER TABLE workspace_invitations DROP CONSTRAINT workspace_invitations_legacy_organization;
      ALTER TABLE manager_assignments DROP CONSTRAINT manager_assignments_legacy_organization;
      ALTER TABLE auth_audit_events DROP CONSTRAINT auth_audit_events_legacy_organization;`);
    await h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'Acme', 'customer', 'active')`, [OTHER]);
    const insertB = `INSERT INTO workspace_members (workspace_id, organization_id, email, role, status) VALUES ('thrivesource', $1, 'b@acme.test', 'contractor', 'invited') RETURNING id`;
    // Sprint 2.0C prerequisite, proven here: the unchanged membership audit trigger still writes the ThriveSource default,
    // so a member of another organization fails closed on the composite audit foreign key until 2.0C updates the trigger.
    await expect(h.pg.query(insertB, [OTHER])).rejects.toThrow(/auth_audit_events_subject_org_fk/);
    await h.pg.exec(`ALTER TABLE workspace_members DISABLE TRIGGER workspace_members_audit`);
    const b = (await one<{ id: string }>(h, insertB, [OTHER])).id;
    await h.pg.exec(`ALTER TABLE workspace_members ENABLE TRIGGER workspace_members_audit`);
    const attempts = [
      [`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $1, 'b@acme.test', 'contractor', 'pending', $2, now() + interval '1 day')`, [b, a.id], /member_org_fk/],
      [`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES (repeat('a', 64), $1, now(), now(), now() + interval '1 hour', now() + interval '1 hour')`, [b], /auth_sessions_member_org_fk/],
      [`INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, subject_member_id) VALUES ('thrivesource', now(), 'probe', 'denied', $1)`, [b], /subject_org_fk/],
      [`INSERT INTO manager_assignments (workspace_id, manager_member_id, contractor_member_id) VALUES ('thrivesource', $1, $2)`, [a.id, b], /contractor_org_fk/],
      [`UPDATE workspace_members SET disabled_by = $2 WHERE id = $1`, [a.id, b], /disabled_by_org_fk/],
      [`INSERT INTO workspace_invitations (workspace_id, organization_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $3, $1, 'b@acme.test', 'contractor', 'pending', $2, now() + interval '1 day')`, [b, a.id, OTHER], /invited_by_org_fk/],
    ] as const;
    for (const [text, params, error] of attempts) await expect(h.pg.query(text, [...params])).rejects.toThrow(error);
  });
  it('the legacy bridge keeps workspace and organization in agreement', async () => {
    const h = await createHarness();
    await h.pg.exec(`ALTER TABLE organizations DROP CONSTRAINT organizations_single_tenant_m7`);
    await h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'Acme', 'customer', 'active')`, [OTHER]);
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, organization_id, email, role, status) VALUES ('thrivesource', $1, 'b@acme.test', 'contractor', 'invited')`, [OTHER])).rejects.toThrow(/workspace_members_legacy_organization/);
  });
  it('keeps RLS disabled on every table', async () => {
    const h = await createHarness();
    expect(await rows(h, `SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND (relrowsecurity OR relforcerowsecurity)`)).toEqual([]);
  });
  it('the new guard function is pinned, owner-owned, not SECURITY DEFINER and executable by nobody else', async () => {
    const h = await createHarness();
    expect(await one(h, `SELECT p.proconfig, p.prosecdef, pg_get_userbyid(p.proowner) AS owner, has_function_privilege('public', p.oid, 'EXECUTE') AS pub,
      has_function_privilege('hourvia_auth_runtime', p.oid, 'EXECUTE') AS rt, has_function_privilege('netlifydb_readonly', p.oid, 'EXECUTE') AS ro
      FROM pg_proc p WHERE p.oid = 'public.hourvia_guard_organization()'::regprocedure`)).toEqual({
      proconfig: ['search_path=pg_catalog, public, pg_temp'], prosecdef: false, owner: 'netlifydb_owner', pub: false, rt: false, ro: false,
    });
    expect(await one(h, `SELECT count(*)::int AS n FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'hourvia\\_%'`)).toEqual({ n: 16 });
  });
});

describe('M7 runtime grants and unauthorized organization writes', () => {
  it('adds only SELECT (id, slug, name, kind, status) on organizations; every earlier runtime privilege is identical', async () => {
    const before = await runtimePrivileges(await createHarness({ organizations: false }));
    const after = await runtimePrivileges(await createHarness());
    expect(after.functions).toEqual(before.functions);
    expect(after.tables).toEqual(before.tables); // table-level grants (workspace_members/invitations/sessions SELECT) unchanged
    const added = (after.columns as Record<string, string>[]).filter(c => !(before.columns as Record<string, string>[]).some(b => JSON.stringify(b) === JSON.stringify(c)));
    const removed = (before.columns as Record<string, string>[]).filter(c => !(after.columns as Record<string, string>[]).some(a => JSON.stringify(a) === JSON.stringify(c)));
    expect(removed).toEqual([]);
    // Table-level SELECT grants surface new columns in column_privileges; reads only, never writes.
    expect(added.filter(c => c.table_name !== 'organizations').every(c => c.column_name === 'organization_id' && c.privilege_type === 'SELECT')).toBe(true);
    expect(added.filter(c => c.table_name === 'organizations').map(c => `${c.column_name}:${c.privilege_type}`).sort()).toEqual(['id:SELECT', 'kind:SELECT', 'name:SELECT', 'slug:SELECT', 'status:SELECT']);
  });
  it('the runtime role cannot create, change, delete or read sensitive columns of organizations', async () => {
    const h = await createHarness();
    for (const text of [
      `INSERT INTO organizations (id, slug, name, kind, status) VALUES ('${OTHER}', 'acme', 'Acme', 'customer', 'active')`,
      `UPDATE organizations SET status = 'closed'`, `DELETE FROM organizations`, `TRUNCATE organizations`,
      `SELECT created_by_auth_user_id FROM organizations`, `SELECT suspended_reason FROM organizations`,
    ]) await expect(h.sql.query(text)).rejects.toThrow(/permission denied/);
    expect((await h.sql.query(`SELECT id::text, slug, name, kind, status FROM organizations`)).rows).toEqual([{ id: TS, slug: 'thrivesource', name: 'ThriveSource', kind: 'internal', status: 'active' }]);
  });
  it('the runtime role can never choose or change an organization_id', async () => {
    const h = await createHarness();
    const m = await h.seedMember('a@t.test', 'workspace_admin');
    await expect(h.sql.query(`INSERT INTO workspace_members (workspace_id, organization_id, email, role, status) VALUES ('thrivesource', $1, 'x@t.test', 'contractor', 'invited')`, [TS])).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`INSERT INTO auth_audit_events (workspace_id, organization_id, occurred_at, event_type, outcome) VALUES ('thrivesource', $1, now(), 'x', 'denied')`, [TS])).rejects.toThrow(/permission denied/);
    for (const t of ['workspace_members', 'workspace_invitations', 'auth_sessions']) {
      await expect(h.sql.query(`UPDATE ${t} SET organization_id = $1`, [TS])).rejects.toThrow(/permission denied/);
    }
    await expect(h.sql.query(`UPDATE workspace_members SET organization_id = $1 WHERE id = $2`, [TS, m.id])).rejects.toThrow(/permission denied/);
  });
  it('netlifydb_readonly and PUBLIC have no access to organizations', async () => {
    const h = await createHarness();
    expect(await one(h, `SELECT has_table_privilege('netlifydb_readonly', 'public.organizations', 'SELECT') AS ro, has_any_column_privilege('netlifydb_readonly', 'public.organizations', 'SELECT') AS roc,
      has_table_privilege('public', 'public.organizations', 'SELECT') AS pub`)).toEqual({ ro: false, roc: false, pub: false });
  });
});

describe('M7 preserves existing data', () => {
  it('leaves every existing row of every table byte-identical and physically untouched (same xmin and ctid), and assigns all of them to ThriveSource', async () => {
    const { h } = await legacyDatabase();
    const before = await snapshot(h);
    expect((before.auth_audit_events as unknown[]).length).toBeGreaterThan(5);
    expect((before.platform_audit_events as unknown[]).length).toBeGreaterThan(1);
    expect((before.auth_sessions as unknown[]).length).toBe(6);
    await applyMigration(h.pg, ORGANIZATIONS_SQL);
    expect(await snapshot(h)).toEqual(before);
    for (const t of TABLES) {
      expect(await one(h, `SELECT count(*)::int AS n, count(*) FILTER (WHERE organization_id = $1)::int AS ts FROM ${t}`, [TS]), t)
        .toEqual({ n: (before[t] as unknown[]).length, ts: (before[t] as unknown[]).length });
    }
  });
  it('writes no audit row and fires no row trigger', async () => {
    const { h } = await legacyDatabase();
    const count = async () => one(h, `SELECT (SELECT count(*)::int FROM auth_audit_events) AS a, (SELECT count(*)::int FROM platform_audit_events) AS p, (SELECT max(id)::int FROM auth_audit_events) AS last`);
    const before = await count();
    await applyMigration(h.pg, ORGANIZATIONS_SQL);
    expect(await count()).toEqual(before);
  });
  it('the append-only audit triggers still block UPDATE and DELETE after M7', async () => {
    const { h } = await legacyDatabase();
    await applyMigration(h.pg, ORGANIZATIONS_SQL);
    await expect(h.pg.query(`UPDATE auth_audit_events SET organization_id = organization_id`)).rejects.toThrow(/append-only/);
    await expect(h.pg.query(`DELETE FROM auth_audit_events`)).rejects.toThrow(/append-only/);
    await expect(h.pg.query(`UPDATE platform_audit_events SET details = details`)).rejects.toThrow(/append-only/);
  });
});

describe('compatibility: sessions, invitations, roles and platform administration across M7', () => {
  it('existing sessions stay valid; existing invitations can still be accepted; the platform console still works (current code)', async () => {
    const d = await legacyDatabase();
    await applyMigration(d.h.pg, ORGANIZATIONS_SQL);
    const me = await d.h.call('GET', '/api/auth/session', { cookie: d.cookies.admin });
    expect(me.status).toBe(200); expect(me.json!.principal.role).toBe('workspace_admin');
    expect((await d.h.call('GET', '/api/auth/session', { cookie: d.cookies.manager })).json!.principal.approvalAuthorized).toBe(true);
    expect((await d.h.call('GET', '/api/auth/session', { cookie: d.cookies.accepter })).json!.principal.role).toBe('contractor');
    // Revoked sessions stay revoked.
    expect((await d.h.call('GET', '/api/auth/session', { cookie: cookieFor(10) })).status).toBe(401);
    expect((await d.h.call('GET', '/api/auth/session', { cookie: cookieFor(11) })).status).toBe(401);
    // Pre-M7 pending invitation is accepted through the current API.
    const token = d.h.provider.tokenFor('invitee@t.test', d.h.provider.inviteTokens);
    expect(token).toBeTruthy();
    const accepted = await d.h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash: token, password: 'a much longer password 1' } });
    expect(accepted.status).toBe(200);
    expect(await one(d.h, `SELECT status, organization_id::text AS o FROM workspace_members WHERE id = $1`, [d.invited.id])).toEqual({ status: 'active', o: TS });
    // Platform Super Admin: unchanged authorization and console access.
    const overview = await d.h.call('GET', '/api/platform/overview', { cookie: d.cookies.holder });
    expect(overview.status).toBe(200);
    expect(overview.json!.overview.organizations[0].id).toBe('thrivesource');
    expect((await d.h.call('GET', '/api/platform/audit', { cookie: d.cookies.holder })).status).toBe(200);
    expect((await d.h.call('GET', '/api/platform/overview', { cookie: d.cookies.admin })).status).toBe(403);
  });
  it('role permissions are unchanged: Administrator vs holder vs Manager vs Contractor', async () => {
    const d = await legacyDatabase();
    await applyMigration(d.h.pg, ORGANIZATIONS_SQL);
    const invite = (cookie: string, email: string, role: string) => d.h.call('POST', '/api/admin/invitations', { cookie, body: { email, role, displayName: 'X' } });
    expect((await invite(d.cookies.admin, 'new.manager@t.test', 'workspace_manager')).status).toBe(201);
    expect((await invite(d.cookies.admin, 'new.admin@t.test', 'workspace_admin')).status).toBe(403);
    expect((await invite(d.cookies.holder, 'new.admin@t.test', 'workspace_admin')).status).toBe(201);
    expect((await invite(d.cookies.manager, 'x@t.test', 'contractor')).status).toBe(403);
    expect((await invite(d.cookies.accepter, 'y@t.test', 'contractor')).status).toBe(403);
    expect((await d.h.call('POST', `/api/admin/members/${d.holder.id}/disable`, { cookie: d.cookies.admin, body: {} })).status).toBe(403);
    // New rows written by the current code land in ThriveSource through the column default.
    expect(await rows(d.h, `SELECT DISTINCT organization_id::text AS o FROM workspace_invitations`)).toEqual([{ o: TS }]);
  });
  it('the deployed 799f042 store SQL works unchanged against a database migrated with M7', async () => {
    const d = await legacyDatabase();
    await applyMigration(d.h.pg, ORGANIZATIONS_SQL);
    const legacy = d.legacy;
    const now = new Date();
    const later = new Date(now.getTime() + 86400_000);
    const uid = d.h.provider.addUser('legacy.new@t.test', null);
    const m = await legacy.upsertInvitation({ email: 'legacy.new@t.test', role: 'contractor', displayName: 'L', authUserId: uid, invitedBy: d.admin.id, now, expiresAt: later });
    expect(await legacy.hasPendingInvitation(m.id, now)).toBe(true);
    expect(await legacy.acceptInvitation(m.id, now)).toBe(true);
    await legacy.createSession({ tokenHash: sha256Hex(cookieFor(20)), memberId: m.id, now, idleExpiresAt: later, absoluteExpiresAt: later });
    const s = await legacy.resolveSession(sha256Hex(cookieFor(20)), now);
    expect(s?.member.id).toBe(m.id);
    await legacy.touchSession(s!.sessionId, now, later);
    expect(await legacy.findMemberByEmail('legacy.new@t.test')).toMatchObject({ id: m.id, status: 'active' });
    expect((await legacy.listMembers()).length).toBeGreaterThan(5);
    expect(await legacy.assignedContractorIds(d.manager.id)).toEqual([d.accepter.id]);
    expect(await legacy.changeMemberRole({ memberId: m.id, expectedRole: 'contractor', role: 'workspace_manager', changedBy: d.admin.id, now })).toBe(true);
    expect(await legacy.revokeMemberSessions(m.id, 'admin_revoked', now, d.admin.id)).toBe(1);
    expect(await legacy.disableMember(m.id, d.admin.id, now)).toBe(true);
    await legacy.audit({ eventType: 'login', outcome: 'success', actorMemberId: d.admin.id }, now);
    expect(await legacy.hitRateLimit('login:' + 'f'.repeat(64), now)).toBe(1);
    expect(await legacy.platformPrivileges(d.holder.authUserId)).toEqual(['platform_super_admin']);
    expect(await legacy.platformOverview(sha256Hex(d.cookies.holder))).not.toBeNull();
    expect(await legacy.revokeSession(sha256Hex(d.cookies.admin), 'logout', now)).toBe(d.admin.id);
    for (const t of TABLES) expect(await rows(d.h, `SELECT DISTINCT organization_id::text AS o FROM ${t}`), t).toEqual([{ o: TS }]);
  });
  it('a session created before M7 by the deployed code is accepted by the current code, and one created after M7 by the current code is accepted by the deployed code', async () => {
    const d = await legacyDatabase();
    await applyMigration(d.h.pg, ORGANIZATIONS_SQL);
    const login = await d.h.login(PLATFORM_EMAIL);
    expect(login.status).toBe(200);
    expect((await d.legacy.resolveSession(sha256Hex(login.cookie!), new Date()))?.member.id).toBe(d.holder.id);
  });
});

describe('tenant context validation', () => {
  it('OrganizationId accepts only canonical lower-case UUIDs', () => {
    expect(parseOrganizationId(TS)).toBe(TS);
    for (const bad of [TS.toUpperCase(), ` ${TS}`, `${TS} `, 'thrivesource', '', null, undefined, 42, {}, [TS], TS.replace(/-/g, ''), '00000000-0000-0000-0000-000000000000'])
      expect(parseOrganizationId(bad), String(bad)).toBeNull();
    expect(isOrganizationId(OTHER)).toBe(true);
  });
  it('the supported organizations are exactly ThriveSource in Sprint 2.0B', () => {
    expect(SUPPORTED_ORGANIZATION_IDS).toEqual([TS]);
    expect(THRIVESOURCE_SYSTEM_CONTEXT).toMatchObject({ organizationId: TS, legacyWorkspaceId: 'thrivesource', source: 'system' });
    expect(Object.isFrozen(THRIVESOURCE_SYSTEM_CONTEXT)).toBe(true);
  });
  it('a membership context fails closed for an unsupported, malformed or mismatched organization', () => {
    expect(organizationContextForMembership({ organizationId: TS, workspaceId: 'thrivesource' })).toMatchObject({ organizationId: TS, source: 'membership' });
    expect(() => organizationContextForMembership({ organizationId: OTHER, workspaceId: 'thrivesource' })).toThrow(OrganizationContextError);
    expect(() => organizationContextForMembership({ organizationId: OTHER, workspaceId: 'thrivesource' })).toThrow(/unsupported_organization/);
    expect(() => organizationContextForMembership({ organizationId: 'thrivesource', workspaceId: 'thrivesource' })).toThrow(/invalid_organization/);
    expect(() => organizationContextForMembership({ organizationId: TS, workspaceId: 'acme' })).toThrow(/workspace_mismatch/);
    expect(() => organizationContextForMembership({ organizationId: undefined, workspaceId: 'thrivesource' })).toThrow(/invalid_organization/);
  });
  it('belongsToOrganization compares only validated identifiers', () => {
    expect(belongsToOrganization(THRIVESOURCE_SYSTEM_CONTEXT, TS)).toBe(true);
    expect(belongsToOrganization(THRIVESOURCE_SYSTEM_CONTEXT, TS.toUpperCase())).toBe(false);
    expect(belongsToOrganization(THRIVESOURCE_SYSTEM_CONTEXT, OTHER)).toBe(false);
    expect(belongsToOrganization(THRIVESOURCE_SYSTEM_CONTEXT, undefined)).toBe(false);
  });
  it('the service rejects a session whose membership is outside the store context (fail closed, 401)', async () => {
    const h = await createHarness();
    const admin = await h.seedMember('a@t.test', 'workspace_admin');
    const cookie = (await h.login(admin.email)).cookie!;
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200);
    const store = h.deps.store as PostgresAuthStore;
    const real = store.resolveSession.bind(store);
    store.resolveSession = async (hash, now) => { const s = await real(hash, now); return s && { ...s, member: { ...s.member, organizationId: OTHER as typeof s.member.organizationId } }; };
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });
  it('the database refuses to resolve a session whose organization is not active (owner-side suspension, test-only)', async () => {
    const h = await createHarness();
    const admin = await h.seedMember('a@t.test', 'workspace_admin');
    const cookie = (await h.login(admin.email)).cookie!;
    await h.pg.query(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'test_only'`);
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });
  it('store.organization() returns the context organization through the runtime role', async () => {
    const h = await createHarness();
    expect(await (h.deps.store as PostgresAuthStore).organization()).toEqual({ id: TS, slug: 'thrivesource', name: 'ThriveSource', kind: 'internal', status: 'active' });
  });
});

describe('static tenant predicates', () => {
  async function issuedStatements() {
    const issued: { text: string; params: unknown[] }[] = [];
    const recorder: SqlClient = {
      query: async <T>(text: string, params: unknown[] = []) => { issued.push({ text, params }); return { rows: [{ id: TS, organization_id: TS, hits: 1, o: null, p: null } as T] }; },
      transaction: async fn => fn(recorder),
    };
    const store = new PostgresAuthStore(statementGuardedSqlClient(recorder));
    const v = 'value';
    const now = new Date();
    await store.organization();
    await store.findMemberById(v); await store.findMemberByEmail(v); await store.findMemberByAuthUserId(v);
    await store.listMembers(); await store.assignedContractorIds(v); await store.platformPrivileges(v);
    await store.platformOverview(v); await store.platformAuditPage(v, { beforeId: null, limit: 10 });
    await store.upsertInvitation({ email: v, role: 'contractor', displayName: v, authUserId: v, invitedBy: v, now, expiresAt: now });
    await store.hasPendingInvitation(v, now); await store.acceptInvitation(v, now); await store.disableMember(v, v, now);
    await store.changeMemberRole({ memberId: v, expectedRole: 'contractor', role: 'workspace_manager', changedBy: v, now });
    await store.createSession({ tokenHash: v, memberId: v, now, idleExpiresAt: now, absoluteExpiresAt: now });
    await store.resolveSession(v, now); await store.touchSession(v, now, now);
    await store.revokeSession(v, v, now); await store.revokeMemberSessions(v, v, now, v);
    await store.hitRateLimit(v, now); await store.audit({ eventType: v, outcome: 'denied' }, now);
    return issued;
  }

  it('every statement the store issues is tenant-scoped (bound to the context organization), a default-derived insert, or global', async () => {
    const issued = await issuedStatements();
    expect(issued.length).toBeGreaterThanOrEqual(25);
    const kinds: Record<string, number> = { global: 0, scoped: 0, default_insert: 0 };
    for (const { text, params } of issued) {
      const a = assertTenantStatement(text, params, THRIVESOURCE_SYSTEM_CONTEXT);
      kinds[a.kind]!++;
      if (a.kind === 'scoped') {
        expect(a.organizationParams.length, text).toBeGreaterThan(0);
        for (const p of a.organizationParams) expect(params[p - 1]).toBe(TS);
      }
      if (a.kind === 'global') expect(text).not.toMatch(new RegExp(`\\b(?:${TABLES.join('|')}|organizations)\\b`));
    }
    expect(kinds.default_insert).toBe(4); // member upsert, invitation, session, audit
    expect(kinds.global).toBe(4); // platform privileges, overview, audit page, rate limit
    expect(kinds.scoped).toBe(issued.length - 8);
  });
  it('every tenant table the store touches is covered, and resolveSession scopes session, member and organization', async () => {
    const issued = await issuedStatements();
    const tables = new Set(issued.flatMap(({ text }) => analyzeTenantStatement(text).tables));
    expect([...tables].sort()).toEqual(['auth_audit_events', 'auth_sessions', 'manager_assignments', 'organizations', 'workspace_invitations', 'workspace_members']);
    const resolve = issued.find(({ text }) => /FROM auth_sessions s JOIN workspace_members m/.test(text))!;
    expect(analyzeTenantStatement(resolve.text)).toMatchObject({ kind: 'scoped', tables: ['auth_sessions', 'workspace_members', 'organizations'], organizationParams: [4] });
  });
  it('rejects statements that would cross or escape the organization boundary', () => {
    const reject = (text: string, reason: RegExp, params: unknown[] = [TS, TS, TS]) =>
      expect(() => assertTenantStatement(text, params, THRIVESOURCE_SYSTEM_CONTEXT), text).toThrow(reason);
    reject(`SELECT m.id FROM workspace_members m WHERE m.id = $1`, /missing_tenant_predicate:workspace_members/);
    reject(`SELECT m.id FROM workspace_members m`, /missing_tenant_predicate/);
    reject(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1 OR m.id = $2`, /disjunction/);
    reject(`SELECT s.id FROM auth_sessions s JOIN workspace_members m ON m.id = s.member_id WHERE m.organization_id = $1`, /missing_tenant_predicate:auth_sessions/);
    reject(`SELECT m.organization_id = $1 FROM workspace_members m WHERE m.id = $2`, /missing_tenant_predicate/);
    reject(`SELECT m.id FROM public.workspace_members m WHERE m.organization_id = $1`, /qualified_tenant_reference/);
    reject(`UPDATE auth_sessions SET organization_id = $1 WHERE organization_id = $1`, /organization_id_assignment/);
    reject(`INSERT INTO auth_sessions (token_hash, organization_id) VALUES ($1, $2)`, /organization_id_assignment/);
    reject(`INSERT INTO workspace_members AS m (email) VALUES ($1) ON CONFLICT (workspace_id, email) DO UPDATE SET organization_id = $1 RETURNING m.id`, /organization_id_assignment/);
    reject(`INSERT INTO organizations (id, slug) VALUES ($1, $2)`, /organization_write/);
    reject(`UPDATE organizations SET status = $2 WHERE id = $1`, /organization_write/);
    reject(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1 AND m.id IN (SELECT i.member_id FROM workspace_invitations i)`, /missing_tenant_predicate:workspace_invitations/);
    reject(`SELECT x.id FROM (SELECT id FROM workspace_members) x WHERE x.organization_id = $1`, /missing_tenant_predicate|unrecognized/);
    reject(`SELECT 1 FROM workspace_members, workspace_invitations WHERE organization_id = $1`, /missing_tenant_predicate|unrecognized/);
    // A correct predicate bound to another organization (or to input) is refused at run time.
    reject(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1`, /organization_parameter/, [OTHER]);
    reject(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $2`, /organization_parameter/, [TS, 'thrivesource']);
    reject(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1`, /organization_parameter/, []);
  });
  it('accepts the scoped shapes, and keeps every rule of the existing statement policy (never weakened)', () => {
    expect(analyzeTenantStatement(`SELECT 1 FROM auth_rate_limits WHERE bucket = $1`).kind).toBe('global');
    expect(analyzeTenantStatement(`UPDATE auth_sessions SET last_seen_at = $2 WHERE id = $1 AND organization_id = $3`)).toMatchObject({ kind: 'scoped', organizationParams: [3] });
    for (const [text, reason] of [
      [`RESET ROLE`, /statement_kind/], [`SELECT 1; RESET ROLE`, /multiple_statements/], [`SELECT set_config('role', 'x', true)`, /set_config/],
      [`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1 -- x`, /comment/], [`SELECT "set_config"($1)`, /quoted_identifier/],
      [`DELETE FROM workspace_members WHERE organization_id = $1`, /statement_kind/], [`WITH x AS (SELECT 1) SELECT 1`, /statement_kind/],
    ] as const) expect(() => analyzeTenantStatement(text)).toThrow(SqlStatementRejectedError), expect(() => analyzeTenantStatement(text)).toThrow(reason);
  });
  it('a default-derived INSERT is refused outside the ThriveSource context', () => {
    const foreign = Object.freeze({ organizationId: OTHER, legacyWorkspaceId: 'thrivesource', source: 'membership' }) as unknown as OrganizationContext;
    expect(() => assertTenantStatement(`INSERT INTO auth_sessions (token_hash) VALUES ($1)`, ['x'], foreign)).toThrow(/default_organization_insert/);
    expect(() => assertTenantStatement(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1`, [TS], foreign)).toThrow(/organization_parameter/);
  });
  it('the scoped client rejects before the database is contacted, inside transactions too', async () => {
    let reached = 0;
    const inner: SqlClient = { query: async () => { reached++; return { rows: [] }; }, transaction: async fn => fn(inner) };
    const client = organizationScopedSqlClient(inner, THRIVESOURCE_SYSTEM_CONTEXT);
    await expect(client.query(`SELECT m.id FROM workspace_members m WHERE m.id = $1`, ['x'])).rejects.toThrow(TenantStatementRejectedError);
    await expect(client.transaction(tx => tx.query(`UPDATE auth_sessions SET revoked_at = $1`, [new Date()]))).rejects.toThrow(TenantStatementRejectedError);
    expect(reached).toBe(0);
    await client.query(`SELECT m.id FROM workspace_members m WHERE m.organization_id = $1`, [TS]);
    expect(reached).toBe(1);
  });
  it('source scan: the store is always constructed over the scoped client, and runtime retains role and statement guards', () => {
    const src = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    expect(src('./store-postgres.ts')).toMatch(/this\.sql = organizationScopedSqlClient\(sql, context\);/);
    expect(src('./store-postgres.ts').match(/this\.sql\s*=/g)).toHaveLength(1);
    expect(src('./runtime.ts')).toMatch(/new PostgresAuthStore\(statementGuardedSqlClient\(roleScopedSqlClient\(poolSqlClient\(pool\)\)\)\)/);
    // No organization identifier is ever read from a request.
    expect(src('./http.ts')).not.toMatch(/organization/i);
    // Both service organization references compare the membership row with the store's server-side context.
    expect(src('./service.ts').match(/organizationId/g)).toEqual(['organizationId', 'organizationId']);
    expect(src('./service.ts')).toMatch(/belongsToOrganization\(this\.deps\.store\.context, member\.organizationId\)/);
  });
});

describe('read-only preview verification script', () => {
  it('every check in db/verification/sprint-2.0b-preview-readonly.sql passes on a migrated database', async () => {
    const h = await createHarness();
    const script = readFileSync(fileURLToPath(new URL('../../db/verification/sprint-2.0b-preview-readonly.sql', import.meta.url)), 'utf8');
    const statements = script.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').split(';').map(x => x.trim()).filter(x => x.startsWith('SELECT'));
    expect(statements).toHaveLength(8);
    for (const text of statements) {
      const result = await one<{ check: string; ok: boolean }>(h, text);
      expect(result.ok, result.check).toBe(true);
    }
    const executable = script.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').replace(/'(?:[^']|'')*'/g, "''");
    expect(executable).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|GRANT|REVOKE|CREATE|TRUNCATE|SET)\b/);
    expect(executable).toMatch(/^BEGIN TRANSACTION READ ONLY;/m); expect(executable.trim()).toMatch(/ROLLBACK;$/);
  });
});

describe('architecture record', () => {
  it('the M7 file is pinned (it will be applied to the preview database branch and must stay byte-identical afterwards)', () => {
    const bytes = readFileSync(fileURLToPath(new URL('../../netlify/database/migrations/20261104170000_organizations-expand.sql', import.meta.url)));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(M7_SHA256);
  });
});
const M7_SHA256 = '9f483233ba7dc2e762ae50890e029478b2d57a4c618e7cc4e3f76e7bfc502576';
