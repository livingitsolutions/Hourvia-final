// PLATFORM SUPER ADMIN TESTS (Sprint 1.8A). Embedded Postgres (PGlite) running all four migrations as the non-superuser
// netlifydb_owner, the real AuthService/HTTP router under the restricted runtime role, and the mocked Supabase provider.
import { PGlite } from '@electric-sql/pglite';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  GRANT_PLATFORM_SQL, PLATFORM_EMAIL, PLATFORM_SQL, REINSTATE_MEMBER_SQL, REVOKE_PLATFORM_SQL, ROLE_SQL, SCHEMA_SQL, SUPER_ADMIN_SQL,
  applyMigration, asNetlifyOwner, createHarness, fillOperatorSql, type Harness,
} from './testing/harness';

let h: Harness;
beforeEach(async () => { h = await createHarness(); });

const one = async <T>(text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows[0]!;
const memberRow = (id: string) => one<{ role: string; status: string; approval_authorized: boolean; role_changed_by: string | null }>(`SELECT role, status, approval_authorized, role_changed_by FROM workspace_members WHERE id = $1`, [id]);
const auditRows = async (eventType: string) => (await h.pg.query<{ outcome: string; actor_member_id: string | null; subject_member_id: string | null; details: Record<string, unknown> }>(
  `SELECT outcome, actor_member_id, subject_member_id, details FROM auth_audit_events WHERE event_type = $1 ORDER BY id`, [eventType])).rows;
const platformAudit = async () => (await h.pg.query<{ event_type: string; subject_auth_user_id: string; details: Record<string, unknown> }>(`SELECT event_type, subject_auth_user_id, details FROM platform_audit_events ORDER BY id`)).rows;
const activeGrants = async () => (await one<{ n: number }>(`SELECT count(*)::int AS n FROM platform_privileges WHERE revoked_at IS NULL`)).n;
const grant = (uid: string, memberId: string, approval = 'CHG-2026-1104') => h.pg.exec(fillOperatorSql(GRANT_PLATFORM_SQL, { SUPABASE_AUTH_UID: uid, EXPECTED_MEMBER_ID: memberId, APPROVAL_REF: approval }));
const revoke = (uid: string, endSessions = 'false', approval = 'CHG-2026-1105') => h.pg.exec(fillOperatorSql(REVOKE_PLATFORM_SQL, { SUPABASE_AUTH_UID: uid, APPROVAL_REF: approval, REASON: 'suspected_compromise', END_SESSIONS: endSessions }));

async function platformSession() { const s = await h.seedPlatformSuperAdmin(); return { ...s, cookie: (await h.login(s.email)).cookie! }; }
async function session(email: string, role: 'workspace_manager' | 'contractor' | 'workspace_admin', extra: { approval?: boolean } = {}) { const m = await h.seedMember(email, role, undefined, extra); return { ...m, cookie: (await h.login(m.email)).cookie! }; }
const setRole = (cookie: string | null, id: string, role: string) => h.call('POST', `/api/admin/members/${id}/role`, { cookie, body: { role } });
const invite = (cookie: string, email: string, role: string) => h.call('POST', '/api/admin/invitations', { cookie, body: { email, role } });
async function accept(email: string, password = 'a brand new passphrase') {
  const tokenHash = h.provider.tokenFor(email, h.provider.inviteTokens)!;
  return h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash, password } });
}

/** Production-like state before Sprint 1.8: the bootstrapped, activated Living IT Solutions Administrator with history. */
async function productionLikeDatabase() {
  const pg = new PGlite();
  await asNetlifyOwner(pg);
  await applyMigration(pg, SCHEMA_SQL);
  await applyMigration(pg, ROLE_SQL);
  const uid = '11111111-2222-4333-8444-555555555555';
  const admin = (await pg.query<{ id: string }>(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status) VALUES ('thrivesource', $1, $2, 'Living IT Solutions', 'workspace_admin', 'invited') RETURNING id`, [uid, PLATFORM_EMAIL])).rows[0]!.id;
  await pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $1, $2, 'workspace_admin', 'pending', NULL, now() + interval '7 days')`, [admin, PLATFORM_EMAIL]);
  await pg.query(`INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, subject_member_id, details) VALUES ('thrivesource', now(), 'admin_bootstrap', 'success', $1, '{"method":"operator_sql"}')`, [admin]);
  await pg.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE member_id = $1`, [admin]);
  await pg.query(`UPDATE workspace_members SET status = 'active', activated_at = now() WHERE id = $1`, [admin]);
  await pg.query(`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, now(), now(), now() + interval '1 hour', now() + interval '2 hour')`, ['a'.repeat(64), admin]);
  await pg.query(`INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id) VALUES ('thrivesource', now(), 'login', 'success', $1, $1)`, [admin]);
  return { pg, uid, admin };
}

describe('forward-only migration sequence', () => {
  it('applies 20261104120000 then 20261104130000 over an active Administrator with bootstrap history, changing no record and promoting nobody', async () => {
    const { pg, admin } = await productionLikeDatabase();
    const snapshot = async () => ({
      members: (await pg.query(`SELECT id, workspace_id, auth_user_id, email, display_name, role, status, approval_authorized, created_at, activated_at, disabled_at, disabled_by FROM workspace_members ORDER BY id`)).rows,
      invitations: (await pg.query(`SELECT * FROM workspace_invitations ORDER BY id`)).rows,
      sessions: (await pg.query(`SELECT id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason FROM auth_sessions ORDER BY id`)).rows,
      audit: (await pg.query(`SELECT * FROM auth_audit_events ORDER BY id`)).rows,
    });
    const before = await snapshot();
    await applyMigration(pg, SUPER_ADMIN_SQL);
    await applyMigration(pg, PLATFORM_SQL);
    expect(await snapshot()).toEqual(before);
    expect((await pg.query(`SELECT role, status FROM workspace_members WHERE id = $1`, [admin])).rows).toEqual([{ role: 'workspace_admin', status: 'active' }]);
    expect((await pg.query(`SELECT (SELECT count(*) FROM platform_privileges)::int AS p, (SELECT count(*) FROM platform_super_admin_designation)::int AS d, (SELECT count(*) FROM platform_audit_events)::int AS a`)).rows[0]).toEqual({ p: 0, d: 0, a: 0 });
  });
  it('aborts (and rolls back) if 20261104120000 was not applied first, or if a withdrawn super_admin row exists', async () => {
    const pg = new PGlite();
    await asNetlifyOwner(pg);
    await applyMigration(pg, SCHEMA_SQL);
    await applyMigration(pg, ROLE_SQL);
    await expect(applyMigration(pg, PLATFORM_SQL)).rejects.toThrow(/apply 20261104120000 first/);
    expect((await pg.query(`SELECT to_regclass('platform_privileges') AS t`)).rows[0]).toEqual({ t: null });

    const { pg: bad, admin } = await productionLikeDatabase();
    await applyMigration(bad, SUPER_ADMIN_SQL);
    await bad.exec(`SET hourvia.super_admin_promotion = 'approved'`);
    await bad.query(`UPDATE workspace_members SET role = 'super_admin' WHERE id = $1`, [admin]); // the withdrawn path
    await bad.exec(`RESET hourvia.super_admin_promotion`);
    await expect(applyMigration(bad, PLATFORM_SQL)).rejects.toThrow(/withdrawn super_admin/);
  });
  it('keeps platform tables hidden from PUBLIC and netlifydb_readonly, and gives the runtime read-only access to active-privilege columns only', async () => {
    expect(await one(`SELECT
      has_column_privilege('hourvia_auth_runtime', 'platform_privileges', 'auth_user_id', 'SELECT') AS can_read,
      has_column_privilege('hourvia_auth_runtime', 'platform_privileges', 'grant_approval_ref', 'SELECT') AS read_approvals,
      has_table_privilege('hourvia_auth_runtime', 'platform_privileges', 'INSERT, UPDATE, DELETE') AS can_write,
      has_any_column_privilege('hourvia_auth_runtime', 'platform_super_admin_designation', 'SELECT, INSERT, UPDATE') AS designation,
      has_any_column_privilege('hourvia_auth_runtime', 'platform_audit_events', 'SELECT, INSERT') AS platform_audit,
      has_any_column_privilege('netlifydb_readonly', 'platform_privileges', 'SELECT') AS readonly,
      has_table_privilege('public', 'platform_privileges', 'SELECT') AS public`))
      .toEqual({ can_read: true, read_approvals: false, can_write: false, designation: false, platform_audit: false, readonly: false, public: false });
    await expect(h.sql.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES (gen_random_uuid(), 'platform_super_admin', 'x-123')`)).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`UPDATE platform_privileges SET revoked_at = now()`)).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`SELECT * FROM platform_audit_events`)).rejects.toThrow(/permission denied/);
  });
});

describe('organization roles no longer include super_admin', () => {
  it('rejects super_admin and platform_super_admin as membership or invitation roles for every role, including the owner', async () => {
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', gen_random_uuid(), $1, 'super_admin', 'invited')`, [PLATFORM_EMAIL])).rejects.toThrow(/role_check/);
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', gen_random_uuid(), 'x@t.test', 'platform_super_admin', 'invited')`)).rejects.toThrow(/role_check/);
    const m = await h.seedMember(PLATFORM_EMAIL, 'workspace_admin');
    await h.pg.exec(`SET hourvia.super_admin_promotion = 'approved'`); // the withdrawn promotion flag no longer opens anything
    await expect(h.pg.query(`UPDATE workspace_members SET role = 'super_admin' WHERE id = $1`, [m.id])).rejects.toThrow(/role_check|only while invited/);
    await h.pg.exec(`RESET hourvia.super_admin_promotion`);
    await expect(h.pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, expires_at) VALUES ('thrivesource', $1, $2, 'super_admin', 'pending', now() + interval '1 day')`, [m.id, PLATFORM_EMAIL])).rejects.toThrow();
  });
});

describe('platform privilege eligibility and operator procedures', () => {
  it('grants only to the verified Living IT Solutions identity and leaves its membership unchanged', async () => {
    const lis = await h.seedMember(PLATFORM_EMAIL, 'workspace_admin');
    const other = await h.seedMember('other.admin@t.test', 'workspace_admin');
    await expect(grant(other.authUserId, other.id)).rejects.toThrow(/do not match/);
    await expect(grant(other.authUserId, lis.id)).rejects.toThrow(/do not match/);
    await expect(grant(lis.authUserId, lis.id, 'bad ref with spaces')).rejects.toThrow(/grant_input/);
    await expect(h.pg.exec(GRANT_PLATFORM_SQL)).rejects.toThrow(/grant_input/); // placeholders not replaced
    // direct owner SQL is held to the same eligibility rules as the procedure
    await expect(h.pg.query(`INSERT INTO platform_super_admin_designation (auth_user_id, approval_ref) VALUES ($1, 'x-123')`, [other.authUserId])).rejects.toThrow(/verified Living IT Solutions/);
    await expect(h.pg.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES ($1, 'platform_super_admin', 'x-123')`, [lis.authUserId])).rejects.toThrow(/designated identity/);
    expect(await activeGrants()).toBe(0);

    const before = await one(`SELECT id, auth_user_id, email, role, status, created_at, activated_at FROM workspace_members WHERE id = $1`, [lis.id]);
    await grant(lis.authUserId, lis.id);
    expect(await one(`SELECT id, auth_user_id, email, role, status, created_at, activated_at FROM workspace_members WHERE id = $1`, [lis.id])).toEqual(before);
    expect(await activeGrants()).toBe(1);
    await grant(lis.authUserId, lis.id); // idempotent
    expect(await activeGrants()).toBe(1);
    expect((await platformAudit()).map(e => e.event_type)).toEqual(['platform_designation_set', 'platform_privilege_granted']);
    expect(await auditRows('membership_role_changed')).toEqual([]); // no membership change at all
  });
  it('refuses an invited, disabled or unactivated Living IT Solutions membership', async () => {
    for (const status of ['invited', 'disabled'] as const) {
      h = await createHarness();
      const m = await h.seedMember(PLATFORM_EMAIL, 'workspace_admin', undefined, { status });
      await expect(grant(m.authUserId, m.id)).rejects.toThrow(/grant_guard/);
      expect(await activeGrants()).toBe(0);
    }
  });
  it('keeps the designation and grant history immutable, allows a single active holder, and supports revoke then reinstate', async () => {
    const s = await platformSession();
    await expect(h.pg.query(`UPDATE platform_super_admin_designation SET approval_ref = 'x-999'`)).rejects.toThrow(/immutable/);
    await expect(h.pg.query(`DELETE FROM platform_super_admin_designation`)).rejects.toThrow(/immutable/);
    await expect(h.pg.query(`DELETE FROM platform_privileges`)).rejects.toThrow(/cannot be deleted/);
    await expect(h.pg.query(`UPDATE platform_privileges SET auth_user_id = gen_random_uuid()`)).rejects.toThrow(/only be revoked/);
    await expect(h.pg.query(`TRUNCATE platform_privileges`)).rejects.toThrow();

    await revoke(s.authUserId, 'true');
    expect(await activeGrants()).toBe(0);
    expect((await h.call('GET', '/api/auth/session', { cookie: s.cookie })).status).toBe(401); // END_SESSIONS=true
    expect(await memberRow(s.id)).toMatchObject({ role: 'workspace_admin', status: 'active' }); // membership untouched
    expect((await auditRows('session_revocation'))[0]).toMatchObject({ actor_member_id: null, subject_member_id: s.id, details: expect.objectContaining({ authority: 'operator', source: 'operator_sql', reason: 'platform_privilege_revoked' }) });
    await revoke(s.authUserId); // idempotent
    await expect(h.pg.query(`UPDATE platform_privileges SET revoked_at = NULL, revoke_approval_ref = NULL, revoked_reason = NULL`)).rejects.toThrow(/only be revoked/);

    const login = await h.login(s.email);
    expect(login.json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: [] });
    await grant(s.authUserId, s.id, 'CHG-2026-1106'); // reinstatement is a fresh, separately approved grant
    expect((await h.call('GET', '/api/auth/session', { cookie: login.cookie })).json!.principal.platformPrivileges).toEqual(['platform_super_admin']);
    expect((await one<{ n: number }>(`SELECT count(*)::int AS n FROM platform_privileges`)).n).toBe(2);
    expect((await platformAudit()).map(e => e.event_type)).toEqual(['platform_designation_set', 'platform_privilege_granted', 'platform_privilege_revoked', 'platform_privilege_granted']);
  });
  it('reinstates a member disabled in error only through the approved procedure, with the same role', async () => {
    const s = await platformSession();
    const c = await h.seedMember('c@t.test', 'contractor');
    expect((await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: s.cookie })).status).toBe(200);
    await expect(h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [c.id])).rejects.toThrow(/cannot be re-enabled/);
    await expect(h.sql.transaction(async tx => { await tx.query(`SELECT set_config('hourvia.member_reinstatement', 'approved', true)`); await tx.query(`UPDATE workspace_members SET status = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = $1`, [c.id]); })).rejects.toThrow(/cannot be re-enabled/);
    await h.pg.exec(fillOperatorSql(REINSTATE_MEMBER_SQL, { EXPECTED_MEMBER_ID: c.id }));
    expect(await memberRow(c.id)).toMatchObject({ role: 'contractor', status: 'active' });
    h.provider.users.get(c.email)!.banned = false; // the separately approved Supabase unban
    expect((await h.login(c.email)).status).toBe(200);
    expect(await auditRows('member_reinstated')).toHaveLength(1);
    await h.pg.exec(fillOperatorSql(REINSTATE_MEMBER_SQL, { EXPECTED_MEMBER_ID: c.id })); // idempotent
    expect(await auditRows('member_reinstated')).toHaveLength(1);
  });
});

describe('platform privilege through the API', () => {
  it('is reported on the principal separately from the organization role and survives in existing sessions', async () => {
    const lis = await h.seedMember(PLATFORM_EMAIL, 'workspace_admin');
    const { cookie } = await h.login(lis.email);
    expect((await h.call('GET', '/api/auth/session', { cookie })).json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: [] });
    await grant(lis.authUserId, lis.id);
    expect((await h.call('GET', '/api/auth/session', { cookie })).json!.principal).toMatchObject({ id: lis.id, role: 'workspace_admin', platformPrivileges: ['platform_super_admin'] });
  });
  it('cannot be requested through invitations or role changes, by anyone', async () => {
    const s = await platformSession();
    const a = await session('admin@t.test', 'workspace_admin');
    const c = await h.seedMember('c@t.test', 'contractor');
    for (const cookie of [s.cookie, a.cookie]) {
      for (const role of ['platform_super_admin', 'super_admin']) {
        expect((await invite(cookie, 'x@t.test', role)).status).toBe(400);
        expect((await setRole(cookie, c.id, role)).status).toBe(400);
      }
      expect((await h.call('POST', '/api/admin/invitations', { cookie, body: { email: 'x@t.test', role: 'contractor', platformPrivileges: ['platform_super_admin'] } })).status).toBe(400);
      expect((await h.call('POST', `/api/admin/members/${c.id}/role`, { cookie, body: { role: 'contractor', platformPrivileges: ['platform_super_admin'] } })).status).toBe(400);
    }
    expect(h.provider.invited).toEqual([]);
    expect(await activeGrants()).toBe(1);
    expect((await auditRows('invitation_created')).every(r => r.details.reason === 'platform_privilege_not_assignable')).toBe(true);
    expect(await auditRows('member_role_changed')).toHaveLength(4);
  });
  it('lets the platform-privileged Administrator invite an Administrator who activates through the normal flow', async () => {
    const s = await platformSession();
    const res = await invite(s.cookie, 'new.admin@t.test', 'workspace_admin');
    expect(res.status).toBe(201); expect(res.json!.member.role).toBe('workspace_admin');
    expect((await accept('new.admin@t.test')).status).toBe(200);
    const login = await h.login('new.admin@t.test', 'a brand new passphrase');
    expect(login.json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: [] }); // no privilege is inherited
    expect((await auditRows('invitation_created'))[0]).toMatchObject({ outcome: 'success', actor_member_id: s.id, details: expect.objectContaining({ role: 'workspace_admin', authority: 'platform_super_admin' }) });
  });
  it('promotes, demotes and revokes Administrators, and the change applies to live sessions immediately', async () => {
    const s = await platformSession();
    const m = await session('m@t.test', 'workspace_manager', { approval: true });
    expect((await setRole(s.cookie, m.id, 'workspace_admin')).status).toBe(200);
    expect(await memberRow(m.id)).toEqual({ role: 'workspace_admin', status: 'active', approval_authorized: false, role_changed_by: s.id });
    expect((await h.call('GET', '/api/admin/members', { cookie: m.cookie })).status).toBe(200);
    h.advance(5);
    expect((await setRole(s.cookie, m.id, 'contractor')).status).toBe(200);
    expect((await h.call('GET', '/api/admin/members', { cookie: m.cookie })).status).toBe(403);
    h.advance(5);
    expect((await setRole(s.cookie, m.id, 'workspace_admin')).status).toBe(200);
    expect((await h.call('POST', `/api/admin/members/${m.id}/revoke-sessions`, { cookie: s.cookie })).json).toEqual({ sessionsRevoked: 1 });
    expect((await h.call('POST', `/api/admin/members/${m.id}/disable`, { cookie: s.cookie })).status).toBe(200);
    expect((await h.login(m.email)).status).toBe(401);
    expect((await auditRows('member_role_changed')).map(c => [c.details.from_role, c.details.to_role, c.details.authority]))
      .toEqual([['workspace_manager', 'workspace_admin', 'platform_super_admin'], ['workspace_admin', 'contractor', 'platform_super_admin'], ['contractor', 'workspace_admin', 'platform_super_admin']]);
  });
  it('loses Administrator authority as soon as the privilege is revoked, without touching the membership', async () => {
    const s = await platformSession();
    const other = await h.seedMember('other.admin@t.test', 'workspace_admin');
    await revoke(s.authUserId);
    expect((await setRole(s.cookie, other.id, 'contractor')).status).toBe(403);
    expect((await invite(s.cookie, 'x@t.test', 'workspace_admin')).status).toBe(403);
    expect((await invite(s.cookie, 'c.new@t.test', 'contractor')).status).toBe(201); // still an ordinary Administrator
  });
  it('cannot change or disable its own membership', async () => {
    const s = await platformSession();
    expect((await setRole(s.cookie, s.id, 'contractor')).status).toBe(403);
    expect((await h.call('POST', `/api/admin/members/${s.id}/disable`, { cookie: s.cookie })).status).toBe(409);
    expect(await memberRow(s.id)).toMatchObject({ role: 'workspace_admin', status: 'active' });
  });
  it('grants no organization authority to a holder who is not an Administrator of that organization', async () => {
    // Defence in depth: even if the identity held the privilege while being only a Manager, it would manage nobody.
    const lis = await h.seedMember(PLATFORM_EMAIL, 'workspace_manager');
    await grant(lis.authUserId, lis.id); // eligibility is identity-based, independent of the organization role
    const { cookie } = await h.login(lis.email);
    expect((await h.call('GET', '/api/auth/session', { cookie })).json!.principal).toMatchObject({ role: 'workspace_manager', platformPrivileges: ['platform_super_admin'] });
    expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(403);
    const c = await h.seedMember('c@t.test', 'contractor');
    expect((await setRole(cookie, c.id, 'workspace_manager')).status).toBe(403);
    await expect(h.sql.query(`UPDATE workspace_members SET role = 'workspace_admin', role_changed_by = $2, role_changed_at = now() WHERE id = $1`, [c.id, lis.id])).rejects.toThrow(/not authorized/);
  });
});

describe('ordinary Administrator limits (preserved from Sprint 1.8)', () => {
  it('manages Managers and Contractors, and clears approval authority when a Manager is moved', async () => {
    const a = await session('admin@thrivesource.test', 'workspace_admin');
    const c = await h.seedMember('c@t.test', 'contractor');
    const m = await h.seedMember('m@t.test', 'workspace_manager', undefined, { approval: true });
    expect((await setRole(a.cookie, c.id, 'workspace_manager')).status).toBe(200);
    expect((await setRole(a.cookie, m.id, 'contractor')).status).toBe(200);
    expect(await memberRow(m.id)).toMatchObject({ role: 'contractor', approval_authorized: false, role_changed_by: a.id });
    expect((await invite(a.cookie, 'new.manager@t.test', 'workspace_manager')).status).toBe(201);
    expect((await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: a.cookie })).status).toBe(200);
  });
  it('cannot create, promote to, modify, demote, revoke or sign out Administrators, including the platform holder', async () => {
    const s = await h.seedPlatformSuperAdmin();
    const a = await session('admin@thrivesource.test', 'workspace_admin');
    const other = await session('other.admin@t.test', 'workspace_admin');
    const m = await h.seedMember('m@t.test', 'workspace_manager');
    const results = [
      (await invite(a.cookie, 'x@t.test', 'workspace_admin')).status,
      (await setRole(a.cookie, m.id, 'workspace_admin')).status,
      (await setRole(a.cookie, other.id, 'contractor')).status,
      (await setRole(a.cookie, a.id, 'contractor')).status,
      (await h.call('POST', `/api/admin/members/${other.id}/disable`, { cookie: a.cookie })).status,
      (await h.call('POST', `/api/admin/members/${other.id}/revoke-sessions`, { cookie: a.cookie })).status,
      (await setRole(a.cookie, s.id, 'contractor')).status,
      (await h.call('POST', `/api/admin/members/${s.id}/disable`, { cookie: a.cookie })).status,
      (await h.call('POST', `/api/admin/members/${s.id}/revoke-sessions`, { cookie: a.cookie })).status,
    ];
    expect(results).toEqual([403, 403, 403, 403, 403, 403, 403, 403, 403]);
    expect(h.provider.invited).toEqual([]); expect(h.provider.banned).toEqual([]);
    expect(await memberRow(m.id)).toMatchObject({ role: 'workspace_manager' });
    expect(await memberRow(other.id)).toMatchObject({ role: 'workspace_admin', status: 'active' });
    expect(await memberRow(s.id)).toMatchObject({ role: 'workspace_admin', status: 'active' });
    expect((await h.call('GET', '/api/auth/session', { cookie: other.cookie })).status).toBe(200);
    const denied = (await h.pg.query<{ reason: string }>(`SELECT details->>'reason' AS reason FROM auth_audit_events WHERE outcome = 'denied' ORDER BY id`)).rows.map(r => r.reason);
    expect(denied).toEqual(['role_not_assignable', 'role_not_assignable', 'member_not_manageable', 'self_change', 'member_not_manageable', 'member_not_manageable', 'member_not_manageable', 'member_not_manageable', 'member_not_manageable']);
  });
  it('cannot use a re-invitation to change a pending Administrator invitation', async () => {
    const s = await platformSession();
    expect((await invite(s.cookie, 'pending.admin@t.test', 'workspace_admin')).status).toBe(201);
    const a = await session('admin@thrivesource.test', 'workspace_admin');
    expect((await invite(a.cookie, 'pending.admin@t.test', 'contractor')).status).toBe(403);
    expect((await one<{ role: string }>(`SELECT role FROM workspace_members WHERE email = 'pending.admin@t.test'`)).role).toBe('workspace_admin');
    h.advance(5);
    expect((await invite(s.cookie, 'pending.admin@t.test', 'workspace_manager')).status).toBe(201);
    expect((await accept('pending.admin@t.test')).status).toBe(200);
    expect((await h.login('pending.admin@t.test', 'a brand new passphrase')).json!.principal.role).toBe('workspace_manager');
  });
  it('is refused by the database even when the runtime SQL names an authorized-looking actor', async () => {
    const a = await h.seedMember('admin@t.test', 'workspace_admin');
    const m = await h.seedMember('m@t.test', 'workspace_manager');
    const esc = (target: string, role: string, actor: string) => h.sql.query(`UPDATE workspace_members SET role = $2, role_changed_by = $3, role_changed_at = now() WHERE id = $1`, [target, role, actor]);
    await expect(esc(m.id, 'workspace_admin', a.id)).rejects.toThrow(/not authorized/);
    await expect(esc(m.id, 'workspace_admin', m.id)).rejects.toThrow(/own role/);
    await expect(h.sql.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now(), disabled_by = $2 WHERE id = $1`, [a.id, m.id])).rejects.toThrow(/disable is not authorized/);
    const inv = (await h.pg.query<{ id: string }>(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, role, status) VALUES ('thrivesource', gen_random_uuid(), 'new@t.test', 'workspace_admin', 'invited') RETURNING id`)).rows[0]!.id;
    await expect(h.sql.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $1, 'new@t.test', 'workspace_admin', 'pending', $2, now() + interval '1 day')`, [inv, a.id])).rejects.toThrow(/inviter is not authorized/);
    await expect(h.sql.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $1, 'new@t.test', 'workspace_admin', 'pending', NULL, now() + interval '1 day')`, [inv])).rejects.toThrow(/must record the inviting member/);
  });
});

describe('session revocation attribution', () => {
  it('records the acting member for logout, password reset, disable and administrative revocation', async () => {
    const a = await session('admin@thrivesource.test', 'workspace_admin');
    const c = await session('c@t.test', 'contractor');
    await h.call('POST', '/api/auth/logout', { cookie: c.cookie });
    const c2 = await h.login(c.email);
    expect((await h.call('POST', `/api/admin/members/${c.id}/revoke-sessions`, { cookie: a.cookie })).json).toEqual({ sessionsRevoked: 1 });
    await h.login(c.email);
    await h.call('POST', '/api/auth/recovery/request', { body: { email: c.email } });
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { email: c.email, code: '482913', password: 'my new long passphrase' } })).status).toBe(200);
    await h.login(c.email, 'my new long passphrase');
    expect((await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: a.cookie })).status).toBe(200);
    expect((await h.call('POST', `/api/admin/members/${a.id}/revoke-sessions`, { cookie: a.cookie })).json).toEqual({ sessionsRevoked: 1 }); // own sessions
    expect(c2.cookie).toBeTruthy();

    const rows = (await h.pg.query<{ reason: string; revoked_by: string }>(`SELECT revoked_reason AS reason, revoked_by_member_id AS revoked_by FROM auth_sessions WHERE revoked_at IS NOT NULL ORDER BY revoked_reason`)).rows;
    expect(rows).toEqual([
      { reason: 'admin_revoked', revoked_by: a.id }, { reason: 'logout', revoked_by: c.id }, { reason: 'member_disabled', revoked_by: a.id },
      { reason: 'password_reset', revoked_by: c.id }, { reason: 'self_revoked', revoked_by: a.id },
    ]);
    expect((await auditRows('session_revocation')).map(r => [r.details.reason, r.actor_member_id, r.subject_member_id, r.details.authority]))
      .toEqual([['logout', c.id, c.id, 'self'], ['admin_revoked', a.id, c.id, 'workspace_admin'], ['password_reset', c.id, c.id, 'self'], ['member_disabled', a.id, c.id, 'workspace_admin'], ['self_revoked', a.id, a.id, 'self']]);
    expect((await auditRows('sessions_revoked')).map(r => r.details.authority)).toEqual(['workspace_admin', 'self']);
  });
  it('refuses unattributed, unauthorized or rewritten revocations from the runtime role', async () => {
    const a = await session('admin@thrivesource.test', 'workspace_admin');
    const other = await session('other.admin@t.test', 'workspace_admin');
    const c = await session('c@t.test', 'contractor');
    await expect(h.sql.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'x' WHERE member_id = $1`, [c.id])).rejects.toThrow(/must record the acting member/);
    await expect(h.sql.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'x', revoked_by_member_id = $2 WHERE member_id = $1`, [a.id, c.id])).rejects.toThrow(/not authorized/);
    await expect(h.sql.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'x', revoked_by_member_id = $2 WHERE member_id = $1`, [other.id, a.id])).rejects.toThrow(/not authorized/);
    await h.call('POST', '/api/auth/logout', { cookie: c.cookie });
    await expect(h.sql.query(`UPDATE auth_sessions SET revoked_by_member_id = $2 WHERE member_id = $1`, [c.id, a.id])).rejects.toThrow(/final/);
    await expect(h.sql.query(`UPDATE auth_sessions SET revoked_by_member_id = $2 WHERE member_id = $1 AND revoked_at IS NULL`, [a.id, a.id])).rejects.toThrow(/revoked_by_requires_revocation/);
    expect((await h.call('GET', '/api/auth/session', { cookie: other.cookie })).status).toBe(200);
  });
});

describe('least privilege and unauthorized requests', () => {
  it('rejects role changes from Managers, Contractors, anonymous and cross-origin callers', async () => {
    const s = await platformSession();
    const m = await session('m@t.test', 'workspace_manager');
    const c = await session('c@t.test', 'contractor');
    expect((await setRole(m.cookie, c.id, 'workspace_manager')).status).toBe(403);
    expect((await setRole(c.cookie, c.id, 'workspace_admin')).status).toBe(403);
    expect((await setRole(null, c.id, 'workspace_admin')).status).toBe(401);
    expect((await h.call('POST', `/api/admin/members/${c.id}/role`, { cookie: s.cookie, body: { role: 'workspace_manager' }, headers: { origin: 'https://evil.test' } })).status).toBe(403);
    expect((await h.call('GET', `/api/admin/members/${c.id}/role`, { cookie: s.cookie })).status).toBe(405);
    expect((await h.call('POST', `/api/admin/members/${c.id}/role`, { cookie: s.cookie, body: { role: 'workspace_manager', workspaceId: 'other' } })).status).toBe(400);
    expect((await h.call('POST', `/api/admin/members/not-a-uuid/role`, { cookie: s.cookie, body: { role: 'contractor' } })).status).toBe(404);
    expect(await memberRow(c.id)).toMatchObject({ role: 'contractor' });
  });
  it('refuses role changes for invited and disabled members', async () => {
    const s = await platformSession();
    const d = await h.seedMember('d@t.test', 'contractor', undefined, { status: 'disabled' });
    const i = await h.seedMember('i@t.test', 'contractor', undefined, { status: 'invited' });
    expect((await setRole(s.cookie, d.id, 'workspace_manager')).status).toBe(409);
    expect((await setRole(s.cookie, i.id, 'workspace_manager')).status).toBe(409);
  });
});

describe('existing bootstrap, login and invitation flows', () => {
  it('the reviewed first-admin bootstrap (invited_by NULL) still activates, and the platform grant then leaves the role unchanged', async () => {
    const userId = h.provider.addUser(PLATFORM_EMAIL, null);
    const member = (await h.pg.query<{ id: string }>(`INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status) VALUES ('thrivesource', $1, $2, 'Living IT Solutions', 'workspace_admin', 'invited') RETURNING id`, [userId, PLATFORM_EMAIL])).rows[0]!.id;
    await h.pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at) VALUES ('thrivesource', $1, $2, 'workspace_admin', 'pending', NULL, now() + interval '7 days')`, [member, PLATFORM_EMAIL]);
    await expect(grant(userId, member)).rejects.toThrow(/grant_guard/); // not yet activated
    h.provider.inviteTokens.set('bootstrap'.padEnd(30, 'b'), PLATFORM_EMAIL);
    expect((await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash: 'bootstrap'.padEnd(30, 'b'), password: 'a brand new passphrase' } })).status).toBe(200);
    expect((await h.login(PLATFORM_EMAIL, 'a brand new passphrase')).json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: [] });
    await grant(userId, member);
    expect((await h.login(PLATFORM_EMAIL, 'a brand new passphrase')).json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: ['platform_super_admin'] });
  });
  it('an activation cannot pick up a role that differs from the accepted invitation', async () => {
    const i = await h.seedMember('i@t.test', 'contractor', undefined, { status: 'invited' });
    await h.pg.query(`INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, expires_at, accepted_at) VALUES ('thrivesource', $1, 'i@t.test', 'contractor', 'accepted', now() + interval '1 day', now())`, [i.id]);
    await h.pg.query(`UPDATE workspace_members SET role = 'workspace_admin' WHERE id = $1`, [i.id]); // owner edit while invited
    await expect(h.sql.query(`UPDATE workspace_members SET status = 'active', activated_at = now() WHERE id = $1`, [i.id])).rejects.toThrow(/accepted invitation for the same role/);
  });
});
