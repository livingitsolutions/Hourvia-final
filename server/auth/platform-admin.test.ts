// PLATFORM ADMINISTRATION TESTS (Sprint 1.8). Embedded Postgres (PGlite) running all five migrations as the non-superuser
// netlifydb_owner, the real HTTP router and AuthService under the restricted runtime role, and the mocked Supabase provider.
// The application clock starts at real time because the database functions check session expiry with now().
import { beforeEach, describe, expect, it } from 'vitest';
import { authorization, permissions, type Principal } from '../../src/domain/permissions';
import { platformAuthorization, platformPermissions } from '../../src/domain/platform';
import { sha256Hex } from './crypto';
import { PostgresAuthStore } from './store-postgres';
import { GRANT_PLATFORM_SQL, PLATFORM_ADMIN_SQL, PLATFORM_EMAIL, REVOKE_PLATFORM_SQL, createHarness, fillOperatorSql, type Harness } from './testing/harness';

let h: Harness;
beforeEach(async () => { h = await createHarness({ now: new Date() }); });

const one = async <T>(text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows[0]!;
const overview = (cookie: string | null, headers?: Record<string, string>) => h.call('GET', '/api/platform/overview', { cookie, headers });
const audit = (cookie: string | null, query = '', headers?: Record<string, string>) => h.call('GET', `/api/platform/audit${query}`, { cookie, headers });
const platformEvents = async () => (await h.pg.query<{ event_type: string; details: Record<string, unknown> }>(`SELECT event_type, details FROM platform_audit_events ORDER BY id`)).rows;
const deniedAccess = async () => (await h.pg.query<{ actor_member_id: string; details: Record<string, unknown> }>(`SELECT actor_member_id, details FROM auth_audit_events WHERE event_type = 'platform_access' AND outcome = 'denied' ORDER BY id`)).rows;
const revoke = (uid: string, endSessions = 'false') => h.pg.exec(fillOperatorSql(REVOKE_PLATFORM_SQL, { SUPABASE_AUTH_UID: uid, APPROVAL_REF: 'CHG-2026-1105', REASON: 'suspected_compromise', END_SESSIONS: endSessions }));
async function holder() { const s = await h.seedPlatformSuperAdmin(); return { ...s, cookie: (await h.login(s.email)).cookie! }; }
async function member(email: string, role: 'workspace_admin' | 'workspace_manager' | 'contractor') { const m = await h.seedMember(email, role); return { ...m, cookie: (await h.login(m.email)).cookie! }; }

describe('platform permission model (domain)', () => {
  const base: Principal = { id: 'x', name: 'X', role: 'workspace_admin', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false };
  it('is deny-by-default and never derived from the organization role', () => {
    for (const role of ['workspace_admin', 'workspace_manager', 'contractor'] as const) {
      for (const p of platformPermissions) {
        expect(platformAuthorization.can({ ...base, role }, p)).toBe(false);
        expect(platformAuthorization.can({ ...base, role, platformPrivileges: [] }, p)).toBe(false);
        expect(platformAuthorization.can({ ...base, role, platformPrivileges: ['platform_super_admin'] }, p)).toBe(true);
      }
    }
    expect(platformAuthorization.can(null, 'platform.console')).toBe(false);
  });
  it('ignores unknown privileges, unknown permissions, malformed principals and other workspaces', () => {
    const forged = { ...base, platformPrivileges: ['platform_owner', 'super_admin', 'PLATFORM_SUPER_ADMIN', '__proto__'] } as unknown as Principal;
    expect(platformAuthorization.can(forged, 'platform.console')).toBe(false);
    expect(platformAuthorization.can({ ...base, platformPrivileges: 'platform_super_admin' } as unknown as Principal, 'platform.console')).toBe(false);
    expect(platformAuthorization.can({ ...base, platformPrivileges: ['platform_super_admin'] }, 'platform.grant' as never)).toBe(false);
    expect(platformAuthorization.can({ ...base, workspaceId: 'other', platformPrivileges: ['platform_super_admin'] } as unknown as Principal, 'platform.console')).toBe(false);
  });
  it('does not leak into the workspace matrix in either direction', () => {
    for (const p of platformPermissions) expect((permissions as readonly string[]).includes(p)).toBe(false);
    for (const p of platformPermissions) expect(authorization.can({ ...base, platformPrivileges: ['platform_super_admin'] }, p as never, { workspaceId: 'thrivesource' })).toBe(false);
    // The privilege still adds nothing to a Manager's organization data access.
    expect(authorization.can({ ...base, role: 'workspace_manager', platformPrivileges: ['platform_super_admin'] }, 'workspace.manage', { workspaceId: 'thrivesource' })).toBe(false);
  });
});

describe('authorized Platform Super Admin', () => {
  it('reads the overview: own grant, grant history, aggregate ThriveSource counts and audit summary, with no-store', async () => {
    const s = await holder();
    await h.seedMember('m@t.test', 'workspace_manager');
    await h.seedMember('c@t.test', 'contractor');
    await h.seedMember('i@t.test', 'contractor', undefined, { status: 'invited' });
    const res = await overview(s.cookie);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('content-type')).toMatch(/application\/json/);
    const o = res.json!.overview;
    expect(o.grant).toMatchObject({ privilege: 'platform_super_admin', approvalRef: 'CHG-2026-1104' });
    expect(Date.parse(o.grant.grantedAt)).not.toBeNaN();
    expect(Date.parse(o.designatedAt)).not.toBeNaN();
    expect(o.grantHistory).toEqual({ granted: 1, revoked: 0 });
    expect(o.organizations).toEqual([{ id: 'thrivesource', members: { active: 3, invited: 1, disabled: 0 }, activeRoles: { workspace_admin: 1, workspace_manager: 1, contractor: 1 } }]);
    expect(o.audit.events).toBe(2);
    // No identities, UIDs, emails or tokens in the overview.
    expect(res.text).not.toMatch(new RegExp(`${s.authUserId}|m@t.test|c@t.test|token`));
  });

  it('pages the platform audit newest-first with keyset cursors, and audits each read', async () => {
    const s = await holder();
    const first = await audit(s.cookie, '?limit=1');
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('no-store');
    expect(first.json!.events).toHaveLength(1);
    expect(first.json!.events[0]).toMatchObject({ eventType: 'platform_privilege_granted', outcome: 'success', subjectIsHolder: true, subjectSuffix: s.authUserId.slice(-4) });
    expect(first.json!.events[0].details).toMatchObject({ privilege: 'platform_super_admin', approval_ref: 'CHG-2026-1104', source: 'operator_sql' });
    expect(first.json!.hasMore).toBe(true);
    const second = await audit(s.cookie, `?limit=1&before=${first.json!.nextBefore}`);
    expect(second.json!.events.map((e: { eventType: string }) => e.eventType)).toEqual(['platform_designation_set']);
    expect(second.json!.hasMore).toBe(false);
    expect(second.json!.nextBefore).toBeNull();
    // Default page size, and the two reads above are now part of the trail (outside the pages they returned).
    const all = await audit(s.cookie);
    expect(all.json!.events.map((e: { eventType: string }) => e.eventType)).toEqual(['platform_audit_read', 'platform_audit_read', 'platform_privilege_granted', 'platform_designation_set']);
    expect(all.json!.events[0].details).toMatchObject({ source: 'application', limit: 1, returned: 1 });
    expect((await platformEvents()).filter(e => e.event_type === 'platform_audit_read')).toHaveLength(3);
    expect(all.text).not.toContain(s.authUserId);
  });

  it('keeps its existing workspace administration unchanged', async () => {
    const s = await holder();
    expect((await h.call('GET', '/api/admin/members', { cookie: s.cookie })).status).toBe(200);
    expect((await h.call('GET', '/api/auth/session', { cookie: s.cookie })).json!.principal).toMatchObject({ role: 'workspace_admin', platformPrivileges: ['platform_super_admin'] });
  });

  it('validates pagination after authorization', async () => {
    const s = await holder();
    for (const q of ['?limit=0', '?limit=101', '?limit=abc', '?limit=1.5', '?before=0', '?before=-1', '?before=x', '?before=1e3', '?limit=1&limit=2', '?privilege=platform_super_admin', '?before=9999999999999999']) {
      expect((await audit(s.cookie, q)).status, q).toBe(400);
    }
    expect((await audit(s.cookie, '?limit=100')).status).toBe(200);
    const m = await member('m@t.test', 'workspace_manager');
    expect((await audit(m.cookie, '?limit=0')).status).toBe(403); // non-holders learn nothing about validation
  });
});

describe('unauthorized callers', () => {
  it('returns 401 without a session, with a forged or revoked session, and clears a bad cookie', async () => {
    await h.seedPlatformSuperAdmin();
    for (const path of ['/api/platform/overview', '/api/platform/audit']) {
      expect((await h.call('GET', path)).status).toBe(401);
      const forged = await h.call('GET', path, { cookie: 'A'.repeat(43) });
      expect(forged.status).toBe(401);
      expect(forged.setCookie).toMatch(/Max-Age=0/);
    }
    const { cookie } = await h.login(PLATFORM_EMAIL);
    expect((await overview(cookie)).status).toBe(200);
    await h.call('POST', '/api/auth/logout', { cookie });
    expect((await overview(cookie)).status).toBe(401);
  });

  it('returns 403 to Administrators, Managers and Contractors without the privilege, audits the denial, and writes no platform audit', async () => {
    await h.seedPlatformSuperAdmin();
    const before = (await platformEvents()).length;
    for (const [email, role] of [['a@t.test', 'workspace_admin'], ['m@t.test', 'workspace_manager'], ['c@t.test', 'contractor']] as const) {
      const m = await member(email, role);
      for (const res of [await overview(m.cookie), await audit(m.cookie)]) {
        expect(res.status).toBe(403);
        expect(res.json).toMatchObject({ error: 'platform_forbidden' });
        expect(res.headers.get('cache-control')).toBe('no-store');
        expect(res.text).not.toMatch(/platform_super_admin|approval|thrivesource/i);
      }
    }
    expect((await deniedAccess()).map(d => d.details.reason)).toEqual(Array(6).fill('no_platform_privilege'));
    expect((await platformEvents()).length).toBe(before);
  });

  it('cannot forge the privilege through query strings, headers or a lying application layer', async () => {
    await h.seedPlatformSuperAdmin();
    const a = await member('a@t.test', 'workspace_admin');
    const forgedHeaders = { 'x-platform-privileges': 'platform_super_admin', 'x-role': 'platform_super_admin', authorization: 'Bearer platform_super_admin' };
    expect((await overview(a.cookie, forgedHeaders)).status).toBe(403);
    expect((await h.call('GET', '/api/platform/overview?platformPrivileges=platform_super_admin', { cookie: a.cookie })).status).toBe(403);
    // Defence in depth: even if the application wrongly believed a non-holder held the privilege, the database refuses.
    const real = h.deps.store as PostgresAuthStore;
    h.deps.store = new Proxy(real, { get: (t, k) => k === 'platformPrivileges' ? async () => ['platform_super_admin'] : Reflect.get(t, k).bind?.(t) ?? Reflect.get(t, k) });
    expect((await h.call('GET', '/api/auth/session', { cookie: a.cookie })).json!.principal.platformPrivileges).toEqual(['platform_super_admin']);
    for (const res of [await overview(a.cookie), await audit(a.cookie)]) expect(res.status).toBe(403);
    expect((await deniedAccess()).map(d => d.details.reason)).toEqual(['no_platform_privilege', 'no_platform_privilege', 'database_denied', 'database_denied']);
  });

  it('rejects cross-site or foreign-origin reads, every write method, and has no privilege-management routes', async () => {
    const s = await holder();
    expect((await overview(s.cookie, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await overview(s.cookie, { 'sec-fetch-site': 'same-site' })).status).toBe(403);
    expect((await overview(s.cookie, { 'sec-fetch-site': 'none' })).status).toBe(403);
    expect((await overview(s.cookie, { origin: 'https://evil.test' })).status).toBe(403);
    expect((await overview(s.cookie, { 'sec-fetch-site': 'same-origin' })).status).toBe(200);
    expect((await h.call('POST', '/api/platform/overview', { cookie: s.cookie, body: {} })).status).toBe(405);
    expect((await h.call('POST', '/api/platform/audit', { cookie: s.cookie, body: {} })).status).toBe(405);
    for (const path of ['/api/platform/grants', '/api/platform/privileges', '/api/platform/revoke', '/api/platform/impersonate', '/api/platform/organizations', '/api/platform/members']) {
      expect((await h.call('GET', path, { cookie: s.cookie })).status, path).toBe(404);
      expect((await h.call('POST', path, { cookie: s.cookie, body: { privilege: 'platform_super_admin' } })).status, path).toBe(404);
    }
  });
});

describe('revocation and fail-closed membership loss', () => {
  it('denies the very next request after the operator revokes the grant, while the workspace session continues', async () => {
    const s = await holder();
    expect((await overview(s.cookie)).status).toBe(200);
    await revoke(s.authUserId);
    expect((await overview(s.cookie)).status).toBe(403);
    expect((await audit(s.cookie)).status).toBe(403);
    expect((await h.call('GET', '/api/auth/session', { cookie: s.cookie })).status).toBe(200); // END_SESSIONS=false
    // Reinstatement is an operator grant again; access returns only then.
    await h.pg.exec(fillOperatorSql(GRANT_PLATFORM_SQL, { SUPABASE_AUTH_UID: s.authUserId, EXPECTED_MEMBER_ID: s.id, APPROVAL_REF: 'CHG-2026-1106' }));
    expect((await overview(s.cookie)).status).toBe(200);
  });

  it('fails closed (401) when the holder loses the active ThriveSource membership, although the grant row stays active', async () => {
    const s = await holder();
    expect((await overview(s.cookie)).status).toBe(200);
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [s.id]); // operator disable
    expect(await one(`SELECT count(*)::int AS n FROM platform_privileges WHERE revoked_at IS NULL`)).toEqual({ n: 1 });
    expect((await overview(s.cookie)).status).toBe(401);
    expect((await audit(s.cookie)).status).toBe(401);
    expect((await h.login(s.email)).status).not.toBe(200);
  });

  it('expires with the session: an idle-expired session gets 401', async () => {
    const s = await holder();
    h.advance(1801);
    expect((await overview(s.cookie)).status).toBe(401);
  });
});

describe('workspace-role isolation', () => {
  it('a holder who is only a Manager (reachable only via direct owner SQL) gets the platform console but no workspace administration', async () => {
    const lis = await h.seedMember(PLATFORM_EMAIL, 'workspace_manager');
    await h.pg.query(`INSERT INTO platform_super_admin_designation (auth_user_id, approval_ref) VALUES ($1, 'x-123')`, [lis.authUserId]);
    await h.pg.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES ($1, 'platform_super_admin', 'x-123')`, [lis.authUserId]);
    const { cookie } = await h.login(lis.email);
    expect((await overview(cookie)).status).toBe(200); // platform plane: independent of the organization role
    expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(403); // workspace plane: unchanged
  });

  it('ordinary Administrators keep full workspace administration and get no platform access', async () => {
    await h.seedPlatformSuperAdmin();
    const a = await member('a@t.test', 'workspace_admin');
    const c = await h.seedMember('c@t.test', 'contractor');
    expect((await h.call('GET', '/api/admin/members', { cookie: a.cookie })).status).toBe(200);
    expect((await h.call('POST', `/api/admin/members/${c.id}/role`, { cookie: a.cookie, body: { role: 'workspace_manager' } })).status).toBe(200);
    expect((await overview(a.cookie)).status).toBe(403);
  });
});

describe('database boundary for platform reads (20261104150000)', () => {
  it('authorizes inside the database from the session hash, and refuses non-holder, revoked, expired and malformed sessions', async () => {
    const s = await holder();
    const a = await member('a@t.test', 'workspace_admin');
    const call = async (hash: string) => (await h.sql.query<{ o: unknown }>(`SELECT hourvia_platform_overview($1) AS o`, [hash])).rows[0]!.o;
    expect(await call(sha256Hex(s.cookie))).not.toBeNull();
    expect(await call(sha256Hex(a.cookie))).toBeNull();
    expect(await call('not-a-hash')).toBeNull();
    expect(await call(`${sha256Hex(s.cookie).slice(0, 63)}'`)).toBeNull();
    const auditPage = async (hash: string) => (await h.sql.query<{ p: unknown }>(`SELECT hourvia_platform_audit_page($1, NULL, 10) AS p`, [hash])).rows[0]!.p;
    expect(await auditPage(sha256Hex(a.cookie))).toBeNull();
    await expect(h.sql.query(`SELECT hourvia_platform_audit_page($1, NULL, 1000)`, [sha256Hex(s.cookie)])).rejects.toThrow(/between 1 and 100/);
    // Expired in the database's clock even if the application clock disagrees.
    await h.pg.query(`UPDATE auth_sessions SET idle_expires_at = now() - interval '1 second' WHERE token_hash = $1`, [sha256Hex(s.cookie)]);
    expect(await call(sha256Hex(s.cookie))).toBeNull();
    const fresh = (await h.login(s.email)).cookie!;
    expect(await call(sha256Hex(fresh))).not.toBeNull();
    await h.pg.query(`UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'logout', revoked_by_member_id = member_id WHERE token_hash = $1`, [sha256Hex(fresh)]);
    expect(await call(sha256Hex(fresh))).toBeNull();
  });

  it('keeps table privileges unchanged and limits EXECUTE to the runtime role', async () => {
    expect(await one(`SELECT
      has_function_privilege('hourvia_auth_runtime', 'hourvia_platform_overview(text)', 'EXECUTE') AS rt_overview,
      has_function_privilege('hourvia_auth_runtime', 'hourvia_platform_audit_page(text,bigint,integer)', 'EXECUTE') AS rt_audit,
      has_function_privilege('hourvia_auth_runtime', 'hourvia_platform_session_holder(text)', 'EXECUTE') AS rt_holder,
      has_function_privilege('netlifydb_readonly', 'hourvia_platform_overview(text)', 'EXECUTE') AS ro_overview,
      has_function_privilege('netlifydb_readonly', 'hourvia_platform_audit_page(text,bigint,integer)', 'EXECUTE') AS ro_audit,
      has_function_privilege('public', 'hourvia_platform_overview(text)', 'EXECUTE') AS pub,
      has_any_column_privilege('hourvia_auth_runtime', 'platform_audit_events', 'SELECT, INSERT') AS rt_audit_table,
      has_any_column_privilege('hourvia_auth_runtime', 'platform_super_admin_designation', 'SELECT') AS rt_designation,
      has_column_privilege('hourvia_auth_runtime', 'platform_privileges', 'grant_approval_ref', 'SELECT') AS rt_approvals,
      has_table_privilege('hourvia_auth_runtime', 'platform_privileges', 'INSERT, UPDATE, DELETE') AS rt_write`))
      .toEqual({ rt_overview: true, rt_audit: true, rt_holder: false, ro_overview: false, ro_audit: false, pub: false, rt_audit_table: false, rt_designation: false, rt_approvals: false, rt_write: false });
    await expect(h.sql.query(`SELECT * FROM platform_audit_events`)).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`SELECT hourvia_platform_session_holder($1)`, ['a'.repeat(64)])).rejects.toThrow(/permission denied/);
    await expect(h.sql.query(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES (gen_random_uuid(), 'platform_super_admin', 'x-123')`)).rejects.toThrow(/permission denied/);
  });

  it('applies over an existing grant without changing any row, and aborts before 20261104130000', async () => {
    const g = await createHarness({ now: new Date(), platformAdmin: false });
    await g.seedPlatformSuperAdmin();
    const snapshot = async () => (await g.pg.query(`SELECT
      (SELECT json_agg(m ORDER BY m.id) FROM workspace_members m) AS members, (SELECT json_agg(p ORDER BY p.id) FROM platform_privileges p) AS privileges,
      (SELECT json_agg(d) FROM platform_super_admin_designation d) AS designation, (SELECT json_agg(e ORDER BY e.id) FROM platform_audit_events e) AS platform_audit,
      (SELECT json_agg(a ORDER BY a.id) FROM auth_audit_events a) AS audit, (SELECT json_agg(s ORDER BY s.id) FROM auth_sessions s) AS sessions`)).rows[0];
    const before = await snapshot();
    await g.pg.transaction(async tx => { await tx.exec(PLATFORM_ADMIN_SQL); });
    expect(await snapshot()).toEqual(before);

    const early = await createHarness({ correction: false });
    await expect(early.pg.transaction(async tx => { await tx.exec(PLATFORM_ADMIN_SQL); })).rejects.toThrow(/apply 20261104130000 first/);
    expect((await early.pg.query(`SELECT to_regprocedure('hourvia_platform_overview(text)') AS f`)).rows[0]).toEqual({ f: null });
  });
});
