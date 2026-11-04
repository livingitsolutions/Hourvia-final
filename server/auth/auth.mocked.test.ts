// MOCKED PROVIDER TESTS. Supabase Auth is replaced by FakeSupabase; the database is an embedded Postgres
// (PGlite) running the staged proposal SQL verbatim. No network, email, Netlify Database or Supabase project.
import { beforeEach, describe, expect, it } from 'vitest';
import { createHarness, type Harness } from './testing/harness';
import { messages } from './service';
import { sha256Hex } from './crypto';
import { handleAuthRequest } from './http';

let h: Harness;
beforeEach(async () => { h = await createHarness(); });

async function adminSession() { const admin = await h.seedMember('admin@thrivesource.test', 'workspace_admin'); const res = await h.login(admin.email); return { ...admin, cookie: res.cookie! }; }
async function inviteAndAccept(adminCookie: string, email: string, role: 'contractor' | 'workspace_manager', password = 'a brand new passphrase') {
  const invited = await h.call('POST', '/api/admin/invitations', { cookie: adminCookie, body: { email, role } });
  expect(invited.status).toBe(201);
  const tokenHash = h.provider.tokenFor(email.toLowerCase(), h.provider.inviteTokens)!;
  const accepted = await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash, password } });
  expect(accepted.status).toBe(200);
  return { id: invited.json!.member.id as string, password };
}

describe('schema proposal', () => {
  it('applies cleanly and keeps audit events append-only', async () => {
    await h.pg.query(`INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome) VALUES ('thrivesource', now(), 't', 'success')`);
    await expect(h.pg.query(`UPDATE auth_audit_events SET outcome = 'denied'`)).rejects.toThrow(/append-only/);
    await expect(h.pg.query(`DELETE FROM auth_audit_events`)).rejects.toThrow(/append-only/);
    await expect(h.pg.query(`TRUNCATE auth_audit_events`)).rejects.toThrow(/append-only/);
  });
  it('rejects any workspace other than ThriveSource and approval authority for non-managers', async () => {
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('other', 'x@y.z', 'contractor', 'invited')`)).rejects.toThrow();
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status, approval_authorized) VALUES ('thrivesource', 'x@y.z', 'contractor', 'invited', true)`)).rejects.toThrow();
    await expect(h.pg.query(`INSERT INTO workspace_members (workspace_id, email, role, status) VALUES ('thrivesource', 'x@y.z', 'contractor', 'active')`)).rejects.toThrow();
  });
});

describe('invitation-only access', () => {
  it('exposes no self-registration endpoint', async () => {
    expect((await h.call('POST', '/api/auth/signup', { body: { email: 'a@b.c', password: 'x'.repeat(12) } })).status).toBe(404);
    expect((await h.call('POST', '/api/auth/register', { body: {} })).status).toBe(404);
  });
  it('denies a valid Supabase identity that has no workspace membership, with the generic message', async () => {
    h.provider.addUser('stranger@example.test', 'correct horse battery');
    const res = await h.login('stranger@example.test');
    expect(res.status).toBe(401); expect(res.json!.message).toBe(messages.loginFailed); expect(res.cookie).toBeNull();
    expect(h.provider.revoked.length).toBe(1); // the provider session was revoked immediately
  });
  it('lets an admin invite a contractor who sets their own password and then signs in', async () => {
    const admin = await adminSession();
    const { id, password } = await inviteAndAccept(admin.cookie, 'New.Person@ThriveSource.test', 'contractor');
    expect(h.provider.users.get('new.person@thrivesource.test')!.password).toBe(password);
    const login = await h.login('new.person@thrivesource.test', password);
    expect(login.status).toBe(200);
    expect(login.json!.principal).toMatchObject({ id, role: 'contractor', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false });
  });
  it('refuses invitations for the admin and super admin roles, client-supplied workspace IDs and unknown fields', async () => {
    const admin = await adminSession();
    for (const body of [{ email: 'x@t.test', role: 'super_admin' }, { email: 'x@t.test', role: 'contractor', workspaceId: 'other' }, { email: 'x@t.test', role: 'contractor', approvalAuthorized: true }]) {
      expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body })).status).toBe(400);
    }
    // workspace_admin is a valid role, but only the Super Admin may grant it
    expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'x@t.test', role: 'workspace_admin' } })).status).toBe(403);
    expect(h.provider.invited).toEqual([]);
  });
  it('blocks invitations from managers, contractors and anonymous callers', async () => {
    const m = await h.seedMember('m@t.test', 'workspace_manager'); const c = await h.seedMember('c@t.test', 'contractor');
    for (const who of [m, c]) { const s = await h.login(who.email); expect((await h.call('POST', '/api/admin/invitations', { cookie: s.cookie, body: { email: 'x@t.test', role: 'contractor' } })).status).toBe(403); }
    expect((await h.call('POST', '/api/admin/invitations', { body: { email: 'x@t.test', role: 'contractor' } })).status).toBe(401);
    expect(h.provider.invited).toEqual([]);
  });
  it('sends no invitation email unless delivery is explicitly authorized', async () => {
    h = await createHarness({ config: { emailDeliveryAuthorized: false } });
    const admin = await adminSession();
    const res = await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'x@t.test', role: 'contractor' } });
    expect(res.status).toBe(503); expect(res.json!.error).toBe('email_delivery_not_authorized'); expect(h.provider.invited).toEqual([]);
  });
  it('rejects reused, unknown and expired invitation tokens', async () => {
    const admin = await adminSession();
    await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'late@t.test', role: 'contractor' } });
    const tokenHash = h.provider.tokenFor('late@t.test', h.provider.inviteTokens)!;
    expect((await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash: 'f'.repeat(40), password: 'a brand new passphrase' } })).json!.message).toBe(messages.inviteFailed);
    h.advance(8 * 86400);
    const expired = await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash, password: 'a brand new passphrase' } });
    expect(expired.status).toBe(400); expect(h.provider.users.get('late@t.test')!.password).toBeNull();
    // a token for a Supabase identity that Hourvia never invited is refused
    h.provider.addUser('rogue@t.test', null); h.provider.inviteTokens.set('rogue'.padEnd(30, 'z'), 'rogue@t.test');
    expect((await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash: 'rogue'.padEnd(30, 'z'), password: 'a brand new passphrase' } })).status).toBe(400);
  });
  it('cannot accept the same invitation twice or re-invite an active member', async () => {
    const admin = await adminSession();
    await inviteAndAccept(admin.cookie, 'once@t.test', 'contractor');
    expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'once@t.test', role: 'workspace_manager' } })).status).toBe(409);
  });
  it('enforces the password policy on acceptance', async () => {
    const admin = await adminSession();
    await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'pw@t.test', role: 'contractor' } });
    const tokenHash = h.provider.tokenFor('pw@t.test', h.provider.inviteTokens)!;
    expect((await h.call('POST', '/api/auth/invitations/accept', { body: { tokenHash, password: 'short' } })).status).toBe(400);
  });
});

describe('login, logout and session cookies', () => {
  it('issues only an opaque HttpOnly Secure SameSite=Strict host cookie and no provider tokens', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const res = await h.login(c.email);
    expect(res.status).toBe(200);
    expect(res.setCookie).toMatch(/^__Host-hourvia_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200$/);
    expect(res.headers.get('cache-control')).toBe('no-store');
    for (const token of h.provider.issued) { expect(res.text).not.toContain(token); expect(res.setCookie).not.toContain(token); }
    expect(res.text).not.toMatch(/refresh|access_token|accessToken/i);
    expect(h.provider.revoked).toEqual([{ token: h.provider.issued[0], scope: 'local' }]);
    const { rows } = await h.pg.query<{ token_hash: string }>('SELECT token_hash FROM auth_sessions');
    expect(rows).toEqual([{ token_hash: sha256Hex(res.cookie!) }]); // only the hash is stored
  });
  it('gives identical responses for wrong password, unknown email, disabled and invited members', async () => {
    await h.seedMember('c@t.test', 'contractor'); await h.seedMember('d@t.test', 'contractor', 'correct horse battery', { status: 'disabled' });
    const bodies = new Set<string>();
    for (const [email, pw] of [['c@t.test', 'wrong password'], ['nobody@t.test', 'whatever'], ['d@t.test', 'correct horse battery']] as const) {
      const res = await h.login(email, pw); expect(res.status).toBe(401); bodies.add(res.text);
    }
    expect(bodies.size).toBe(1);
  });
  it('logs out by revoking the server session and clearing the cookie', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200);
    const out = await h.call('POST', '/api/auth/logout', { cookie });
    expect(out.status).toBe(204); expect(out.setCookie).toContain('Max-Age=0');
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });
  it('expires idle sessions after 30 minutes', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    h.advance(29 * 60); expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200);
    h.advance(29 * 60); expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200); // activity extended it
    h.advance(31 * 60);
    const expired = await h.call('GET', '/api/auth/session', { cookie });
    expect(expired.status).toBe(401); expect(expired.setCookie).toContain('Max-Age=0');
  });
  it('enforces the 12-hour absolute lifetime even with continuous activity', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    for (let i = 0; i < 35; i++) { h.advance(20 * 60); expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200); }
    h.advance(20 * 60); h.advance(20 * 60);
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });
  it('rate limits sign-in by email and by IP', async () => {
    await h.seedMember('c@t.test', 'contractor');
    for (let i = 0; i < 10; i++) expect((await h.login('c@t.test', 'wrong', `198.51.100.${i}`)).status).toBe(401);
    expect((await h.login('c@t.test', 'correct horse battery', '198.51.100.99')).status).toBe(429);
    for (let i = 0; i < 20; i++) await h.login(`u${i}@t.test`, 'wrong', '192.0.2.1');
    expect((await h.login('other@t.test', 'wrong', '192.0.2.1')).status).toBe(429);
  });
  it('fails closed when the identity provider is down', async () => {
    await h.seedMember('c@t.test', 'contractor'); h.provider.outage = true;
    const res = await h.login('c@t.test'); expect(res.status).toBe(503); expect(res.cookie).toBeNull();
  });
});

describe('forged tokens and CSRF', () => {
  it('rejects forged, malformed, hashed, duplicated and bearer credentials', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    for (const forged of ['A'.repeat(43), 'not-a-token', sha256Hex(cookie!), `${cookie}x`, h.provider.issued[0]!]) {
      expect((await h.call('GET', '/api/auth/session', { cookie: forged })).status).toBe(401);
    }
    expect((await h.call('GET', '/api/auth/session', { headers: { authorization: `Bearer ${h.provider.issued[0]}` } })).status).toBe(401);
    expect((await h.call('GET', '/api/auth/session', { headers: { cookie: `__Host-hourvia_session=${cookie}; __Host-hourvia_session=${'B'.repeat(43)}` } })).status).toBe(401);
  });
  it('rejects cross-origin, cross-site and non-JSON state-changing requests', async () => {
    const admin = await adminSession();
    const body = { email: 'x@t.test', role: 'contractor' };
    expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body, headers: { origin: 'https://evil.test' } })).status).toBe(403);
    expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body, headers: { 'content-type': 'text/plain' } })).status).toBe(403);
    expect((await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body, headers: { 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
    expect(h.provider.invited).toEqual([]);
  });
});

describe('disabled members and revocation', () => {
  it('ends active sessions, blocks sign-in and bans the provider identity when an admin disables a member', async () => {
    const admin = await adminSession();
    const c = await h.seedMember('c@t.test', 'contractor');
    const s1 = await h.login(c.email), s2 = await h.login(c.email);
    const res = await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: admin.cookie });
    expect(res.status).toBe(200); expect(res.json).toMatchObject({ sessionsRevoked: 2, providerBanned: true });
    expect((await h.call('GET', '/api/auth/session', { cookie: s1.cookie })).status).toBe(401);
    expect((await h.call('GET', '/api/auth/session', { cookie: s2.cookie })).status).toBe(401);
    expect(h.provider.banned).toEqual([c.authUserId]);
    h.provider.users.get(c.email)!.banned = false; // even if the provider ban failed, Hourvia denies
    expect((await h.login(c.email)).status).toBe(401);
  });
  it('denies a disabled member immediately even before session revocation', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]);
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });
  it('prevents admins from disabling themselves and validates member IDs', async () => {
    const admin = await adminSession();
    expect((await h.call('POST', `/api/admin/members/${admin.id}/disable`, { cookie: admin.cookie })).status).toBe(409);
    expect((await h.call('POST', `/api/admin/members/not-a-uuid/disable`, { cookie: admin.cookie })).status).toBe(404);
    expect((await h.call('POST', `/api/admin/members/00000000-0000-4000-8000-999999999999/disable`, { cookie: admin.cookie })).status).toBe(404);
  });
  it('lets an admin end all sessions for a member without disabling them', async () => {
    const admin = await adminSession(); const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    expect((await h.call('POST', `/api/admin/members/${c.id}/revoke-sessions`, { cookie: admin.cookie })).json).toEqual({ sessionsRevoked: 1 });
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
    expect((await h.login(c.email)).status).toBe(200);
  });
});

describe('password recovery', () => {
  it('returns the same response for active, unknown and disabled emails and only emails active members', async () => {
    await h.seedMember('c@t.test', 'contractor'); await h.seedMember('d@t.test', 'contractor', 'x'.repeat(12), { status: 'disabled' });
    const bodies = new Set<string>();
    for (const email of ['c@t.test', 'nobody@t.test', 'd@t.test']) { const res = await h.call('POST', '/api/auth/recovery/request', { body: { email } }); expect(res.status).toBe(202); bodies.add(res.text); }
    expect(bodies.size).toBe(1); expect(h.provider.recoverySent).toEqual(['c@t.test']);
    expect(h.sleeps.length).toBe(3); // every request is padded to the minimum duration
  });
  it('resets the password with the 6-digit code and revokes every existing session', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    const { cookie } = await h.login(c.email);
    await h.call('POST', '/api/auth/recovery/request', { body: { email: c.email } });
    const done = await h.call('POST', '/api/auth/recovery/complete', { body: { email: c.email, code: '482913', password: 'my new long passphrase' } });
    expect(done.status).toBe(200);
    expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
    expect((await h.login(c.email)).status).toBe(401);
    expect((await h.login(c.email, 'my new long passphrase')).status).toBe(200);
    expect(h.provider.revoked.at(-2)?.scope).toBe('global');
  });
  it('supports the emailed link (token hash) and rejects reuse', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    await h.call('POST', '/api/auth/recovery/request', { body: { email: c.email } });
    const tokenHash = h.provider.tokenFor(c.email, h.provider.recoveryTokens)!;
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { tokenHash, password: 'my new long passphrase' } })).status).toBe(200);
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { tokenHash, password: 'another long passphrase' } })).json!.message).toBe(messages.recoveryFailed);
  });
  it('limits code guesses per email to five per hour', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    await h.call('POST', '/api/auth/recovery/request', { body: { email: c.email } });
    for (let i = 0; i < 5; i++) expect((await h.call('POST', '/api/auth/recovery/complete', { ip: `198.51.100.${i}`, body: { email: c.email, code: String(100000 + i), password: 'my new long passphrase' } })).status).toBe(400);
    expect((await h.call('POST', '/api/auth/recovery/complete', { ip: '198.51.100.77', body: { email: c.email, code: '482913', password: 'my new long passphrase' } })).status).toBe(429);
  });
  it('limits recovery requests per email', async () => {
    await h.seedMember('c@t.test', 'contractor');
    for (let i = 0; i < 3; i++) expect((await h.call('POST', '/api/auth/recovery/request', { ip: `198.51.100.${i}`, body: { email: 'c@t.test' } })).status).toBe(202);
    expect((await h.call('POST', '/api/auth/recovery/request', { ip: '198.51.100.9', body: { email: 'c@t.test' } })).status).toBe(429);
    expect(h.provider.recoverySent.length).toBe(3);
  });
  it('does not let a disabled member complete a reset with a still-valid code', async () => {
    const c = await h.seedMember('c@t.test', 'contractor');
    await h.call('POST', '/api/auth/recovery/request', { body: { email: c.email } });
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]);
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { email: c.email, code: '482913', password: 'my new long passphrase' } })).status).toBe(400);
    expect(h.provider.users.get(c.email)!.password).toBe('correct horse battery');
  });
  it('sends nothing while email delivery is not authorized, with the same generic response', async () => {
    h = await createHarness({ config: { emailDeliveryAuthorized: false } });
    await h.seedMember('c@t.test', 'contractor');
    const res = await h.call('POST', '/api/auth/recovery/request', { body: { email: 'c@t.test' } });
    expect(res.status).toBe(202); expect(res.json!.message).toBe(messages.recoveryAccepted); expect(h.provider.recoverySent).toEqual([]);
  });
});

describe('server-side RBAC, workspace isolation and cross-user access', () => {
  it('builds principals only from Hourvia membership, never provider data or request input', async () => {
    const m = await h.seedMember('m@t.test', 'workspace_manager', 'correct horse battery', { approval: true });
    const c1 = await h.seedMember('c1@t.test', 'contractor'); const c2 = await h.seedMember('c2@t.test', 'contractor', 'x'.repeat(12), { status: 'disabled' });
    await h.pg.query(`INSERT INTO manager_assignments (workspace_id, manager_member_id, contractor_member_id) VALUES ('thrivesource', $1, $2), ('thrivesource', $1, $3)`, [m.id, c1.id, c2.id]);
    const res = await h.call('POST', '/api/auth/login', { body: { email: m.email, password: m.password } });
    expect(res.json!.principal).toEqual({ id: m.id, name: 'm', role: 'workspace_manager', workspaceId: 'thrivesource', assignedContractorIds: [c1.id], approvalAuthorized: true, platformPrivileges: [] });
    // extra client fields such as a role are rejected outright
    expect((await h.call('POST', '/api/auth/login', { body: { email: m.email, password: m.password, role: 'workspace_admin' } })).status).toBe(400);
  });
  it('keeps each session bound to its own member', async () => {
    const a = await h.seedMember('a@t.test', 'contractor'); const b = await h.seedMember('b@t.test', 'contractor');
    const sa = await h.login(a.email), sb = await h.login(b.email);
    expect((await h.call('GET', '/api/auth/session', { cookie: sa.cookie })).json!.principal.id).toBe(a.id);
    expect((await h.call('GET', '/api/auth/session', { cookie: sb.cookie })).json!.principal.id).toBe(b.id);
    await h.call('POST', '/api/auth/logout', { cookie: sa.cookie });
    expect((await h.call('GET', '/api/auth/session', { cookie: sb.cookie })).status).toBe(200);
  });
  it('restricts member administration to workspace admins', async () => {
    const admin = await adminSession();
    const m = await h.seedMember('m@t.test', 'workspace_manager'); const c = await h.seedMember('c@t.test', 'contractor');
    const sm = await h.login(m.email), sc = await h.login(c.email);
    for (const cookie of [sm.cookie, sc.cookie]) {
      expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(403);
      expect((await h.call('POST', `/api/admin/members/${admin.id}/disable`, { cookie })).status).toBe(403);
      expect((await h.call('POST', `/api/admin/members/${c.id}/revoke-sessions`, { cookie })).status).toBe(403);
    }
    const list = await h.call('GET', '/api/admin/members', { cookie: admin.cookie });
    expect(list.json!.members.map((x: { email: string }) => x.email).sort()).toEqual(['admin@thrivesource.test', 'c@t.test', 'm@t.test']);
    expect(list.text).not.toMatch(/auth_user_id|authUserId|token/);
  });
});

describe('audit trail', () => {
  it('records security events without raw emails or IP addresses', async () => {
    const admin = await adminSession();
    await h.login('nobody@t.test', 'wrong');
    await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'new@t.test', role: 'contractor' } });
    await h.call('POST', '/api/auth/logout', { cookie: admin.cookie });
    const { rows } = await h.pg.query<{ event_type: string; outcome: string }>(`SELECT event_type, outcome FROM auth_audit_events WHERE NOT details ? 'source' ORDER BY id`);
    expect(rows).toEqual([{ event_type: 'login', outcome: 'success' }, { event_type: 'login', outcome: 'denied' }, { event_type: 'invitation_created', outcome: 'success' }, { event_type: 'logout', outcome: 'success' }]);
    // the database itself records every membership row change, attributed to its source
    const db = await h.pg.query<{ event_type: string; source: string }>(`SELECT event_type, details->>'source' AS source FROM auth_audit_events WHERE details ? 'source' ORDER BY id`);
    expect(db.rows).toEqual([{ event_type: 'membership_created', source: 'operator_sql' }, { event_type: 'membership_created', source: 'application' }, { event_type: 'session_revocation', source: 'application' }]);
    const dump = JSON.stringify((await h.pg.query('SELECT * FROM auth_audit_events')).rows);
    expect(dump).not.toMatch(/nobody@t\.test|new@t\.test|203\.0\.113\.10/);
  });
});

describe('fail-closed infrastructure', () => {
  it('returns 503 while the proposal tables are not applied', async () => {
    const bare = await createHarness({ schema: false });
    const res = await bare.call('POST', '/api/auth/login', { body: { email: 'a@t.test', password: 'x' } });
    expect(res.status).toBe(503); expect(res.text).not.toMatch(/relation|does not exist|stack/i);
    expect((await bare.call('GET', '/api/auth/session', { cookie: 'A'.repeat(43) })).status).toBe(503);
  });
});

describe('production smoke-test stage (designated test accounts only)', () => {
  const SMOKE = ['admin@thrivesource.test', 'c.smoke@t.test', 'm.smoke@t.test'];
  beforeEach(async () => { h = await createHarness({ config: { smokeTestEmails: new Set(SMOKE) } }); });

  it('denies a real user before Supabase is contacted, with the generic message', async () => {
    const real = await h.seedMember('real.person@t.test', 'contractor');
    const issuedBefore = h.provider.issued.length;
    const res = await h.login(real.email);
    expect(res.status).toBe(401); expect(res.json!.message).toBe(messages.loginFailed); expect(res.cookie).toBeNull();
    expect(h.provider.issued.length).toBe(issuedBefore);
  });
  it('lets designated test accounts sign in, be invited, activate and recover', async () => {
    const admin = await adminSession();
    expect(admin.cookie).toBeTruthy();
    const { password } = await inviteAndAccept(admin.cookie, 'c.smoke@t.test', 'contractor');
    expect((await h.login('c.smoke@t.test', password)).status).toBe(200);
    expect((await h.call('POST', '/api/auth/recovery/request', { body: { email: 'c.smoke@t.test' } })).status).toBe(202);
    expect(h.provider.recoverySent).toEqual(['c.smoke@t.test']);
  });
  it('refuses to invite, email, disable or end sessions for anyone outside the list', async () => {
    const admin = await adminSession();
    const invite = await h.call('POST', '/api/admin/invitations', { cookie: admin.cookie, body: { email: 'real.invitee@t.test', role: 'contractor' } });
    expect(invite.status).toBe(403); expect(h.provider.invited).toEqual([]);
    const real = await h.seedMember('real.person@t.test', 'contractor');
    const recovery = await h.call('POST', '/api/auth/recovery/request', { body: { email: real.email } });
    expect(recovery.status).toBe(202); expect(recovery.json!.message).toBe(messages.recoveryAccepted); expect(h.provider.recoverySent).toEqual([]);
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { email: real.email, code: '482913', password: 'another long passphrase' } })).status).toBe(400);
    expect((await h.call('POST', `/api/admin/members/${real.id}/disable`, { cookie: admin.cookie, body: {} })).status).toBe(403);
    expect((await h.call('POST', `/api/admin/members/${real.id}/revoke-sessions`, { cookie: admin.cookie, body: {} })).status).toBe(403);
    expect(h.provider.banned).toEqual([]);
    const { rows } = await h.pg.query<{ status: string }>(`SELECT status FROM workspace_members WHERE id = $1`, [real.id]);
    expect(rows[0]!.status).toBe('active');
  });
  it('ends an existing session once its account leaves the list', async () => {
    const c = await h.seedMember('c.smoke@t.test', 'contractor');
    const s = await h.login(c.email);
    expect((await h.call('GET', '/api/auth/session', { cookie: s.cookie })).status).toBe(200);
    (h.deps.config as { smokeTestEmails: ReadonlySet<string> | null }).smokeTestEmails = new Set(['admin@thrivesource.test']);
    expect((await h.call('GET', '/api/auth/session', { cookie: s.cookie })).status).toBe(401);
  });
});

describe('restricted database role (staged 002 proposal, enforced by real Postgres 18 privileges)', () => {
  const asRuntime = (text: string) => h.sql.query(text);
  it('switches every store statement to a non-bypass role and fails closed without it', async () => {
    const { rows } = await h.sql.query<{ u: string; bypass: boolean; superuser: boolean }>(`SELECT current_user AS u, rolbypassrls AS bypass, rolsuper AS superuser FROM pg_roles WHERE rolname = current_user`);
    expect(rows[0]).toEqual({ u: 'hourvia_auth_runtime', bypass: false, superuser: false });
    const noRole = await createHarness({ restrictedRole: false });
    await noRole.seedMember('a@t.test', 'workspace_admin');
    const res = await noRole.login('a@t.test');
    expect(res.status).toBe(503); expect(res.cookie).toBeNull();
  });
  it('cannot read, change or erase the audit trail', async () => {
    await h.login((await h.seedMember('a@t.test', 'workspace_admin')).email);
    await expect(asRuntime(`SELECT * FROM auth_audit_events`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`DELETE FROM auth_audit_events`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`UPDATE auth_audit_events SET outcome = 'success'`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`TRUNCATE auth_audit_events`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`ALTER TABLE auth_audit_events DISABLE TRIGGER ALL`)).rejects.toThrow(/must be owner/);
  });
  it('cannot escalate privileges, rebind identities or change schema', async () => {
    const m = await h.seedMember('m@t.test', 'workspace_manager');
    await expect(asRuntime(`UPDATE workspace_members SET approval_authorized = true`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`UPDATE workspace_members SET auth_user_id = gen_random_uuid()`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`UPDATE workspace_members SET role = 'workspace_admin' WHERE id = '${m.id}'`)).rejects.toThrow(/must record the authorizing member/);
    await expect(asRuntime(`UPDATE workspace_members SET role = 'super_admin', role_changed_by = '${m.id}', role_changed_at = now() WHERE id = '${m.id}'`)).rejects.toThrow(/role_check|own role/);
    await expect(asRuntime(`INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES (gen_random_uuid(), 'platform_super_admin', 'x-123')`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`INSERT INTO manager_assignments (workspace_id, manager_member_id, contractor_member_id) VALUES ('thrivesource', '${m.id}', '${m.id}')`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`DELETE FROM auth_sessions`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`DELETE FROM workspace_members`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`CREATE TABLE stolen (x int)`)).rejects.toThrow(/permission denied/);
    await expect(asRuntime(`DROP TABLE auth_sessions`)).rejects.toThrow(/must be owner/);
    await expect(asRuntime(`CREATE ROLE sneaky`)).rejects.toThrow(/permission denied/);
  });
  it('keeps disabling terminal even for the owner', async () => {
    const c = await h.seedMember('c@t.test', 'contractor', 'correct horse battery', { status: 'disabled' });
    await expect(h.pg.query(`UPDATE workspace_members SET status = 'active' WHERE id = $1`, [c.id])).rejects.toThrow(/cannot be re-enabled/);
  });
});

describe('canonical origin pinning', () => {
  it('refuses auth on any hostname other than the configured app origin', async () => {
    await h.seedMember('a@t.test', 'workspace_admin');
    const other = 'https://hourvia-tracker.netlify.app';
    const res = await handleAuthRequest(new Request(`${other}/api/auth/login`, { method: 'POST', headers: { origin: other, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'a@t.test', password: 'correct horse battery' }) }), '203.0.113.10', async () => h.deps);
    expect(res.status).toBe(421); expect(res.headers.get('set-cookie')).toBeNull();
    expect((await h.login('a@t.test')).status).toBe(200);
  });
});
