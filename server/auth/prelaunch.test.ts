import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHarness, type Harness } from './testing/harness';
import type { IdentityPolicy } from './synthetic-policy';
let h: Harness;
afterEach(async () => { await h?.pg.close(); });
async function setup() {
  h = await createHarness();
  const synthetic = await h.seedMember('synthetic@example.test', 'workspace_admin');
  const protectedMember = await h.seedMember('protected@example.test', 'contractor');
  const policy: IdentityPolicy = {
    identities: [{ email: synthetic.email, memberId: synthetic.id, authUserId: synthetic.authUserId }],
    protectedEmails: [protectedMember.email], protectedMemberIds: [protectedMember.id], protectedAuthUserIds: [protectedMember.authUserId],
  };
  h.config.prelaunch = policy;
  h.config.smokeTestEmails = new Set([synthetic.email]);
  return { synthetic, protectedMember, policy };
}
function spies() {
  return Object.fromEntries((['signInWithPassword', 'verifyEmailOtp', 'revokeSession', 'inviteUser', 'sendRecovery', 'setPassword', 'banUser'] as const).map(k => [k, vi.spyOn(h.provider, k)]));
}
describe('strict pre-launch provider preauthorization', () => {
  it('blocks unapproved, protected and mismatched memberships without provider contact', async () => {
    const { synthetic, protectedMember, policy } = await setup(); const s = spies();
    expect((await h.login(protectedMember.email)).status).toBe(401);
    expect((await h.login('unknown@example.test')).status).toBe(401);
    policy.identities[0]!.authUserId = protectedMember.authUserId;
    expect((await h.login(synthetic.email)).status).toBe(401);
    for (const spy of Object.values(s)) expect(spy).not.toHaveBeenCalled();
  });
  it('refuses a provider identity mismatch before revocation, session creation or password changes', async () => {
    const { synthetic, protectedMember } = await setup();
    const revoke = vi.spyOn(h.provider, 'revokeSession');
    vi.spyOn(h.provider, 'signInWithPassword').mockResolvedValue({ userId: protectedMember.authUserId, accessToken: 'offline-fixture' });
    const login = await h.login(synthetic.email); expect(login.status).toBe(401); expect(login.cookie).toBeNull(); expect(revoke).not.toHaveBeenCalled();
    const password = vi.spyOn(h.provider, 'setPassword');
    vi.spyOn(h.provider, 'verifyEmailOtp').mockResolvedValue({ userId: protectedMember.authUserId, accessToken: 'offline-fixture' });
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { email: synthetic.email, code: '123456', password: 'replacement password' } })).status).toBe(400);
    expect(password).not.toHaveBeenCalled(); expect(revoke).not.toHaveBeenCalled();
  });
  it('blocks every opaque invitation/recovery token before verification, even for approved users', async () => {
    await setup(); const verify = vi.spyOn(h.provider, 'verifyEmailOtp');
    for (const path of ['/api/auth/invitations/accept', '/api/auth/recovery/complete']) {
      expect((await h.call('POST', path, { body: { tokenHash: 'a'.repeat(56), password: 'replacement password' } })).status).toBe(400);
    }
    expect(verify).not.toHaveBeenCalled();
  });
  it('allows only exact approved identities to log in and use email-code recovery', async () => {
    const { synthetic, protectedMember } = await setup();
    const login = await h.login(synthetic.email); expect(login.status).toBe(200);
    expect(login.setCookie).toContain('HttpOnly; Secure; SameSite=Strict');
    expect((await h.call('GET', '/api/auth/session', { cookie: login.cookie })).status).toBe(200);
    const recovery = vi.spyOn(h.provider, 'sendRecovery');
    h.config.emailDeliveryAuthorized = false;
    expect((await h.call('POST', '/api/auth/recovery/request', { body: { email: synthetic.email } })).status).toBe(202);
    expect(recovery).not.toHaveBeenCalled();
    h.config.emailDeliveryAuthorized = true;
    expect((await h.call('POST', '/api/auth/recovery/request', { body: { email: protectedMember.email } })).status).toBe(202);
    expect(recovery).not.toHaveBeenCalled();
    await h.call('POST', '/api/auth/recovery/request', { body: { email: synthetic.email } });
    expect(recovery).toHaveBeenCalledOnce();
    expect((await h.call('POST', '/api/auth/recovery/complete', { body: { email: synthetic.email, code: '482913', password: 'replacement password' } })).status).toBe(200);
    expect((await h.call('GET', '/api/auth/session', { cookie: login.cookie })).status).toBe(401);
  });
  it('blocks invitations and protected targets; invalidates sessions after policy changes', async () => {
    const { synthetic, protectedMember, policy } = await setup(); const login = await h.login(synthetic.email);
    const invite = vi.spyOn(h.provider, 'inviteUser'); const ban = vi.spyOn(h.provider, 'banUser');
    expect((await h.call('POST', '/api/admin/invitations', { cookie: login.cookie, body: { email: 'synthetic2@example.test', role: 'contractor' } })).status).toBe(503);
    expect((await h.call('POST', `/api/admin/members/${protectedMember.id}/disable`, { cookie: login.cookie })).status).toBe(403);
    expect(invite).not.toHaveBeenCalled(); expect(ban).not.toHaveBeenCalled();
    policy.protectedAuthUserIds.push(synthetic.authUserId);
    expect((await h.call('GET', '/api/auth/session', { cookie: login.cookie })).status).toBe(401);
    expect((await h.login(synthetic.email)).status).toBe(401);
  });
  it('rejects platform privilege holders even if an operator mistakenly maps them as synthetic', async () => {
    await setup(); const holder = await h.seedPlatformSuperAdmin();
    h.config.prelaunch!.identities.push({ email: holder.email, memberId: holder.id, authUserId: holder.authUserId });
    h.config.smokeTestEmails = new Set([holder.email]);
    const signIn = vi.spyOn(h.provider, 'signInWithPassword');
    expect((await h.login(holder.email)).status).toBe(401); expect(signIn).not.toHaveBeenCalled();
  });
});
