import { z } from 'zod';
import { authorization, WORKSPACE_ID, type Principal } from '../../src/domain/permissions';
import { acceptInvitationSchema, adminInviteSchema, loginSchema, recoveryCompleteSchema, recoveryRequestSchema } from '../../src/domain/contracts';
import { hmacHex, isSessionTokenShape, newSessionToken, sha256Hex } from './crypto';
import { ProviderConflictError, type AuditEvent, type AuthDeps, type MemberRecord } from './types';

export interface Outcome { status: number; body?: unknown; cookie?: { set: string; maxAge: number } | 'clear' }
export interface RequestMeta { ip: string; sessionToken: string | null }

export const messages = {
  loginFailed: 'Email or password is incorrect, or this account does not have active workspace access.',
  recoveryAccepted: 'If an active Hourvia account uses that email, a 6-digit reset code and link are on the way.',
  recoveryFailed: 'That code or link is invalid or has expired. Request a new one and try again.',
  inviteFailed: 'This invitation is invalid, expired, or already used. Ask your workspace admin for a new invitation.',
  rateLimited: 'Too many attempts. Wait a few minutes and try again.',
  unauthenticated: 'Your session has ended. Sign in again.',
  forbidden: 'Your workspace role does not allow this action.',
} as const;

const ok = (body: unknown, status = 200): Outcome => ({ status, body });
const fail = (status: number, error: string, message: string): Outcome => ({ status, body: { error, message } });
const invalid = (issues: z.core.$ZodIssue[]): Outcome => ({ status: 400, body: { error: 'invalid_request', message: 'Check the highlighted fields.', fields: Object.fromEntries(issues.map(i => [String(i.path[0] ?? 'form'), i.message])) } });
const publicMember = (m: MemberRecord) => ({ id: m.id, email: m.email, name: m.displayName || m.email, role: m.role, status: m.status, createdAt: m.createdAt.toISOString() });

interface Limit { name: string; key: string; max: number; windowSeconds: number }

export class AuthService {
  constructor(private readonly deps: AuthDeps) {}
  private get now() { return this.deps.now(); }
  private hmac(kind: string, value: string) { return hmacHex(this.deps.config.hashKey, `${kind}:${value}`); }
  private audit(event: AuditEvent) { return this.deps.store.audit(event, this.now); }
  private async bestEffort(fn: () => Promise<unknown>) { try { await fn(); } catch { /* provider hygiene only; Hourvia state is authoritative */ } }

  /** Fixed-window limits, keyed by HMAC so raw emails and IPs are never stored. */
  private async limited(ip: string, limits: Limit[]): Promise<Outcome | null> {
    const nowMs = this.now.getTime();
    for (const limit of limits) {
      const windowMs = limit.windowSeconds * 1000;
      const hits = await this.deps.store.hitRateLimit(`${limit.name}:${this.hmac(limit.name, limit.key)}`, new Date(Math.floor(nowMs / windowMs) * windowMs));
      if (hits > limit.max) {
        await this.audit({ eventType: 'rate_limited', outcome: 'denied', ipHmac: this.hmac('ip', ip), details: { limit: limit.name } });
        return fail(429, 'rate_limited', messages.rateLimited);
      }
    }
    return null;
  }

  private async principal(member: MemberRecord): Promise<Principal | null> {
    if (member.workspaceId !== WORKSPACE_ID || member.status !== 'active') return null;
    const manager = member.role === 'workspace_manager';
    return {
      id: member.id, name: member.displayName || member.email, role: member.role, workspaceId: WORKSPACE_ID,
      assignedContractorIds: manager ? await this.deps.store.assignedContractorIds(member.id) : [],
      approvalAuthorized: manager && member.approvalAuthorized,
    };
  }

  /** Resolves the opaque cookie to a trusted principal. Expired, revoked, disabled or forged → null. */
  async authenticate(token: string | null): Promise<Principal | null> {
    if (!token || !isSessionTokenShape(token)) return null;
    const now = this.now;
    const session = await this.deps.store.resolveSession(sha256Hex(token), now);
    if (!session) return null;
    if (now.getTime() - session.lastSeenAt.getTime() > 60_000) {
      await this.deps.store.touchSession(session.sessionId, now, new Date(now.getTime() + this.deps.config.idleTimeoutSeconds * 1000));
    }
    return this.principal(session.member);
  }

  async session(meta: RequestMeta): Promise<Outcome> {
    const principal = await this.authenticate(meta.sessionToken);
    return principal ? ok({ principal }) : { ...fail(401, 'unauthenticated', messages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
  }

  async login(input: unknown, meta: RequestMeta): Promise<Outcome> {
    const parsed = loginSchema.extend({ password: z.string().min(1, 'Enter your password.').max(1024) }).strict().safeParse(input);
    if (!parsed.success) return invalid(parsed.error.issues);
    const email = parsed.data.email.trim().toLowerCase();
    const emailHmac = this.hmac('email', email), ipHmac = this.hmac('ip', meta.ip);
    const blocked = await this.limited(meta.ip, [
      { name: 'login_ip', key: meta.ip, max: 20, windowSeconds: 900 },
      { name: 'login_email', key: email, max: 10, windowSeconds: 900 },
    ]);
    if (blocked) return blocked;

    const providerSession = await this.deps.provider.signInWithPassword(email, parsed.data.password);
    if (!providerSession) {
      await this.audit({ eventType: 'login', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'credentials' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }
    // Hourvia issues its own session; the provider session is revoked so no refresh token survives anywhere.
    await this.bestEffort(() => this.deps.provider.revokeSession(providerSession.accessToken, 'local'));
    const member = await this.deps.store.findMemberByAuthUserId(providerSession.userId);
    const principal = member ? await this.principal(member) : null;
    if (!member || !principal) {
      await this.audit({ eventType: 'login', outcome: 'denied', subjectMemberId: member?.id, emailHmac, ipHmac, details: { reason: member ? `member_${member.status}` : 'no_membership' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }
    const token = newSessionToken(), now = this.now, cfg = this.deps.config;
    await this.deps.store.createSession({
      tokenHash: sha256Hex(token), memberId: member.id, now,
      idleExpiresAt: new Date(now.getTime() + cfg.idleTimeoutSeconds * 1000),
      absoluteExpiresAt: new Date(now.getTime() + cfg.absoluteTimeoutSeconds * 1000),
    });
    await this.audit({ eventType: 'login', outcome: 'success', actorMemberId: member.id, subjectMemberId: member.id, ipHmac });
    return { status: 200, body: { principal }, cookie: { set: token, maxAge: cfg.absoluteTimeoutSeconds } };
  }

  async logout(meta: RequestMeta): Promise<Outcome> {
    if (meta.sessionToken && isSessionTokenShape(meta.sessionToken)) {
      const memberId = await this.deps.store.revokeSession(sha256Hex(meta.sessionToken), 'logout', this.now);
      if (memberId) await this.audit({ eventType: 'logout', outcome: 'success', actorMemberId: memberId, subjectMemberId: memberId, ipHmac: this.hmac('ip', meta.ip) });
    }
    return { status: 204, cookie: 'clear' };
  }

  async requestRecovery(input: unknown, meta: RequestMeta): Promise<Outcome> {
    const started = Date.now();
    const parsed = recoveryRequestSchema.strict().safeParse(input);
    if (!parsed.success) return invalid(parsed.error.issues);
    const email = parsed.data.email.trim().toLowerCase();
    const blocked = await this.limited(meta.ip, [
      { name: 'recovery_request_ip', key: meta.ip, max: 10, windowSeconds: 3600 },
      { name: 'recovery_request_email', key: email, max: 3, windowSeconds: 3600 },
    ]);
    if (blocked) return blocked;
    let result: 'sent' | 'not_eligible' | 'delivery_not_authorized' | 'provider_error' = 'not_eligible';
    const member = await this.deps.store.findMemberByEmail(email);
    if (member?.status === 'active' && member.authUserId) {
      if (!this.deps.config.emailDeliveryAuthorized || !this.deps.config.appOrigin) result = 'delivery_not_authorized';
      else {
        try { await this.deps.provider.sendRecovery(email, `${this.deps.config.appOrigin}/reset-password`); result = 'sent'; }
        catch { result = 'provider_error'; }
      }
    }
    await this.audit({ eventType: 'recovery_requested', outcome: result === 'sent' ? 'success' : result === 'provider_error' ? 'error' : 'denied', subjectMemberId: member?.id, emailHmac: this.hmac('email', email), ipHmac: this.hmac('ip', meta.ip), details: { result } });
    const remaining = this.deps.config.recoveryMinimumMs - (Date.now() - started);
    if (remaining > 0) await this.deps.sleep(remaining);
    return ok({ message: messages.recoveryAccepted }, 202);
  }

  async completeRecovery(input: unknown, meta: RequestMeta): Promise<Outcome> {
    const parsed = recoveryCompleteSchema.safeParse(input);
    if (!parsed.success) return invalid(parsed.error.issues);
    const data = parsed.data;
    const email = 'email' in data ? data.email.trim().toLowerCase() : null;
    const blocked = await this.limited(meta.ip, [
      { name: 'recovery_verify_ip', key: meta.ip, max: 20, windowSeconds: 3600 },
      ...(email ? [{ name: 'recovery_verify_email', key: email, max: 5, windowSeconds: 3600 }] : []),
    ]);
    if (blocked) return blocked;
    const ipHmac = this.hmac('ip', meta.ip), emailHmac = email ? this.hmac('email', email) : null;
    const verified = await this.deps.provider.verifyEmailOtp(email && 'code' in data ? { type: 'recovery', email, code: data.code } : { type: 'recovery', tokenHash: (data as { tokenHash: string }).tokenHash });
    if (!verified) {
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'verification' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    const member = await this.deps.store.findMemberByAuthUserId(verified.userId);
    if (member?.status !== 'active') {
      await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', subjectMemberId: member?.id, emailHmac, ipHmac, details: { reason: member ? `member_${member.status}` : 'no_membership' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    try { await this.deps.provider.setPassword(verified.userId, data.password); }
    catch (error) {
      await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      if (error instanceof ProviderConflictError) return fail(400, 'weak_password', 'Choose a stronger password.');
      throw error;
    }
    const revoked = await this.deps.store.revokeMemberSessions(member.id, 'password_reset', this.now);
    await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
    await this.audit({ eventType: 'recovery_completed', outcome: 'success', actorMemberId: member.id, subjectMemberId: member.id, ipHmac, details: { sessions_revoked: revoked } });
    return ok({ message: 'Password updated. Sign in with your new password.' });
  }

  async acceptInvitation(input: unknown, meta: RequestMeta): Promise<Outcome> {
    const parsed = acceptInvitationSchema.strict().safeParse(input);
    if (!parsed.success) return invalid(parsed.error.issues);
    const blocked = await this.limited(meta.ip, [{ name: 'invite_accept_ip', key: meta.ip, max: 10, windowSeconds: 3600 }]);
    if (blocked) return blocked;
    const ipHmac = this.hmac('ip', meta.ip);
    const verified = await this.deps.provider.verifyEmailOtp({ type: 'invite', tokenHash: parsed.data.tokenHash });
    if (!verified) {
      await this.audit({ eventType: 'invitation_accepted', outcome: 'denied', ipHmac, details: { reason: 'verification' } });
      return fail(400, 'invitation_failed', messages.inviteFailed);
    }
    const now = this.now;
    const member = await this.deps.store.findMemberByAuthUserId(verified.userId);
    if (!member || member.status !== 'invited' || !(await this.deps.store.hasPendingInvitation(member.id, now))) {
      await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      await this.audit({ eventType: 'invitation_accepted', outcome: 'denied', subjectMemberId: member?.id, ipHmac, details: { reason: member ? `member_${member.status}_or_expired` : 'no_invitation' } });
      return fail(400, 'invitation_failed', messages.inviteFailed);
    }
    try { await this.deps.provider.setPassword(verified.userId, parsed.data.password); }
    catch (error) {
      await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      if (error instanceof ProviderConflictError) return fail(400, 'weak_password', 'Choose a stronger password.');
      throw error;
    }
    const accepted = await this.deps.store.acceptInvitation(member.id, now);
    await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
    await this.audit({ eventType: 'invitation_accepted', outcome: accepted ? 'success' : 'denied', actorMemberId: member.id, subjectMemberId: member.id, ipHmac });
    return accepted ? ok({ message: 'Your password is set. Sign in to open your workspace.' }) : fail(400, 'invitation_failed', messages.inviteFailed);
  }

  // ---------- Admin (server-side RBAC: workspace.manage inside ThriveSource) ----------
  private async admin(meta: RequestMeta): Promise<Principal | Outcome> {
    const principal = await this.authenticate(meta.sessionToken);
    if (!principal) return { ...fail(401, 'unauthenticated', messages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    if (!authorization.can(principal, 'workspace.manage', { workspaceId: WORKSPACE_ID })) {
      await this.audit({ eventType: 'admin_access', outcome: 'denied', actorMemberId: principal.id, ipHmac: this.hmac('ip', meta.ip) });
      return fail(403, 'forbidden', messages.forbidden);
    }
    return principal;
  }

  async listMembers(meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    return ok({ members: (await this.deps.store.listMembers()).map(publicMember) });
  }

  async invite(input: unknown, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    const parsed = adminInviteSchema.strict().safeParse(input);
    if (!parsed.success) return invalid(parsed.error.issues);
    const cfg = this.deps.config;
    if (!cfg.emailDeliveryAuthorized || !cfg.appOrigin) return fail(503, 'email_delivery_not_authorized', 'Invitation email delivery is not authorized in this environment.');
    const blocked = await this.limited(meta.ip, [{ name: 'admin_invite', key: admin.id, max: 30, windowSeconds: 3600 }]);
    if (blocked) return blocked;
    const email = parsed.data.email.trim().toLowerCase();
    const existing = await this.deps.store.findMemberByEmail(email);
    if (existing && existing.status !== 'invited') return fail(409, 'member_exists', 'This email already belongs to a workspace member.');
    let userId: string;
    try { ({ userId } = await this.deps.provider.inviteUser(email, `${cfg.appOrigin}/accept-invite`)); }
    catch (error) {
      await this.audit({ eventType: 'invitation_created', outcome: 'error', actorMemberId: admin.id, emailHmac: this.hmac('email', email), details: { reason: error instanceof ProviderConflictError ? 'identity_exists' : 'provider' } });
      return error instanceof ProviderConflictError ? fail(409, 'identity_exists', 'This email already has a sign-in identity. Review it in Supabase before inviting.') : fail(502, 'provider_unavailable', 'The invitation could not be sent. Try again.');
    }
    if (existing && existing.authUserId !== userId) return fail(409, 'identity_mismatch', 'This invitation does not match the existing identity. Review it before inviting again.');
    const member = await this.deps.store.upsertInvitation({
      email, role: parsed.data.role, displayName: parsed.data.displayName ?? '', authUserId: userId, invitedBy: admin.id,
      now: this.now, expiresAt: new Date(this.now.getTime() + cfg.invitationTtlSeconds * 1000),
    });
    await this.audit({ eventType: 'invitation_created', outcome: 'success', actorMemberId: admin.id, subjectMemberId: member.id, details: { role: member.role, resent: !!existing } });
    return ok({ member: publicMember(member) }, 201);
  }

  async disableMember(memberId: string, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    if (!z.uuid().safeParse(memberId).success) return fail(404, 'not_found', 'Member not found.');
    if (memberId === admin.id) return fail(409, 'self_disable', 'You cannot disable your own access.');
    const target = await this.deps.store.findMemberById(memberId);
    if (!target) return fail(404, 'not_found', 'Member not found.');
    const changed = await this.deps.store.disableMember(memberId, admin.id, this.now);
    const revoked = await this.deps.store.revokeMemberSessions(memberId, 'member_disabled', this.now);
    let providerBanned = false;
    if (target.authUserId) { try { await this.deps.provider.banUser(target.authUserId); providerBanned = true; } catch { /* Hourvia disable is already authoritative */ } }
    await this.audit({ eventType: 'member_disabled', outcome: 'success', actorMemberId: admin.id, subjectMemberId: memberId, details: { changed, sessions_revoked: revoked, provider_banned: providerBanned } });
    return ok({ member: publicMember({ ...target, status: 'disabled' }), sessionsRevoked: revoked, providerBanned });
  }

  async revokeMemberSessions(memberId: string, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    if (!z.uuid().safeParse(memberId).success || !(await this.deps.store.findMemberById(memberId))) return fail(404, 'not_found', 'Member not found.');
    const revoked = await this.deps.store.revokeMemberSessions(memberId, 'admin_revoked', this.now);
    await this.audit({ eventType: 'sessions_revoked', outcome: 'success', actorMemberId: admin.id, subjectMemberId: memberId, details: { sessions_revoked: revoked } });
    return ok({ sessionsRevoked: revoked });
  }
}
