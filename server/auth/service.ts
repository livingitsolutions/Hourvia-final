import { z } from 'zod';
import { identityAllowed } from './synthetic-policy';
import { belongsToOrganization } from '../../src/domain/organization';
import { authorization, canAssignRole, canManageMember, hasPlatformPrivilege, WORKSPACE_ID, type Principal } from '../../src/domain/permissions';
import { acceptInvitationSchema, adminInviteSchema, loginSchema, memberRoleChangeSchema, recoveryCompleteSchema, recoveryRequestSchema } from '../../src/domain/contracts';
import { PLATFORM_AUDIT_DEFAULT_LIMIT, PLATFORM_AUDIT_MAX_LIMIT, platformAuthorization, type PlatformPermission } from '../../src/domain/platform';
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
  privilegeDenied: 'Your workspace role cannot grant or change that access.',
  platformForbidden: 'Platform Administration is available only to the Platform Super Admin.',
} as const;

const ok = (body: unknown, status = 200): Outcome => ({ status, body });
const fail = (status: number, error: string, message: string): Outcome => ({ status, body: { error, message } });
const invalid = (issues: z.core.$ZodIssue[]): Outcome => ({ status: 400, body: { error: 'invalid_request', message: 'Check the highlighted fields.', fields: Object.fromEntries(issues.map(i => [String(i.path[0] ?? 'form'), i.message])) } });
const publicMember = (m: MemberRecord) => ({ id: m.id, email: m.email, name: m.displayName || m.email, role: m.role, status: m.status, createdAt: m.createdAt.toISOString() });

/** auditOnce: record only the first rejection per window, so a flood of rejected requests writes one audit row, not one per request. */
interface Limit { name: string; key: string; max: number; windowSeconds: number; auditOnce?: boolean }

/**
 * Platform request limits (Sprint 1.8B, audit finding M-1). Both protected paths write to append-only audit tables:
 * a denial writes auth_audit_events, an audit-page read writes platform_audit_events. The limit is checked first, so
 * a caller over the limit gets 429 and writes nothing more than one rate_limited row per window.
 */
export const PLATFORM_LIMITS = {
  deniedPerMember: { name: 'platform_denied', max: 10, windowSeconds: 3600 },
  deniedPerIp: { name: 'platform_denied_ip', max: 30, windowSeconds: 3600 },
  auditReadsPerMember: { name: 'platform_audit_read', max: 60, windowSeconds: 3600 },
} as const;

export class AuthService {
  constructor(private readonly deps: AuthDeps) {}
  private get now() { return this.deps.now(); }
  private hmac(kind: string, value: string) { return hmacHex(this.deps.config.hashKey, `${kind}:${value}`); }
  private audit(event: AuditEvent) { return this.deps.store.audit(event, this.now); }
  /** True while the production smoke-test stage is active and this email is not a designated test account. */
  private outsideSmoke(email: string) { const allow = this.deps.config.smokeTestEmails; return !!allow && !allow.has(email.trim().toLowerCase()); }
  private async approvedMember(member: MemberRecord | null): Promise<boolean> {
    const policy = this.deps.config.prelaunch;
    return !policy || !!member && identityAllowed(policy, member)
      && belongsToOrganization(this.deps.store.context, member.organizationId)
      && !(await this.deps.store.platformPrivileges(member.authUserId!)).length;
  }
  private async bestEffort(fn: () => Promise<unknown>) { try { await fn(); } catch { /* provider hygiene only; Hourvia state is authoritative */ } }

  /** Fixed-window limits, keyed by HMAC so raw emails and IPs are never stored. */
  private async limited(ip: string, limits: Limit[]): Promise<Outcome | null> {
    const nowMs = this.now.getTime();
    for (const limit of limits) {
      const windowMs = limit.windowSeconds * 1000;
      const hits = await this.deps.store.hitRateLimit(`${limit.name}:${this.hmac(limit.name, limit.key)}`, new Date(Math.floor(nowMs / windowMs) * windowMs));
      if (hits > limit.max) {
        if (!limit.auditOnce || hits === limit.max + 1) await this.audit({ eventType: 'rate_limited', outcome: 'denied', ipHmac: this.hmac('ip', ip), details: { limit: limit.name } });
        return fail(429, 'rate_limited', messages.rateLimited);
      }
    }
    return null;
  }

  private async principal(member: MemberRecord): Promise<Principal | null> {
    if (member.workspaceId !== WORKSPACE_ID || member.status !== 'active') return null;
    // Sprint 2.0B: the membership must also belong to the store's server-derived organization context (fail closed).
    if (!belongsToOrganization(this.deps.store.context, member.organizationId)) return null;
    const manager = member.role === 'workspace_manager';
    return {
      id: member.id, name: member.displayName || member.email, role: member.role, workspaceId: WORKSPACE_ID,
      assignedContractorIds: manager ? await this.deps.store.assignedContractorIds(member.id) : [],
      approvalAuthorized: manager && member.approvalAuthorized,
      // Read from platform_privileges by verified identity; never from the membership, the client or Supabase metadata.
      platformPrivileges: member.authUserId ? await this.deps.store.platformPrivileges(member.authUserId) : [],
    };
  }

  /** Resolves the opaque cookie to a trusted principal. Expired, revoked, disabled or forged → null. */
  async authenticate(token: string | null): Promise<Principal | null> {
    if (!token || !isSessionTokenShape(token)) return null;
    const now = this.now;
    const session = await this.deps.store.resolveSession(sha256Hex(token), now);
    if (!session || this.outsideSmoke(session.member.email) || !await this.approvedMember(session.member)) return null;
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
    if (this.outsideSmoke(email)) {
      // Denied before Supabase is contacted, so a real user's identity is never touched during smoke tests.
      await this.audit({ eventType: 'login', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'smoke_allowlist' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }

    const expected = this.deps.config.prelaunch ? await this.deps.store.findMemberByEmail(email) : null;
    if (this.deps.config.prelaunch && (expected?.status !== 'active' || !await this.approvedMember(expected))) {
      await this.audit({ eventType: 'login', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'identity_not_authorized' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }
    const providerSession = await this.deps.provider.signInWithPassword(email, parsed.data.password);
    if (!providerSession) {
      await this.audit({ eventType: 'login', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'credentials' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }
    if (expected && providerSession.userId !== expected.authUserId) {
      await this.audit({ eventType: 'login', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'provider_identity_mismatch' } });
      return fail(401, 'login_failed', messages.loginFailed);
    }
    // Hourvia issues its own session; the provider session is revoked so no refresh token survives anywhere.
    await this.bestEffort(() => this.deps.provider.revokeSession(providerSession.accessToken, 'local'));
    const member = await this.deps.store.findMemberByAuthUserId(providerSession.userId);
    const principal = member ? await this.principal(member) : null;
    if (!member || !principal || !await this.approvedMember(member) || (expected && member.id !== expected.id)) {
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
    let result: 'sent' | 'not_eligible' | 'smoke_allowlist' | 'delivery_not_authorized' | 'provider_error' = 'not_eligible';
    const member = await this.deps.store.findMemberByEmail(email);
    if (member?.status === 'active' && member.authUserId && (this.outsideSmoke(email) || !await this.approvedMember(member))) result = 'smoke_allowlist';
    else if (member?.status === 'active' && member.authUserId) {
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
    if (email && this.outsideSmoke(email)) {
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'smoke_allowlist' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    const expected = this.deps.config.prelaunch && email ? await this.deps.store.findMemberByEmail(email) : null;
    if (this.deps.config.prelaunch && (!email || expected?.status !== 'active' || !await this.approvedMember(expected))) {
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'identity_not_authorized' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    const verified = await this.deps.provider.verifyEmailOtp(email && 'code' in data ? { type: 'recovery', email, code: data.code } : { type: 'recovery', tokenHash: (data as { tokenHash: string }).tokenHash });
    if (!verified) {
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'verification' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    if (expected && verified.userId !== expected.authUserId) {
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', emailHmac, ipHmac, details: { reason: 'provider_identity_mismatch' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    const member = await this.deps.store.findMemberByAuthUserId(verified.userId);
    if (member?.status !== 'active' || this.outsideSmoke(member.email) || !await this.approvedMember(member) || (expected && member.id !== expected.id)) {
      if (!this.deps.config.prelaunch) await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      await this.audit({ eventType: 'recovery_completed', outcome: 'denied', subjectMemberId: member?.id, emailHmac, ipHmac, details: { reason: !member ? 'no_membership' : member.status !== 'active' ? `member_${member.status}` : 'smoke_allowlist' } });
      return fail(400, 'recovery_failed', messages.recoveryFailed);
    }
    try { await this.deps.provider.setPassword(verified.userId, data.password); }
    catch (error) {
      await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
      if (error instanceof ProviderConflictError) return fail(400, 'weak_password', 'Choose a stronger password.');
      throw error;
    }
    const revoked = await this.deps.store.revokeMemberSessions(member.id, 'password_reset', this.now, member.id);
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
    if (this.deps.config.prelaunch) {
      await this.audit({ eventType: 'invitation_accepted', outcome: 'denied', ipHmac, details: { reason: 'challenge_preauthorization_required' } });
      return fail(400, 'invitation_failed', messages.inviteFailed);
    }
    const verified = await this.deps.provider.verifyEmailOtp({ type: 'invite', tokenHash: parsed.data.tokenHash });
    if (!verified) {
      await this.audit({ eventType: 'invitation_accepted', outcome: 'denied', ipHmac, details: { reason: 'verification' } });
      return fail(400, 'invitation_failed', messages.inviteFailed);
    }
    const now = this.now;
    const member = await this.deps.store.findMemberByAuthUserId(verified.userId);
    if (!member || member.status !== 'invited' || this.outsideSmoke(member.email) || !(await this.deps.store.hasPendingInvitation(member.id, now))) {
      if (!this.deps.config.prelaunch) await this.bestEffort(() => this.deps.provider.revokeSession(verified.accessToken, 'global'));
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
    if (!parsed.success) {
      const requested = input && typeof input === 'object' ? (input as { role?: unknown }).role : undefined;
      if (requested === 'super_admin' || requested === 'platform_super_admin') {
        await this.audit({ eventType: 'invitation_created', outcome: 'denied', actorMemberId: admin.id, details: { reason: 'platform_privilege_not_assignable' } });
      }
      return invalid(parsed.error.issues);
    }
    if (this.deps.config.prelaunch) {
      const blocked = await this.limited(meta.ip, [{ name: 'admin_invite', key: admin.id, max: 30, windowSeconds: 3600 }]);
      if (blocked) return blocked;
      await this.audit({ eventType: 'invitation_created', outcome: 'denied', actorMemberId: admin.id, details: { reason: 'challenge_preauthorization_required' } });
      return fail(503, 'invitation_unavailable', 'Invitation onboarding is unavailable during pre-launch.');
    }
    const cfg = this.deps.config;
    if (!cfg.emailDeliveryAuthorized || !cfg.appOrigin) return fail(503, 'email_delivery_not_authorized', 'Invitation email delivery is not authorized in this environment.');
    const blocked = await this.limited(meta.ip, [{ name: 'admin_invite', key: admin.id, max: 30, windowSeconds: 3600 }]);
    if (blocked) return blocked;
    const email = parsed.data.email.trim().toLowerCase();
    if (!canAssignRole(admin, parsed.data.role)) {
      await this.audit({ eventType: 'invitation_created', outcome: 'denied', actorMemberId: admin.id, emailHmac: this.hmac('email', email), details: { reason: 'role_not_assignable', role: parsed.data.role } });
      return fail(403, 'privilege_denied', messages.privilegeDenied);
    }
    if (this.outsideSmoke(email)) {
      await this.audit({ eventType: 'invitation_created', outcome: 'denied', actorMemberId: admin.id, emailHmac: this.hmac('email', email), details: { reason: 'smoke_allowlist' } });
      return fail(403, 'smoke_allowlist', 'During production smoke testing, only designated test accounts can be invited.');
    }
    const existing = await this.deps.store.findMemberByEmail(email);
    if (existing && existing.status !== 'invited') return fail(409, 'member_exists', 'This email already belongs to a workspace member.');
    if (existing && !canManageMember(admin, existing)) {
      // Re-inviting changes the pending role, so it needs authority over the member's current role too.
      await this.audit({ eventType: 'invitation_created', outcome: 'denied', actorMemberId: admin.id, subjectMemberId: existing.id, details: { reason: 'member_not_manageable', role: parsed.data.role } });
      return fail(403, 'privilege_denied', messages.privilegeDenied);
    }
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
    await this.audit({ eventType: 'invitation_created', outcome: 'success', actorMemberId: admin.id, subjectMemberId: member.id, details: { role: member.role, resent: !!existing, authority: this.authority(admin, member.role, existing?.role ?? ''), ...(existing && existing.role !== member.role ? { from_role: existing.role } : {}) } });
    return ok({ member: publicMember(member) }, 201);
  }

  /** Denies (and audits) any action on a member outside the caller's authority. */
  private async manageable(admin: Principal, target: MemberRecord, eventType: string, details: AuditEvent['details'] = {}): Promise<Outcome | null> {
    if (canManageMember(admin, target)) return null;
    await this.audit({ eventType, outcome: 'denied', actorMemberId: admin.id, subjectMemberId: target.id, details: { reason: 'member_not_manageable', target_role: target.role, ...details } });
    return fail(403, 'privilege_denied', messages.privilegeDenied);
  }
  /** Which authority an allowed membership action relied on, for the audit trail. */
  private authority(admin: Principal, ...roles: string[]) {
    return roles.includes('workspace_admin') && hasPlatformPrivilege(admin, 'platform_super_admin') ? 'platform_super_admin' : 'workspace_admin';
  }

  async changeMemberRole(memberId: string, input: unknown, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    const parsed = memberRoleChangeSchema.strict().safeParse(input);
    if (!parsed.success) {
      const requested = input && typeof input === 'object' ? (input as { role?: unknown }).role : undefined;
      if (requested === 'super_admin' || requested === 'platform_super_admin') {
        await this.audit({ eventType: 'member_role_changed', outcome: 'denied', actorMemberId: admin.id, details: { reason: 'platform_privilege_not_assignable' } });
      }
      return invalid(parsed.error.issues);
    }
    if (!z.uuid().safeParse(memberId).success) return fail(404, 'not_found', 'Member not found.');
    const role = parsed.data.role;
    if (memberId === admin.id) {
      await this.audit({ eventType: 'member_role_changed', outcome: 'denied', actorMemberId: admin.id, subjectMemberId: admin.id, details: { reason: 'self_change', role } });
      return fail(403, 'self_change', 'You cannot change your own role.');
    }
    const target = await this.deps.store.findMemberById(memberId);
    if (!target) return fail(404, 'not_found', 'Member not found.');
    const denied = await this.manageable(admin, target, 'member_role_changed', { role });
    if (denied) return denied;
    if (!canAssignRole(admin, role)) {
      await this.audit({ eventType: 'member_role_changed', outcome: 'denied', actorMemberId: admin.id, subjectMemberId: target.id, details: { reason: 'role_not_assignable', from_role: target.role, role } });
      return fail(403, 'privilege_denied', messages.privilegeDenied);
    }
    if (this.outsideSmoke(target.email) || !await this.approvedMember(target)) return fail(403, 'smoke_allowlist', 'During production smoke testing, only designated test accounts can be changed.');
    if (target.status !== 'active') return fail(409, 'member_not_active', target.status === 'invited' ? 'Send a new invitation with the new role instead.' : 'Disabled members cannot change role.');
    if (target.role === role) return fail(409, 'role_unchanged', 'This member already has that role.');
    const changed = await this.deps.store.changeMemberRole({ memberId: target.id, expectedRole: target.role, role, changedBy: admin.id, now: this.now });
    if (!changed) return fail(409, 'member_changed', 'This member changed in the meantime. Reload and try again.');
    await this.audit({ eventType: 'member_role_changed', outcome: 'success', actorMemberId: admin.id, subjectMemberId: target.id, ipHmac: this.hmac('ip', meta.ip), details: { from_role: target.role, to_role: role, authority: this.authority(admin, target.role, role) } });
    return ok({ member: publicMember({ ...target, role, approvalAuthorized: role === 'workspace_manager' && target.approvalAuthorized }) });
  }

  async disableMember(memberId: string, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    if (!z.uuid().safeParse(memberId).success) return fail(404, 'not_found', 'Member not found.');
    if (memberId === admin.id) return fail(409, 'self_disable', 'You cannot disable your own access.');
    const target = await this.deps.store.findMemberById(memberId);
    if (!target) return fail(404, 'not_found', 'Member not found.');
    const denied = await this.manageable(admin, target, 'member_disabled');
    if (denied) return denied;
    if (this.outsideSmoke(target.email) || !await this.approvedMember(target)) return fail(403, 'smoke_allowlist', 'During production smoke testing, only designated test accounts can be changed.');
    // Sprint 3.0.2 (G1): one transaction. A failure can no longer leave a disabled member with live sessions that an
    // operator reinstatement would revive; either the member is disabled with every session ended, or nothing changed.
    const { changed, sessionsRevoked: revoked } = await this.deps.store.disableMemberAndRevokeSessions(memberId, admin.id, this.now);
    let providerBanned = false;
    if (target.authUserId) { try { await this.deps.provider.banUser(target.authUserId); providerBanned = true; } catch { /* Hourvia disable is already authoritative */ } }
    await this.audit({ eventType: 'member_disabled', outcome: 'success', actorMemberId: admin.id, subjectMemberId: memberId, details: { changed, target_role: target.role, authority: this.authority(admin, target.role), sessions_revoked: revoked, provider_banned: providerBanned } });
    return ok({ member: publicMember({ ...target, status: 'disabled' }), sessionsRevoked: revoked, providerBanned });
  }

  async revokeMemberSessions(memberId: string, meta: RequestMeta): Promise<Outcome> {
    const admin = await this.admin(meta);
    if ('status' in admin) return admin;
    const target = z.uuid().safeParse(memberId).success ? await this.deps.store.findMemberById(memberId) : null;
    if (!target) return fail(404, 'not_found', 'Member not found.');
    // Ending your own sessions is always allowed; anyone else needs authority over the member's role.
    const denied = target.id === admin.id ? null : await this.manageable(admin, target, 'sessions_revoked');
    if (denied) return denied;
    if (this.outsideSmoke(target.email) || !await this.approvedMember(target)) return fail(403, 'smoke_allowlist', 'During production smoke testing, only designated test accounts can be changed.');
    const revoked = await this.deps.store.revokeMemberSessions(memberId, target.id === admin.id ? 'self_revoked' : 'admin_revoked', this.now, admin.id);
    await this.audit({ eventType: 'sessions_revoked', outcome: 'success', actorMemberId: admin.id, subjectMemberId: memberId, details: { sessions_revoked: revoked, target_role: target.role, authority: target.id === admin.id ? 'self' : this.authority(admin, target.role) } });
    return ok({ sessionsRevoked: revoked });
  }

  // ---------- Platform Administration (Sprint 1.8): read-only, platform plane only ----------
  /**
   * Platform guard. Authorizes from the platform plane only (platformAuthorization never reads the organization role
   * or workspace permissions), then the database re-authorizes from the session itself inside hourvia_platform_*.
   * Unauthenticated → 401. Authenticated without the platform permission → 403, audited in auth_audit_events, or 429
   * once the caller exceeds PLATFORM_LIMITS (checked before the denial is audited).
   */
  private async platform(meta: RequestMeta, permission: PlatformPermission): Promise<{ principal: Principal; tokenHash: string } | Outcome> {
    const principal = await this.authenticate(meta.sessionToken);
    if (!principal || !meta.sessionToken) return { ...fail(401, 'unauthenticated', messages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    if (!platformAuthorization.can(principal, permission)) return this.platformDenied(principal, meta, permission, 'no_platform_privilege');
    return { principal, tokenHash: sha256Hex(meta.sessionToken) };
  }
  private async platformDenied(principal: Principal, meta: RequestMeta, permission: PlatformPermission, reason: string): Promise<Outcome> {
    // Limit before auditing: past the limit the caller gets 429 and no further denial rows are written.
    const blocked = await this.limited(meta.ip, [
      { ...PLATFORM_LIMITS.deniedPerMember, key: principal.id, auditOnce: true },
      { ...PLATFORM_LIMITS.deniedPerIp, key: meta.ip, auditOnce: true },
    ]);
    if (blocked) return blocked;
    await this.audit({ eventType: 'platform_access', outcome: 'denied', actorMemberId: principal.id, ipHmac: this.hmac('ip', meta.ip), details: { permission, reason } });
    return fail(403, 'platform_forbidden', messages.platformForbidden);
  }

  async platformOverview(meta: RequestMeta): Promise<Outcome> {
    const guard = await this.platform(meta, 'platform.overview.read');
    if ('status' in guard) return guard;
    const overview = await this.deps.store.platformOverview(guard.tokenHash);
    if (!overview) return this.platformDenied(guard.principal, meta, 'platform.overview.read', 'database_denied');
    return ok({ overview });
  }

  async platformAudit(meta: RequestMeta, query: URLSearchParams): Promise<Outcome> {
    const guard = await this.platform(meta, 'platform.audit.read');
    if ('status' in guard) return guard;
    const page = parseAuditQuery(query);
    if ('error' in page) return { status: 400, body: { error: 'invalid_request', message: page.error } };
    // Every audit-page read is recorded in platform_audit_events, so reads are limited before the database call.
    const blocked = await this.limited(meta.ip, [{ ...PLATFORM_LIMITS.auditReadsPerMember, key: guard.principal.id, auditOnce: true }]);
    if (blocked) return blocked;
    const result = await this.deps.store.platformAuditPage(guard.tokenHash, page);
    if (!result) return this.platformDenied(guard.principal, meta, 'platform.audit.read', 'database_denied');
    return ok(result);
  }
}

/** Accepts only ?limit=1..100 and ?before=<positive id>, each at most once. Validated after authorization. */
function parseAuditQuery(query: URLSearchParams): { beforeId: number | null; limit: number } | { error: string } {
  const keys = [...query.keys()];
  if (keys.some(key => key !== 'limit' && key !== 'before') || new Set(keys).size !== keys.length) return { error: 'Only the limit and before parameters are accepted.' };
  const limitText = query.get('limit'); const beforeText = query.get('before');
  if (limitText !== null && !/^[1-9]\d{0,2}$/.test(limitText)) return { error: `limit must be between 1 and ${PLATFORM_AUDIT_MAX_LIMIT}.` };
  const limit = limitText === null ? PLATFORM_AUDIT_DEFAULT_LIMIT : Number(limitText);
  if (limit > PLATFORM_AUDIT_MAX_LIMIT) return { error: `limit must be between 1 and ${PLATFORM_AUDIT_MAX_LIMIT}.` };
  if (beforeText !== null && !/^[1-9]\d{0,14}$/.test(beforeText)) return { error: 'before must be a positive event id.' };
  return { beforeId: beforeText === null ? null : Number(beforeText), limit };
}
