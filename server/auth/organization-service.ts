import { z } from 'zod';
import {
  THRIVESOURCE_ORGANIZATION_ID, isMultiOrganizationCapability, organizationContextForVerifiedMembership, type MultiOrganizationCapability,
  type OrganizationContext,
} from '../../src/domain/organization';
import type { Permission } from '../../src/domain/permissions';
import {
  canReserveSeat, membershipGrantsAccess, organizationCan, seatUsage, selectableMembership, type OrganizationMembership,
  type OrganizationPrincipal, type OrganizationResourceScope,
} from '../../src/domain/tenancy';
import { isSessionTokenShape, newSessionToken, sha256Hex } from './crypto';
import type { IdentityDirectory, ResolvedIdentity } from './organization-directory';
import type { Outcome, RequestMeta } from './service';
import type { PostgresAuthStore } from './store-postgres';
import type { PostgresTenancyStore } from './store-tenancy';
import type { AuthStore } from './types';

/**
 * Sprint 3.0 organization selection and switching contracts (backend only; no HTTP route is registered).
 *
 * Server-authoritative context: the organization of every request is derived from the session cookie
 * -> auth_sessions -> membership -> organization, all read by the server. A client-supplied organization id is only
 * ever a *request* to switch, matched against the memberships the server read for the session's own identity.
 *
 * Every method returns 503 multi_organization_unavailable unless the service was constructed with a valid
 * MultiOrganizationCapability. Production never constructs one in Sprint 3.0 (M8 is not applied), so these paths are
 * explicitly unavailable rather than simulated.
 */
export interface OrganizationServiceDeps {
  capability: MultiOrganizationCapability | null;
  directory: IdentityDirectory;
  /** Store bound to exactly one server-built context. */
  storeFor(context: OrganizationContext): AuthStore;
  /**
   * Sprint 3.0.1: runs fn in ONE database transaction; every store it builds shares that transaction. Used by the
   * organization switch so that revoking the source session and issuing its replacement commit together or not at all.
   */
  transaction<T>(fn: (storeFor: (context: OrganizationContext) => PostgresAuthStore) => Promise<T>): Promise<T>;
  tenancyFor(context: OrganizationContext): PostgresTenancyStore;
  now(): Date;
  session: { idleTimeoutSeconds: number; absoluteTimeoutSeconds: number };
}

const ok = (body: unknown, status = 200): Outcome => ({ status, body });
const fail = (status: number, error: string, message: string): Outcome => ({ status, body: { error, message } });
export const organizationMessages = {
  unavailable: 'Organization switching is not available yet.',
  unauthenticated: 'Your session has ended. Sign in again.',
  notAvailable: 'That organization is not available to your account.',
  forbidden: 'Your organization role does not allow this action.',
  switchFailed: 'The organization could not be switched. Your current session is unchanged; try again.',
} as const;
const UNAVAILABLE = fail(503, 'multi_organization_unavailable', organizationMessages.unavailable);
const selectSchema = z.object({ organizationId: z.string().max(64) }).strict();

const publicMembership = (m: OrganizationMembership, current: boolean) => ({
  organizationId: m.organizationId, slug: m.organization.slug, name: m.organization.name, kind: m.organization.kind,
  role: m.role, status: m.status, selectable: membershipGrantsAccess(m), current,
});

interface Resolved { identity: ResolvedIdentity; membership: OrganizationMembership; context: OrganizationContext; store: AuthStore }

export class OrganizationAccessService {
  constructor(private readonly deps: OrganizationServiceDeps) {}
  private get available() { return isMultiOrganizationCapability(this.deps.capability); }

  /** Resolves the session into its server-built organization context, re-reading the membership inside that context. */
  private async resolve(meta: RequestMeta): Promise<Resolved | null> {
    if (!meta.sessionToken || !isSessionTokenShape(meta.sessionToken)) return null;
    const identity = await this.deps.directory.resolve(sha256Hex(meta.sessionToken), this.deps.now());
    if (!identity) return null;
    const membership = identity.memberships.find(m => m.memberId === identity.session.memberId && m.organizationId === identity.session.organizationId);
    if (!membership || !membershipGrantsAccess(membership)) return null;
    let context: OrganizationContext;
    try {
      context = organizationContextForVerifiedMembership(
        { organizationId: membership.organizationId, workspaceId: identity.session.workspaceId },
        { id: membership.organizationId, slug: membership.organization.slug, status: membership.organization.status }, this.deps.capability);
    } catch { return null; }
    const store = this.deps.storeFor(context);
    // Revalidation inside the tenant boundary: the same session must still resolve in its own organization.
    const session = await store.resolveSession(sha256Hex(meta.sessionToken), this.deps.now());
    if (!session || session.member.id !== membership.memberId || session.member.organizationId !== context.organizationId) return null;
    return { identity, membership, context, store };
  }

  /** The principal for the session's organization. Platform privileges come from the identity, never from a role. */
  async principal(meta: RequestMeta): Promise<OrganizationPrincipal | null> {
    if (!this.available) return null;
    const r = await this.resolve(meta);
    if (!r) return null;
    const member = await r.store.findMemberById(r.membership.memberId);
    if (!member || member.status !== 'active' || !member.authUserId) return null;
    const manager = member.role === 'workspace_manager';
    return {
      id: member.id, organizationId: r.context.organizationId, role: member.role,
      assignedContractorIds: manager ? await r.store.assignedContractorIds(member.id) : [],
      approvalAuthorized: manager && member.approvalAuthorized,
      // Sprint 3.0.1 (M1): the platform privilege belongs to the holder's ThriveSource membership only. A membership in
      // any other organization never carries it, even for the designated holder.
      platformPrivileges: r.context.organizationId === THRIVESOURCE_ORGANIZATION_ID ? await r.store.platformPrivileges(member.authUserId) : [],
    };
  }

  async listOrganizations(meta: RequestMeta): Promise<Outcome> {
    if (!this.available) return UNAVAILABLE;
    const r = await this.resolve(meta);
    if (!r) return { ...fail(401, 'unauthenticated', organizationMessages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    return ok({ organizations: r.identity.memberships.map(m => publicMembership(m, m.memberId === r.membership.memberId)) });
  }

  /** Revalidates the current organization context (membership and organization still active). */
  async revalidate(meta: RequestMeta): Promise<Outcome> {
    if (!this.available) return UNAVAILABLE;
    const r = await this.resolve(meta);
    if (!r) return { ...fail(401, 'unauthenticated', organizationMessages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    return ok({ organization: publicMembership(r.membership, true) });
  }

  /**
   * Switches the session to another organization of the same identity. In one transaction the old session is revoked
   * conditionally and a new session bound to the target membership is issued with the OLD absolute expiry (Sprint 3.0.1).
   * A replayed, concurrently switched, logged-out or administrator-revoked session yields 401 and no replacement; a
   * database failure rolls back both steps. Non-member, suspended, removed and inactive targets are indistinguishable.
   */
  async selectOrganization(input: unknown, meta: RequestMeta): Promise<Outcome> {
    if (!this.available) return UNAVAILABLE;
    const parsed = selectSchema.safeParse(input);
    if (!parsed.success) return fail(400, 'invalid_request', 'Choose an organization.');
    const r = await this.resolve(meta);
    if (!r) return { ...fail(401, 'unauthenticated', organizationMessages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    const now = this.deps.now();
    const target = selectableMembership(r.identity.memberships, parsed.data.organizationId);
    if (!target) {
      await r.store.audit({ eventType: 'organization_switch', outcome: 'denied', actorMemberId: r.membership.memberId, subjectMemberId: r.membership.memberId, details: { reason: 'organization_not_available' } }, now);
      return fail(403, 'organization_not_available', organizationMessages.notAvailable);
    }
    if (target.memberId === r.membership.memberId) return ok({ organization: publicMembership(target, true) });

    let targetContext: OrganizationContext;
    try {
      targetContext = organizationContextForVerifiedMembership({ organizationId: target.organizationId, workspaceId: target.organization.slug },
        { id: target.organizationId, slug: target.organization.slug, status: target.organization.status }, this.deps.capability);
    } catch { return fail(403, 'organization_not_available', organizationMessages.notAvailable); }
    const targetStore = this.deps.storeFor(targetContext);
    // Re-read the target membership inside its own tenant boundary; it must be the same, active, identity-bound member.
    const current = await r.store.findMemberById(r.membership.memberId);
    const member = await targetStore.findMemberById(target.memberId);
    if (!current?.authUserId || !member || member.status !== 'active' || member.authUserId !== current.authUserId || member.organizationId !== targetContext.organizationId) {
      await r.store.audit({ eventType: 'organization_switch', outcome: 'denied', actorMemberId: r.membership.memberId, subjectMemberId: r.membership.memberId, details: { reason: 'membership_changed' } }, now);
      return fail(403, 'organization_not_available', organizationMessages.notAvailable);
    }

    // Sprint 3.0.1 (H2, H3): one transaction. The source session is consumed conditionally (still valid, still this
    // member's, not yet revoked by anyone); only the single winner issues a replacement, and the replacement keeps the
    // source session's absolute expiry. Any failure rolls everything back, leaving the source session exactly as it was.
    const token = newSessionToken(), cfg = this.deps.session, sourceHash = sha256Hex(meta.sessionToken!);
    let switched: { absoluteExpiresAt: Date } | null;
    try {
      switched = await this.deps.transaction(async storeFor => {
        const source = storeFor(r.context), destination = storeFor(targetContext);
        const consumed = await source.consumeSession(sourceHash, r.membership.memberId, 'organization_switched', now);
        if (!consumed) return null;
        const absoluteExpiresAt = consumed.absoluteExpiresAt;
        const idleExpiresAt = new Date(Math.min(now.getTime() + cfg.idleTimeoutSeconds * 1000, absoluteExpiresAt.getTime()));
        await destination.createSession({ tokenHash: sha256Hex(token), memberId: member.id, now, idleExpiresAt, absoluteExpiresAt });
        await source.audit({ eventType: 'organization_switch', outcome: 'success', actorMemberId: r.membership.memberId, subjectMemberId: r.membership.memberId, details: { direction: 'out' } }, now);
        await destination.audit({ eventType: 'organization_switch', outcome: 'success', actorMemberId: member.id, subjectMemberId: member.id, details: { direction: 'in' } }, now);
        return { absoluteExpiresAt };
      });
    } catch {
      return fail(503, 'organization_switch_failed', organizationMessages.switchFailed);
    }
    // Lost the race, or the session was revoked or expired meanwhile: no replacement exists, and the caller is signed out.
    if (!switched) {
      await r.store.audit({ eventType: 'organization_switch', outcome: 'denied', actorMemberId: r.membership.memberId, subjectMemberId: r.membership.memberId, details: { reason: 'session_not_current' } }, now).catch(() => undefined);
      return { ...fail(401, 'unauthenticated', organizationMessages.unauthenticated), cookie: 'clear' };
    }
    const maxAge = Math.max(1, Math.floor((switched.absoluteExpiresAt.getTime() - now.getTime()) / 1000));
    return { status: 200, body: { organization: publicMembership(target, true) }, cookie: { set: token, maxAge } };
  }

  /** Seat usage of the session's organization. Administrators only. */
  async seats(meta: RequestMeta): Promise<Outcome> {
    if (!this.available) return UNAVAILABLE;
    const principal = await this.principal(meta);
    if (!principal) return { ...fail(401, 'unauthenticated', organizationMessages.unauthenticated), cookie: meta.sessionToken ? 'clear' : undefined };
    if (!organizationCan(principal, 'workspace.manage', { organizationId: principal.organizationId })) return fail(403, 'forbidden', organizationMessages.forbidden);
    const r = await this.resolve(meta);
    if (!r) return fail(401, 'unauthenticated', organizationMessages.unauthenticated);
    const tenancy = this.deps.tenancyFor(r.context);
    const entitlement = await tenancy.seatEntitlement();
    if (!entitlement) return fail(503, 'seat_entitlement_unavailable', 'Seat information is not available for this organization.');
    const now = this.deps.now();
    const usage = seatUsage(entitlement, await tenancy.seatCounts(now), now);
    return ok({ seats: { ...usage, canInvite: canReserveSeat(usage) } });
  }

  /** Organization-scoped authorization for any tenant resource (projects, time records, timesheets, billing, …). */
  async authorize(meta: RequestMeta, permission: Permission, resource: OrganizationResourceScope): Promise<boolean> {
    if (!this.available) return false;
    return organizationCan(await this.principal(meta), permission, resource);
  }
}
