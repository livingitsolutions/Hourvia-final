/**
 * Sprint 3.0 organization-first tenancy contracts (pure domain logic; no I/O).
 *
 * Hourvia is organization-first: every workspace belongs to an organization and there are no personal workspaces. A
 * global Supabase identity can hold one membership per organization, each with its own role and status. All of this
 * depends on migration M8 (db/proposals/sprint-3.0/), which is NOT applied in Sprint 3.0, so the server keeps every
 * multi-organization path unavailable (see MULTI_ORGANIZATION_AVAILABILITY in organization.ts).
 */
import { parseOrganizationId, type OrganizationContext, type OrganizationId, type OrganizationKind, type OrganizationStatus } from './organization';
import { roleCan, type Permission, type PlatformPrivilege, type Role } from './permissions';

// ---------- Memberships ----------
/** 'disabled' is the deactivated (removed) state; 'suspended' is reversible by an operator only. */
export const MEMBERSHIP_STATUSES = ['invited', 'active', 'suspended', 'disabled'] as const;
export type MembershipStatus = typeof MEMBERSHIP_STATUSES[number];

/** One membership of the signed-in identity, as listed for organization selection. */
export interface OrganizationMembership {
  memberId: string;
  organizationId: OrganizationId;
  organization: { slug: string; name: string; kind: OrganizationKind; status: OrganizationStatus };
  role: Role;
  status: MembershipStatus;
}
/** A membership grants access only while both the membership and its organization are active. */
export const membershipGrantsAccess = (m: Pick<OrganizationMembership, 'status' | 'organization'>) =>
  m.status === 'active' && m.organization.status === 'active';

/**
 * Picks the membership for a requested organization. The request value is untrusted: it is parsed, and only a
 * membership the server read for the session's own identity can match. Unknown, malformed, suspended, removed or
 * inactive all yield null, so callers cannot tell them apart (no membership enumeration).
 */
export function selectableMembership(memberships: readonly OrganizationMembership[], requested: unknown): OrganizationMembership | null {
  const id = parseOrganizationId(requested);
  if (!id) return null;
  const matches = memberships.filter(m => m.organizationId === id);
  return matches.length === 1 && membershipGrantsAccess(matches[0]!) ? matches[0]! : null;
}

// ---------- Tenant-owned resources ----------
/** Resource kinds that are organization-owned. Future tables for them must carry organization_id (see tenant-sql.ts). */
export const TENANT_RESOURCE_KINDS = ['membership', 'invitation', 'project', 'time_record', 'timesheet', 'billing_record'] as const;
export type TenantResourceKind = typeof TENANT_RESOURCE_KINDS[number];
export interface TenantOwned { organizationId: unknown }

export class CrossTenantAccessError extends Error {
  constructor(readonly kind: TenantResourceKind) { super(`cross_tenant_access_denied:${kind}`); this.name = 'CrossTenantAccessError'; }
}
/** Throws unless the resource belongs to the context's organization. Malformed or missing ids always fail. */
export function assertTenantResource<T extends TenantOwned>(context: OrganizationContext, kind: TenantResourceKind, resource: T | null | undefined): T {
  if (!resource || parseOrganizationId(resource.organizationId) !== context.organizationId) throw new CrossTenantAccessError(kind);
  return resource;
}
/** Keeps only the context's rows; a defence in depth on top of the SQL predicates, never a replacement for them. */
export const scopeTenantResources = <T extends TenantOwned>(context: OrganizationContext, rows: readonly T[]) =>
  rows.filter(r => parseOrganizationId(r.organizationId) === context.organizationId);

// ---------- Organization-scoped authorization ----------
/** A principal bound to exactly one organization by the server (from the session's membership). */
export interface OrganizationPrincipal {
  id: string;
  organizationId: OrganizationId;
  role: Role;
  assignedContractorIds: readonly string[];
  approvalAuthorized: boolean;
  /** Read from platform_privileges by verified identity. Organization roles never produce one. */
  platformPrivileges: readonly PlatformPrivilege[];
}
export interface OrganizationResourceScope { organizationId: unknown; contractorId?: string }
/** Same role rules as the ThriveSource authorization, plus a strict same-organization requirement. */
export function organizationCan(principal: OrganizationPrincipal | null, permission: Permission, resource: OrganizationResourceScope): boolean {
  if (!principal || !parseOrganizationId(principal.organizationId)) return false;
  if (parseOrganizationId(resource.organizationId) !== principal.organizationId) return false;
  return roleCan(principal, permission, resource.contractorId);
}

// ---------- Seat entitlements ----------
export const SEAT_PLANS = ['internal_unlimited', 'standard'] as const;
export type SeatPlan = typeof SEAT_PLANS[number];
export interface SeatEntitlement {
  organizationId: OrganizationId;
  plan: SeatPlan;
  /** null only for internal_unlimited (ThriveSource). */
  seatLimit: number | null;
  billingExpiresAt: Date | null;
}
export interface SeatCounts { activeMembers: number; pendingInvitations: number }
export interface SeatUsage extends SeatCounts {
  organizationId: OrganizationId;
  plan: SeatPlan;
  consumed: number;
  limit: number | null;
  /** null means unlimited. */
  available: number | null;
  expired: boolean;
}

/** Rows used to count seats. The SQL path counts the same thing in the database; both must agree. */
export interface SeatMemberRow { id: string; organizationId: unknown; status: MembershipStatus }
export interface SeatInvitationRow { memberId: string; organizationId: unknown; status: 'pending' | 'accepted' | 'revoked'; expiresAt: Date }

/**
 * Seat rule: active members consume seats; pending, unexpired invitations to invited members reserve seats; invited
 * members without a pending invitation, suspended and disabled members consume nothing. Rows of other organizations
 * are ignored, so memberships in different organizations are counted independently.
 */
export function countSeats(organizationId: OrganizationId, members: readonly SeatMemberRow[], invitations: readonly SeatInvitationRow[], now: Date): SeatCounts {
  const own = members.filter(m => parseOrganizationId(m.organizationId) === organizationId);
  const invited = new Set(own.filter(m => m.status === 'invited').map(m => m.id));
  const reserving = new Set(invitations
    .filter(i => parseOrganizationId(i.organizationId) === organizationId && i.status === 'pending' && i.expiresAt.getTime() > now.getTime() && invited.has(i.memberId))
    .map(i => i.memberId));
  return { activeMembers: own.filter(m => m.status === 'active').length, pendingInvitations: reserving.size };
}

export function seatUsage(entitlement: SeatEntitlement, counts: SeatCounts, now: Date): SeatUsage {
  const consumed = counts.activeMembers + counts.pendingInvitations;
  const unlimited = entitlement.plan === 'internal_unlimited';
  const expired = !unlimited && entitlement.billingExpiresAt !== null && entitlement.billingExpiresAt.getTime() <= now.getTime();
  const limit = unlimited ? null : entitlement.seatLimit;
  return {
    organizationId: entitlement.organizationId, plan: entitlement.plan, ...counts, consumed, limit, expired,
    available: limit === null ? null : expired ? 0 : Math.max(0, limit - consumed),
  };
}
/** Whether one more seat (a new pending invitation or an activation) can be taken. Fails closed for a malformed entitlement. */
export function canReserveSeat(usage: SeatUsage): boolean {
  if (usage.plan === 'internal_unlimited') return usage.limit === null;
  return !usage.expired && usage.limit !== null && Number.isInteger(usage.limit) && usage.limit > 0 && usage.consumed < usage.limit;
}
