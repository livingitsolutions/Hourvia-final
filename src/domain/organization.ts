/**
 * Organization domain foundation (Sprint 2.0B, migration M7 20261104170000_organizations-expand.sql).
 *
 * Hourvia is still single-tenant in this sprint: ThriveSource is the only organization, and every server-side
 * organization context resolves to it. The types below exist so that Sprint 2.0C can make the organization
 * session-derived without retyping every call site, and so that an unchecked string can never be used where an
 * organization identifier is expected.
 */

declare const organizationIdBrand: unique symbol;
/** A validated, lower-case organization UUID. Obtain one only through parseOrganizationId or a constant below. */
export type OrganizationId = string & { readonly [organizationIdBrand]: 'OrganizationId' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Parses an untrusted value. Anything that is not a canonical lower-case UUID string is rejected (null). */
export function parseOrganizationId(value: unknown): OrganizationId | null {
  return typeof value === 'string' && UUID.test(value) ? (value as OrganizationId) : null;
}
export const isOrganizationId = (value: unknown): value is OrganizationId => parseOrganizationId(value) !== null;

/**
 * The permanent identifier of the ThriveSource organization. It is seeded by M7, used as the column default on every
 * tenant table, and documented in docs/architecture.md. It must never change.
 */
export const THRIVESOURCE_ORGANIZATION_ID = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6' as OrganizationId;
export const THRIVESOURCE_ORGANIZATION_SLUG = 'thrivesource' as const;
/** The legacy text tenant key still stored in workspace_id (CHECK (workspace_id = 'thrivesource') stays in 2.0B). */
export const THRIVESOURCE_LEGACY_WORKSPACE_ID = 'thrivesource' as const;

export const ORGANIZATION_KINDS = ['internal', 'customer'] as const;
export type OrganizationKind = typeof ORGANIZATION_KINDS[number];
export const ORGANIZATION_STATUSES = ['provisioning', 'active', 'suspended', 'closed'] as const;
export type OrganizationStatus = typeof ORGANIZATION_STATUSES[number];

/** Mirrors the organizations table. The runtime role can read only id, slug, name, kind and status. */
export interface Organization {
  id: OrganizationId;
  slug: string;
  name: string;
  kind: OrganizationKind;
  status: OrganizationStatus;
}
export interface OrganizationAdministrativeRecord extends Organization {
  createdAt: Date;
  createdByAuthUserId: string | null;
  suspendedAt: Date | null;
  suspendedReason: string | null;
}

/**
 * Organizations the server may build a context for in this sprint. Sprint 2.0C replaces this allowlist with a
 * session-bound membership lookup. A client-supplied organization identifier is never consulted.
 */
export const SUPPORTED_ORGANIZATION_IDS: readonly OrganizationId[] = [THRIVESOURCE_ORGANIZATION_ID];

declare const organizationContextBrand: unique symbol;
/**
 * The organization every tenant query of one request is scoped to. It is created on the server only, from the
 * authenticated session's membership (or, before authentication, from the single supported organization). It is
 * frozen and branded, so it cannot be built from request data with an object literal.
 */
export interface OrganizationContext {
  readonly [organizationContextBrand]: true;
  readonly organizationId: OrganizationId;
  /** The organization's immutable slug, still stored as workspace_id ('thrivesource' for ThriveSource). */
  readonly legacyWorkspaceId: string;
  /** 'system': pre-authentication flows (login, recovery, invitation acceptance) in the single supported organization. */
  readonly source: 'membership' | 'system';
}

export class OrganizationContextError extends Error {
  constructor(reason: 'invalid_organization' | 'unsupported_organization' | 'workspace_mismatch' | 'multi_organization_unavailable' | 'organization_inactive') {
    super(`organization_context_rejected:${reason}`);
    this.name = 'OrganizationContextError';
  }
}

function makeContext(organizationId: unknown, legacyWorkspaceId: unknown, source: OrganizationContext['source']): OrganizationContext {
  const id = parseOrganizationId(organizationId);
  if (!id) throw new OrganizationContextError('invalid_organization');
  if (!SUPPORTED_ORGANIZATION_IDS.includes(id)) throw new OrganizationContextError('unsupported_organization');
  if (legacyWorkspaceId !== THRIVESOURCE_LEGACY_WORKSPACE_ID) throw new OrganizationContextError('workspace_mismatch');
  return Object.freeze({ organizationId: id, legacyWorkspaceId: THRIVESOURCE_LEGACY_WORKSPACE_ID, source }) as OrganizationContext;
}

/** Fails closed (throws) unless the membership row belongs to a supported organization and its legacy workspace agrees. */
export function organizationContextForMembership(member: { organizationId: unknown; workspaceId: unknown }): OrganizationContext {
  return makeContext(member.organizationId, member.workspaceId, 'membership');
}

/** The context used before a session exists. In Sprint 2.0B this is always ThriveSource. */
export const THRIVESOURCE_SYSTEM_CONTEXT: OrganizationContext = makeContext(THRIVESOURCE_ORGANIZATION_ID, THRIVESOURCE_LEGACY_WORKSPACE_ID, 'system');

/** Whether a membership-derived value matches the context (a plain comparison that cannot be satisfied by a non-UUID). */
export const belongsToOrganization = (context: OrganizationContext, organizationId: unknown) =>
  parseOrganizationId(organizationId) === context.organizationId;

// ---------- Sprint 3.0: multi-organization contexts (available only with M8 and an explicit capability) ----------

/** Mirrors the organizations.slug CHECK. */
export const ORGANIZATION_SLUG = /^[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])$/;

declare const capabilityBrand: unique symbol;
/**
 * Proof that the multi-organization schema (M8) is present and verified. Without it no context for an organization
 * other than ThriveSource can be built, so every multi-organization path fails closed. Production never holds one in
 * Sprint 3.0: M8 is a proposal, and the production evidence gate pins exactly M1-M7.
 */
export interface MultiOrganizationCapability { readonly [capabilityBrand]: true; readonly schema: 'm8' }
const minted = new WeakSet<object>();
/** Sprint 3.0 production status of multi-organization features. */
export const MULTI_ORGANIZATION_AVAILABILITY = { available: false, reason: 'm8_not_applied' } as const;
/**
 * Mints a capability for offline tests against a disposable database with the M8 proposal applied. Imported only by
 * the offline multi-organization tests (a source-scan test enforces this). Promotion of M8 must replace it with an evidence-bound check.
 */
export function mintMultiOrganizationCapabilityForOfflineTests(): MultiOrganizationCapability {
  const capability = Object.freeze({ schema: 'm8' }) as MultiOrganizationCapability;
  minted.add(capability);
  return capability;
}
export const isMultiOrganizationCapability = (value: unknown): value is MultiOrganizationCapability =>
  typeof value === 'object' && value !== null && minted.has(value);

/**
 * Builds a membership context for ANY organization, from rows the server read itself: the membership and its
 * organization must agree on id and slug, the organization must be active, and a capability must be presented.
 * Client input is never an argument here; callers pass database rows only.
 */
export function organizationContextForVerifiedMembership(
  member: { organizationId: unknown; workspaceId: unknown },
  organization: { id: unknown; slug: unknown; status: unknown },
  capability: unknown,
): OrganizationContext {
  if (!isMultiOrganizationCapability(capability)) throw new OrganizationContextError('multi_organization_unavailable');
  const id = parseOrganizationId(member.organizationId);
  if (!id || parseOrganizationId(organization.id) !== id) throw new OrganizationContextError('invalid_organization');
  if (typeof organization.slug !== 'string' || !ORGANIZATION_SLUG.test(organization.slug) || member.workspaceId !== organization.slug
    || (id === THRIVESOURCE_ORGANIZATION_ID) !== (organization.slug === THRIVESOURCE_ORGANIZATION_SLUG)) {
    throw new OrganizationContextError('workspace_mismatch');
  }
  if (organization.status !== 'active') throw new OrganizationContextError('organization_inactive');
  return Object.freeze({ organizationId: id, legacyWorkspaceId: organization.slug, source: 'membership' }) as OrganizationContext;
}
