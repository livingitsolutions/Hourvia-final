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
  readonly legacyWorkspaceId: typeof THRIVESOURCE_LEGACY_WORKSPACE_ID;
  /** 'system': pre-authentication flows (login, recovery, invitation acceptance) in the single supported organization. */
  readonly source: 'membership' | 'system';
}

export class OrganizationContextError extends Error {
  constructor(reason: 'invalid_organization' | 'unsupported_organization' | 'workspace_mismatch') {
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
