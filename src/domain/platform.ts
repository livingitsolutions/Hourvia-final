import { WORKSPACE_ID, type PlatformPrivilege, type Principal } from './permissions';

/**
 * Platform plane authorization (Sprint 1.8). Separate from, and never derived from, organization permissions:
 * it reads only the principal's active platform privileges, which the server loads from platform_privileges on
 * every request. The organization role is deliberately ignored, so a workspace role can never grant a platform
 * permission, and a platform privilege adds nothing to the workspace `authorization` matrix. Deny by default.
 *
 * The principal still has to be an authenticated ThriveSource session: a holder whose membership is disabled has
 * no session, so platform access fails closed. The auth API service and the database
 * (hourvia_platform_* functions in 20261104150000) re-check independently; the UI uses this only to decide what to show.
 */
export const PLATFORM_PRIVILEGES: readonly PlatformPrivilege[] = ['platform_super_admin'];
export const platformPermissions = ['platform.console', 'platform.overview.read', 'platform.audit.read'] as const;
export type PlatformPermission = typeof platformPermissions[number];

const platformGrants: Readonly<Record<PlatformPrivilege, readonly PlatformPermission[]>> = {
  platform_super_admin: platformPermissions,
};

export const isPlatformPrivilege = (value: unknown): value is PlatformPrivilege =>
  typeof value === 'string' && (PLATFORM_PRIVILEGES as readonly string[]).includes(value);
export const isPlatformPermission = (value: unknown): value is PlatformPermission =>
  typeof value === 'string' && (platformPermissions as readonly string[]).includes(value);

export const platformAuthorization = {
  can(principal: Principal | null, permission: PlatformPermission): boolean {
    if (!principal || principal.workspaceId !== WORKSPACE_ID || !isPlatformPermission(permission)) return false;
    const held: readonly unknown[] = Array.isArray(principal.platformPrivileges) ? principal.platformPrivileges : [];
    return held.some(privilege => isPlatformPrivilege(privilege) && Object.hasOwn(platformGrants, privilege) && platformGrants[privilege].includes(permission));
  },
};

// ---------- Read-only API contract shared by /api/platform/* and the console ----------
export const PLATFORM_AUDIT_DEFAULT_LIMIT = 25;
export const PLATFORM_AUDIT_MAX_LIMIT = 100;

export interface PlatformOverview {
  grant: { privilege: PlatformPrivilege; grantedAt: string; approvalRef: string };
  designatedAt: string | null;
  grantHistory: { granted: number; revoked: number };
  /** Aggregate counts only, ThriveSource only. No member identities and no other tenant. */
  organizations: readonly {
    id: string;
    members: { active: number; invited: number; disabled: number };
    activeRoles: { workspace_admin: number; workspace_manager: number; contractor: number };
  }[];
  audit: { events: number; lastEventAt: string | null };
}

export type PlatformAuditDetail = string | number | boolean | null;
export interface PlatformAuditEvent {
  id: number;
  occurredAt: string;
  eventType: string;
  outcome: 'success' | 'denied' | 'error';
  /** Whether the event concerns the signed-in holder; other identities are shown only by a 4-character suffix. */
  subjectIsHolder: boolean;
  subjectSuffix: string | null;
  details: Readonly<Record<string, PlatformAuditDetail>>;
}
export interface PlatformAuditPage { events: readonly PlatformAuditEvent[]; hasMore: boolean; nextBefore: number | null }
