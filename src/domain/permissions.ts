/** Organization membership roles. They are independent of platform privileges and can never imply one. */
export type Role = 'workspace_admin' | 'workspace_manager' | 'contractor';
/** Every organization role can be granted through the application, within the caller's authority. */
export type AssignableRole = Role;
export const ORGANIZATION_ROLES: readonly Role[] = ['workspace_admin', 'workspace_manager', 'contractor'];
export const WORKSPACE_ID = 'thrivesource' as const;
export const roleLabels: Record<Role, string> = { workspace_admin: 'Administrator', workspace_manager: 'Manager', contractor: 'Contractor' };

/**
 * Platform privileges belong to a Supabase identity, not to an organization membership. They are stored in
 * platform_privileges, granted only by the approved operator procedure, and only for the designated, verified
 * Living IT Solutions identity. The application can read them, never grant them.
 */
export type PlatformPrivilege = 'platform_super_admin';
export const platformPrivilegeLabels: Record<PlatformPrivilege, string> = { platform_super_admin: 'Platform Super Admin' };

export interface Principal {
  id: string; name: string; role: Role; workspaceId: typeof WORKSPACE_ID; assignedContractorIds: readonly string[]; approvalAuthorized: boolean;
  /** Active platform privileges of this identity. Missing means none (deny by default). */
  platformPrivileges?: readonly PlatformPrivilege[];
}
export const hasPlatformPrivilege = (user: Principal | null, privilege: PlatformPrivilege) => !!user?.platformPrivileges?.includes(privilege);

export const permissions = ['dashboard', 'tracker.own', 'dtr.own', 'timesheets.own', 'requests.own', 'directory.read', 'contractors.records', 'approvals.review', 'cutoffs.review', 'reports.read', 'workspace.manage', 'administrators.manage'] as const;
export type Permission = typeof permissions[number];
export interface ResourceScope { workspaceId: string; contractorId?: string }
const own: readonly Permission[] = ['dashboard', 'tracker.own', 'dtr.own', 'timesheets.own', 'requests.own'];
// Organization data access comes only from the organization role. Platform privileges add nothing here.
const grants: Record<Role, readonly Permission[]> = {
  workspace_admin: permissions,
  workspace_manager: ['dashboard', 'directory.read', 'contractors.records', 'approvals.review', 'cutoffs.review', 'reports.read'],
  contractor: own,
};
export interface Authorization { can(principal: Principal | null, permission: Permission, resource: ResourceScope): boolean }
/** The role-dependent part of a principal. Shared by the ThriveSource authorization below and the Sprint 3.0 organization authorization. */
export type RoleSubject = Pick<Principal, 'id' | 'role' | 'assignedContractorIds' | 'approvalAuthorized' | 'platformPrivileges'>;
/** Role rules only. Callers must first establish that the subject and the resource belong to the same organization. */
export function roleCan(user: RoleSubject, permission: Permission, contractorId: string | undefined): boolean {
  if (!Object.hasOwn(grants, user.role) || !grants[user.role].includes(permission)) return false;
  // Managing Administrators needs BOTH an Administrator membership in this organization and the platform privilege.
  if (permission === 'administrators.manage') return user.role === 'workspace_admin' && !!user.platformPrivileges?.includes('platform_super_admin');
  if (user.role === 'workspace_admin') return true;
  if (permission === 'dashboard') return true;
  if (user.role === 'contractor') return contractorId === user.id;
  if (permission === 'approvals.review' && !user.approvalAuthorized) return false;
  return !!contractorId && user.assignedContractorIds.includes(contractorId);
}
export const authorization: Authorization = {
  can(user, permission, resource) {
    if (!user || user.workspaceId !== WORKSPACE_ID || resource.workspaceId !== WORKSPACE_ID) return false;
    return roleCan(user, permission, resource.contractorId);
  },
};
// Navigation is discoverability only; every future backend request must authorize its resource.
export function canNavigate(user: Principal, permission: Permission): boolean {
  if (authorization.can(user, permission, { workspaceId: WORKSPACE_ID, contractorId: user.id })) return true;
  return user.assignedContractorIds.some(contractorId => authorization.can(user, permission, { workspaceId: WORKSPACE_ID, contractorId }));
}

/**
 * Membership authority matrix, shared by the API (authoritative) and the UI (discoverability only). The database
 * guards in 20261104130000_platform-privileges-correction.sql enforce the same rules for the runtime role.
 *   Administrator + platform_super_admin → grant, change and revoke Administrator, Manager and Contractor access
 *   Administrator                        → grant, change and revoke Manager and Contractor access only
 *   Manager, Contractor                  → nothing
 * Nobody may manage their own membership.
 */
export function assignableRoles(actor: Principal | null): readonly AssignableRole[] {
  if (!actor || actor.workspaceId !== WORKSPACE_ID || actor.role !== 'workspace_admin') return [];
  return authorization.can(actor, 'administrators.manage', { workspaceId: WORKSPACE_ID }) ? ORGANIZATION_ROLES : ['workspace_manager', 'contractor'];
}
export function canAssignRole(actor: Principal | null, role: string): boolean {
  return (assignableRoles(actor) as readonly string[]).includes(role);
}
/** Whether actor may invite again, change the role of, disable, or end the sessions of target. */
export function canManageMember(actor: Principal | null, target: { id: string; role: string }): boolean {
  return !!actor && actor.id !== target.id && canAssignRole(actor, target.role);
}
