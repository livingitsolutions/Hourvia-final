export type Role = 'workspace_admin' | 'workspace_manager' | 'contractor';
export const WORKSPACE_ID = 'thrivesource' as const;
export interface Principal { id: string; name: string; role: Role; workspaceId: typeof WORKSPACE_ID; assignedContractorIds: readonly string[]; approvalAuthorized: boolean }
export const permissions = ['dashboard', 'tracker.own', 'dtr.own', 'timesheets.own', 'requests.own', 'directory.read', 'contractors.records', 'approvals.review', 'cutoffs.review', 'reports.read', 'workspace.manage'] as const;
export type Permission = typeof permissions[number];
export interface ResourceScope { workspaceId: string; contractorId?: string }
const own: readonly Permission[] = ['dashboard', 'tracker.own', 'dtr.own', 'timesheets.own', 'requests.own'];
const grants: Record<Role, readonly Permission[]> = {
  workspace_admin: permissions,
  workspace_manager: ['dashboard', 'directory.read', 'contractors.records', 'approvals.review', 'cutoffs.review', 'reports.read'],
  contractor: own,
};
export interface Authorization { can(principal: Principal | null, permission: Permission, resource: ResourceScope): boolean }
export const authorization: Authorization = {
  can(user, permission, resource) {
    if (!user || user.workspaceId !== WORKSPACE_ID || resource.workspaceId !== WORKSPACE_ID) return false;
    if (!Object.hasOwn(grants, user.role) || !grants[user.role].includes(permission)) return false;
    if (user.role === 'workspace_admin') return true;
    if (permission === 'dashboard') return true;
    if (user.role === 'contractor') return resource.contractorId === user.id;
    if (permission === 'approvals.review' && !user.approvalAuthorized) return false;
    return !!resource.contractorId && user.assignedContractorIds.includes(resource.contractorId);
  },
};
// Navigation is discoverability only; every future backend request must authorize its resource.
export function canNavigate(user: Principal, permission: Permission): boolean {
  if (authorization.can(user, permission, { workspaceId: WORKSPACE_ID, contractorId: user.id })) return true;
  return user.assignedContractorIds.some(contractorId => authorization.can(user, permission, { workspaceId: WORKSPACE_ID, contractorId }));
}
