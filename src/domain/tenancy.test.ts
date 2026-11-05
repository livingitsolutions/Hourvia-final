// SPRINT 3.0: pure tenancy rules (no database). Seat accounting, membership selection, tenant resources, authorization.
import { describe, expect, it } from 'vitest';
import {
  OrganizationContextError, THRIVESOURCE_ORGANIZATION_ID, THRIVESOURCE_SYSTEM_CONTEXT, isMultiOrganizationCapability,
  mintMultiOrganizationCapabilityForOfflineTests, organizationContextForMembership, organizationContextForVerifiedMembership,
  MULTI_ORGANIZATION_AVAILABILITY, type OrganizationId,
} from './organization';
import { authorization, type Principal } from './permissions';
import {
  CrossTenantAccessError, assertTenantResource, canReserveSeat, countSeats, organizationCan, scopeTenantResources, seatUsage,
  selectableMembership, type OrganizationMembership, type OrganizationPrincipal,
} from './tenancy';

const TS = THRIVESOURCE_ORGANIZATION_ID;
const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const now = new Date('2026-11-05T12:00:00Z');
const later = new Date(now.getTime() + 3600_000), earlier = new Date(now.getTime() - 1);
const cap = mintMultiOrganizationCapabilityForOfflineTests();
const acme = organizationContextForVerifiedMembership({ organizationId: ACME, workspaceId: 'acme' }, { id: ACME, slug: 'acme', status: 'active' }, cap);

describe('multi-organization availability', () => {
  it('is unavailable in Sprint 3.0 production, and contexts outside ThriveSource need a minted capability', () => {
    expect(MULTI_ORGANIZATION_AVAILABILITY).toEqual({ available: false, reason: 'm8_not_applied' });
    const args = [{ organizationId: ACME, workspaceId: 'acme' }, { id: ACME, slug: 'acme', status: 'active' }] as const;
    for (const forged of [null, undefined, {}, { schema: 'm8' }, Object.freeze({ schema: 'm8' })]) {
      expect(isMultiOrganizationCapability(forged)).toBe(false);
      expect(() => organizationContextForVerifiedMembership(...args, forged)).toThrow(/multi_organization_unavailable/);
    }
    // The Sprint 2.0B path still refuses any organization other than ThriveSource.
    expect(() => organizationContextForMembership({ organizationId: ACME, workspaceId: 'acme' })).toThrow(OrganizationContextError);
    expect(THRIVESOURCE_SYSTEM_CONTEXT.organizationId).toBe(TS);
  });
  it('a verified context requires agreeing ids and slugs, an active organization, and the permanent ThriveSource binding', () => {
    expect(acme).toMatchObject({ organizationId: ACME, legacyWorkspaceId: 'acme', source: 'membership' });
    expect(Object.isFrozen(acme)).toBe(true);
    const bad: [{ organizationId: unknown; workspaceId: unknown }, { id: unknown; slug: unknown; status: unknown }, RegExp][] = [
      [{ organizationId: ACME, workspaceId: 'acme' }, { id: TS, slug: 'acme', status: 'active' }, /invalid_organization/],
      [{ organizationId: ACME, workspaceId: 'other' }, { id: ACME, slug: 'acme', status: 'active' }, /workspace_mismatch/],
      [{ organizationId: ACME, workspaceId: 'thrivesource' }, { id: ACME, slug: 'thrivesource', status: 'active' }, /workspace_mismatch/],
      [{ organizationId: TS, workspaceId: 'ts' }, { id: TS, slug: 'ts', status: 'active' }, /workspace_mismatch/],
      [{ organizationId: ACME, workspaceId: 'Acme' }, { id: ACME, slug: 'Acme', status: 'active' }, /workspace_mismatch/],
      [{ organizationId: ACME, workspaceId: 'acme' }, { id: ACME, slug: 'acme', status: 'suspended' }, /organization_inactive/],
      [{ organizationId: ACME.toUpperCase(), workspaceId: 'acme' }, { id: ACME.toUpperCase(), slug: 'acme', status: 'active' }, /invalid_organization/],
    ];
    for (const [m, o, error] of bad) expect(() => organizationContextForVerifiedMembership(m, o, cap)).toThrow(error);
  });
});

describe('seat accounting', () => {
  const members = [
    { id: 'a', organizationId: ACME, status: 'active' as const }, { id: 'b', organizationId: ACME, status: 'active' as const },
    { id: 'c', organizationId: ACME, status: 'invited' as const }, { id: 'd', organizationId: ACME, status: 'invited' as const },
    { id: 'e', organizationId: ACME, status: 'invited' as const }, { id: 's', organizationId: ACME, status: 'suspended' as const },
    { id: 'x', organizationId: ACME, status: 'disabled' as const }, { id: 'o', organizationId: TS, status: 'active' as const },
  ];
  const invitations = [
    { memberId: 'c', organizationId: ACME, status: 'pending' as const, expiresAt: later },
    { memberId: 'd', organizationId: ACME, status: 'pending' as const, expiresAt: earlier },
    { memberId: 'e', organizationId: ACME, status: 'revoked' as const, expiresAt: later },
    { memberId: 'x', organizationId: ACME, status: 'pending' as const, expiresAt: later },
    { memberId: 'o', organizationId: TS, status: 'pending' as const, expiresAt: later },
  ];
  it('active consume; pending unexpired invitations reserve; invited, suspended, disabled and other organizations do not', () => {
    expect(countSeats(ACME, members, invitations, now)).toEqual({ activeMembers: 2, pendingInvitations: 1 });
    expect(countSeats(TS, members, invitations, now)).toEqual({ activeMembers: 1, pendingInvitations: 0 });
  });
  it('computes availability, expiry and the reservation decision', () => {
    const standard = { organizationId: ACME, plan: 'standard' as const, seatLimit: 4, billingExpiresAt: null };
    const usage = seatUsage(standard, { activeMembers: 2, pendingInvitations: 1 }, now);
    expect(usage).toMatchObject({ consumed: 3, limit: 4, available: 1, expired: false });
    expect(canReserveSeat(usage)).toBe(true);
    expect(canReserveSeat(seatUsage(standard, { activeMembers: 3, pendingInvitations: 1 }, now))).toBe(false);
    const expired = seatUsage({ ...standard, billingExpiresAt: earlier }, { activeMembers: 0, pendingInvitations: 0 }, now);
    expect(expired).toMatchObject({ expired: true, available: 0 });
    expect(canReserveSeat(expired)).toBe(false);
    expect(canReserveSeat(seatUsage({ ...standard, seatLimit: null }, { activeMembers: 0, pendingInvitations: 0 }, now))).toBe(false);
  });
  it('ThriveSource internal_unlimited is unlimited and never expires', () => {
    const usage = seatUsage({ organizationId: TS, plan: 'internal_unlimited', seatLimit: null, billingExpiresAt: null }, { activeMembers: 5000, pendingInvitations: 40 }, now);
    expect(usage).toMatchObject({ limit: null, available: null, expired: false, consumed: 5040 });
    expect(canReserveSeat(usage)).toBe(true);
  });
});

describe('membership selection and tenant resources', () => {
  const m = (organizationId: OrganizationId, status: OrganizationMembership['status'], orgStatus: OrganizationMembership['organization']['status'] = 'active'): OrganizationMembership =>
    ({ memberId: `${organizationId}-${status}`, organizationId, role: 'contractor', status, organization: { slug: 's', name: 'n', kind: 'customer', status: orgStatus } });
  it('only an active membership of an active organization the identity holds can be selected', () => {
    expect(selectableMembership([m(TS, 'active'), m(ACME, 'active')], ACME)?.organizationId).toBe(ACME);
    for (const [list, requested] of [
      [[m(ACME, 'suspended')], ACME], [[m(ACME, 'disabled')], ACME], [[m(ACME, 'active', 'suspended')], ACME],
      [[m(TS, 'active')], ACME], [[m(ACME, 'active')], ACME.toUpperCase()], [[m(ACME, 'active')], { id: ACME }], [[m(ACME, 'active'), m(ACME, 'active')], ACME],
    ] as const) expect(selectableMembership(list, requested)).toBeNull();
  });
  it('tenant resources outside the context are rejected and filtered', () => {
    expect(assertTenantResource(acme, 'project', { organizationId: ACME, id: 'p' })).toEqual({ organizationId: ACME, id: 'p' });
    for (const r of [{ organizationId: TS }, { organizationId: 'acme' }, { organizationId: null }, null]) {
      expect(() => assertTenantResource(acme, 'timesheet', r)).toThrow(CrossTenantAccessError);
    }
    expect(scopeTenantResources(acme, [{ organizationId: ACME, n: 1 }, { organizationId: TS, n: 2 }])).toEqual([{ organizationId: ACME, n: 1 }]);
  });
});

describe('organization-scoped authorization', () => {
  const admin: OrganizationPrincipal = { id: 'a', organizationId: ACME, role: 'workspace_admin', assignedContractorIds: [], approvalAuthorized: false, platformPrivileges: [] };
  const contractor: OrganizationPrincipal = { ...admin, id: 'c', role: 'contractor' };
  it('requires the same organization, then applies the unchanged role rules', () => {
    expect(organizationCan(admin, 'workspace.manage', { organizationId: ACME })).toBe(true);
    expect(organizationCan(admin, 'workspace.manage', { organizationId: TS })).toBe(false);
    expect(organizationCan(admin, 'administrators.manage', { organizationId: ACME })).toBe(false);
    expect(organizationCan(contractor, 'timesheets.own', { organizationId: ACME, contractorId: 'c' })).toBe(true);
    expect(organizationCan(contractor, 'timesheets.own', { organizationId: ACME, contractorId: 'other' })).toBe(false);
    expect(organizationCan(contractor, 'workspace.manage', { organizationId: ACME })).toBe(false);
    expect(organizationCan(null, 'dashboard', { organizationId: ACME })).toBe(false);
    expect(organizationCan({ ...admin, organizationId: 'acme' as OrganizationId }, 'dashboard', { organizationId: 'acme' })).toBe(false);
  });
  it('an organization role never implies a platform privilege, and the ThriveSource authorization is unchanged', () => {
    expect(organizationCan({ ...admin, platformPrivileges: ['platform_super_admin'] }, 'administrators.manage', { organizationId: ACME })).toBe(true);
    const p: Principal = { id: 'a', name: 'A', role: 'workspace_admin', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false };
    expect(authorization.can(p, 'workspace.manage', { workspaceId: 'thrivesource' })).toBe(true);
    expect(authorization.can(p, 'administrators.manage', { workspaceId: 'thrivesource' })).toBe(false);
    expect(authorization.can(p, 'workspace.manage', { workspaceId: 'acme' })).toBe(false);
  });
});
