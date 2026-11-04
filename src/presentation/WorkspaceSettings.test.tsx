// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider } from '../application/auth';
import { assignableRoles, authorization, canManageMember, canNavigate, type Principal } from '../domain/permissions';
import type { WorkspaceAdminApi, WorkspaceMember } from '../infrastructure/server-session-auth';
import App from './App';
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const base: Principal = { id: 'sa', name: 'Living IT Solutions', role: 'workspace_admin', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false, platformPrivileges: ['platform_super_admin'] };
const superAdmin = base;
const admin: Principal = { ...base, id: 'a1', name: 'Ada Admin', platformPrivileges: [] };
const manager: Principal = { ...base, id: 'm1', role: 'workspace_manager', platformPrivileges: [] };
const members: WorkspaceMember[] = [
  { id: 'sa', email: 'livingitsolutions@gmail.com', name: 'Living IT Solutions', role: 'workspace_admin', status: 'active', createdAt: '2026-11-04T00:00:00Z' },
  { id: 'a1', email: 'ada@t.test', name: 'Ada Admin', role: 'workspace_admin', status: 'active', createdAt: '2026-11-04T00:00:00Z' },
  { id: 'a2', email: 'bo@t.test', name: 'Bo Admin', role: 'workspace_admin', status: 'active', createdAt: '2026-11-04T00:00:00Z' },
  { id: 'c1', email: 'cy@t.test', name: 'Cy Contractor', role: 'contractor', status: 'active', createdAt: '2026-11-04T00:00:00Z' },
];
function fakeAdmin(): WorkspaceAdminApi & { changeRole: ReturnType<typeof vi.fn> } {
  return { listMembers: vi.fn(async () => members), invite: vi.fn(), disable: vi.fn(async () => undefined), revokeSessions: vi.fn(async () => undefined), changeRole: vi.fn(async () => members[3]!) } as never;
}
function mount(user: Principal, api = fakeAdmin()) {
  render(<MemoryRouter initialEntries={['/settings']}><AuthProvider service={{ getSession: async () => user, signIn: async () => user, signOut: async () => {} }} admin={api}><App/></AuthProvider></MemoryRouter>);
  return api;
}
const options = (select: HTMLElement) => within(select).getAllByRole('option').map(o => (o as HTMLOptionElement).value);
const row = (email: string) => screen.getByText(email).closest('li')!;

describe('role policy', () => {
  it('encodes the authorization matrix from the organization role plus the platform privilege', () => {
    expect(assignableRoles(superAdmin)).toEqual(['workspace_admin', 'workspace_manager', 'contractor']);
    expect(assignableRoles(admin)).toEqual(['workspace_manager', 'contractor']);
    expect(assignableRoles(manager)).toEqual([]);
    expect(assignableRoles({ ...manager, platformPrivileges: ['platform_super_admin'] })).toEqual([]); // no membership authority, no management
    expect(assignableRoles({ ...base, role: 'contractor' })).toEqual([]);
    expect(canManageMember(superAdmin, { id: 'a2', role: 'workspace_admin' })).toBe(true);
    expect(canManageMember(admin, { id: 'a2', role: 'workspace_admin' })).toBe(false);
    expect(canManageMember(admin, { id: 'sa', role: 'workspace_admin' })).toBe(false);
    expect(canManageMember(admin, { id: 'c1', role: 'contractor' })).toBe(true);
    expect(canManageMember(superAdmin, { id: 'sa', role: 'workspace_admin' })).toBe(false); // never yourself
    expect(canNavigate(superAdmin, 'administrators.manage')).toBe(true);
    expect(canNavigate(admin, 'administrators.manage')).toBe(false);
    expect(authorization.can(superAdmin, 'workspace.manage', { workspaceId: 'other' })).toBe(false); // no cross-organization access
    expect(authorization.can({ ...manager, platformPrivileges: ['platform_super_admin'] }, 'contractors.records', { workspaceId: 'thrivesource', contractorId: 'c9' })).toBe(false);
  });
});

describe('Workspace Settings', () => {
  it('lets the platform-privileged Administrator invite and manage Administrators, and shows the privilege separately', async () => {
    const api = mount(superAdmin);
    await screen.findByText('bo@t.test');
    expect(screen.getAllByText('Platform Super Admin').length).toBeGreaterThan(0); // sidebar badge and banner
    expect(options(screen.getByLabelText('Role'))).toEqual(['workspace_admin', 'workspace_manager', 'contractor']);
    expect(within(row('livingitsolutions@gmail.com')).queryByRole('button')).toBeNull(); // own row
    expect(within(row('bo@t.test')).getByRole('button', { name: 'Revoke access' })).toBeTruthy();
    expect(options(screen.getByLabelText('Role for bo@t.test'))).not.toContain('platform_super_admin');
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    fireEvent.change(screen.getByLabelText('Role for bo@t.test'), { target: { value: 'workspace_manager' } });
    await vi.waitFor(() => expect(api.changeRole).toHaveBeenCalledWith('a2', 'workspace_manager'));
  });
  it('limits ordinary Administrators to Managers and Contractors', async () => {
    mount(admin);
    await screen.findByText('bo@t.test');
    expect(screen.queryByText('Platform Super Admin')).toBeNull();
    expect(screen.getAllByText('Administrator').length).toBeGreaterThan(0);
    expect(options(screen.getByLabelText('Role'))).toEqual(['workspace_manager', 'contractor']);
    for (const email of ['livingitsolutions@gmail.com', 'ada@t.test', 'bo@t.test']) expect(within(row(email)).queryByRole('button')).toBeNull();
    expect(options(screen.getByLabelText('Role for cy@t.test'))).toEqual(['workspace_manager', 'contractor']);
    expect(within(row('cy@t.test')).getByRole('button', { name: 'Disable' })).toBeTruthy();
  });
  it('is not available to Managers, even with the platform privilege', async () => {
    mount({ ...manager, platformPrivileges: ['platform_super_admin'] });
    expect(await screen.findByRole('heading', { name: 'This page isn’t available to you.' })).toBeTruthy();
  });
});
