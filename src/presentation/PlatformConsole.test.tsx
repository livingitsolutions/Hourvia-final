// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider } from '../application/auth';
import type { Principal } from '../domain/permissions';
import type { PlatformAuditEvent, PlatformOverview } from '../domain/platform';
import { AuthRequestError, createPlatformApi, type PlatformApi } from '../infrastructure/server-session-auth';
import App from './App';
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const holder: Principal = { id: 'sa', name: 'Living IT Solutions', role: 'workspace_admin', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false, platformPrivileges: ['platform_super_admin'] };
const admin: Principal = { ...holder, id: 'a1', name: 'Ada Admin', platformPrivileges: [] };
const manager: Principal = { ...holder, id: 'm1', name: 'Max Manager', role: 'workspace_manager', platformPrivileges: [] };
const contractor: Principal = { ...holder, id: 'c1', name: 'Cy Contractor', role: 'contractor', platformPrivileges: [] };
const forged = { ...admin, platformPrivileges: ['platform_owner', 'super_admin'] } as unknown as Principal;

const overview: PlatformOverview = {
  grant: { privilege: 'platform_super_admin', grantedAt: '2026-11-04T01:00:00.000Z', approvalRef: 'CHG-2026-1104' },
  designatedAt: '2026-11-04T01:00:00.000Z', grantHistory: { granted: 1, revoked: 0 },
  organizations: [{ id: 'thrivesource', members: { active: 7, invited: 2, disabled: 1 }, activeRoles: { workspace_admin: 2, workspace_manager: 2, contractor: 3 } }],
  audit: { events: 3, lastEventAt: '2026-11-04T02:00:00.000Z' },
};
const ev = (id: number, eventType: string): PlatformAuditEvent => ({ id, occurredAt: '2026-11-04T01:00:00.000Z', eventType, outcome: 'success', subjectIsHolder: true, subjectSuffix: 'abcd', details: { source: 'operator_sql', approval_ref: 'CHG-2026-1104' } });
function fakePlatform(overrides: Partial<PlatformApi> = {}): PlatformApi & { overview: ReturnType<typeof vi.fn>; audit: ReturnType<typeof vi.fn> } {
  return {
    overview: vi.fn(async () => overview),
    audit: vi.fn(async ({ before }: { before?: number | null } = {}) => before ? { events: [ev(1, 'platform_designation_set')], hasMore: false, nextBefore: null } : { events: [ev(3, 'platform_audit_read'), ev(2, 'platform_privilege_granted')], hasMore: true, nextBefore: 2 }),
    ...overrides,
  } as never;
}
function mount(path: string, user: Principal, platform = fakePlatform()) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider service={{ getSession: async () => user, signIn: async () => user, signOut: async () => {} }} platform={platform}><App/></AuthProvider></MemoryRouter>);
  return platform;
}

describe('Platform navigation', () => {
  it('shows a separate Platform group to the Platform Super Admin', async () => {
    mount('/dashboard', holder);
    await screen.findByRole('heading', { name: 'Dashboard' });
    const nav = screen.getByRole('navigation', { name: 'Platform navigation' });
    expect(nav.textContent).toContain('Platform Overview');
    expect(nav.textContent).toContain('Platform Audit');
    expect(screen.getByRole('navigation', { name: 'Workspace navigation' }).textContent).not.toContain('Platform');
  });
  it('is absent for Administrators, Managers, Contractors and forged privilege values', async () => {
    for (const user of [admin, manager, contractor, forged]) {
      mount('/dashboard', user);
      await screen.findByRole('heading', { name: 'Dashboard' });
      expect(screen.queryByRole('navigation', { name: 'Platform navigation' })).toBeNull();
      expect(screen.queryByRole('link', { name: /Platform/ })).toBeNull();
      cleanup();
    }
  });
});

describe('/platform route guard', () => {
  it('shows the restricted page and never calls the platform API for non-holders', async () => {
    for (const [user, path] of [[admin, '/platform'], [manager, '/platform/audit'], [contractor, '/platform'], [forged, '/platform/audit']] as const) {
      const api = mount(path, user);
      expect((await screen.findByRole('heading', { name: 'This page isn’t available to you.' }))).toBeTruthy();
      expect(screen.getByText(/only to the Platform Super Admin/)).toBeTruthy();
      expect(api.overview).not.toHaveBeenCalled();
      expect(api.audit).not.toHaveBeenCalled();
      cleanup();
    }
  });
  it('falls back to the restricted page when the server refuses (e.g. the grant was just revoked)', async () => {
    mount('/platform', holder, fakePlatform({ overview: vi.fn(async () => { throw new AuthRequestError('Platform Administration is available only to the Platform Super Admin.', 403, 'platform_forbidden'); }) }));
    expect(await screen.findByRole('heading', { name: 'This page isn’t available to you.' })).toBeTruthy();
  });
});

describe('Platform screens (read-only)', () => {
  it('renders the overview with the grant, organization counts and the operator-only notice, and no write controls', async () => {
    mount('/platform', holder);
    await screen.findByText('CHG-2026-1104');
    expect(screen.getByRole('heading', { name: 'Platform Overview' })).toBeTruthy();
    expect(screen.getByText('Platform Super Admin', { selector: 'dd' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'ThriveSource' }).closest('tr')!.textContent).toBe('ThriveSource721223');
    expect(screen.getByRole('note').textContent).toMatch(/read-only.*operator procedures/);
    expect(screen.queryAllByRole('button').map(b => b.textContent!.trim())).toEqual(['Sign out', '']); // sign-out + menu toggle only
    expect(screen.queryByRole('textbox')).toBeNull();
  });
  it('renders the audit newest-first and loads older pages with the cursor', async () => {
    const api = mount('/platform/audit', holder);
    await screen.findByText('Platform audit viewed');
    expect(api.audit).toHaveBeenLastCalledWith({ before: null, limit: 25 });
    expect(screen.getAllByRole('row').slice(1).map(r => r.querySelector('th')!.textContent)).toEqual(['Platform audit viewed', 'Privilege granted']);
    fireEvent.click(screen.getByRole('button', { name: 'Load older events' }));
    await screen.findByText('Identity designated');
    expect(api.audit).toHaveBeenLastCalledWith({ before: 2, limit: 25 });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Load older events' })).toBeNull());
  });
});

describe('platform API client', () => {
  it('uses same-origin, no-store GETs only and encodes the cursor', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ events: [], hasMore: false, nextBefore: null }), { status: 200 }));
    const api = createPlatformApi(fetcher as never);
    await api.audit({ before: 40, limit: 10 });
    await api.audit();
    expect(fetcher.mock.calls.map(c => (c as unknown[])[0])).toEqual(['/api/platform/audit?limit=10&before=40', '/api/platform/audit']);
    const init = (fetcher.mock.calls[0] as unknown[])[1] as RequestInit;
    expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store' });
    expect(init.body).toBeUndefined();
  });
});
