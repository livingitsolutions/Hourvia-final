// @vitest-environment jsdom
// MOCKED: browser adapter and auth UI against a fake fetch / fake services. No server, provider or email.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { AuthProvider } from '../application/auth';
import type { AccountAccess } from '../domain/contracts';
import type { Principal } from '../domain/permissions';
import App from '../presentation/App';
import { AuthRequestError, createServerSessionAuth, createWorkspaceAdminApi } from './server-session-auth';
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); });

const principal: Principal = { id: 'c1', name: 'C', role: 'contractor', workspaceId: 'thrivesource', assignedContractorIds: [], approvalAuthorized: false };
function fetchStub(status: number, body?: unknown) {
  return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
}

describe('server-session browser adapter', () => {
  it('uses same-origin cookies only and stores nothing in browser storage', async () => {
    const fetcher = fetchStub(200, { principal });
    const auth = createServerSessionAuth(fetcher);
    const cookieSpy = vi.spyOn(document, 'cookie', 'set');
    expect(await auth.signIn({ email: 'c@t.test', password: 'pw' })).toEqual(principal);
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toBe('/api/auth/login'); expect(init).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store' });
    expect(new Headers(init!.headers).get('authorization')).toBeNull();
    expect(localStorage.length + sessionStorage.length).toBe(0); expect(cookieSpy).not.toHaveBeenCalled();
  });
  it('treats 401 as signed out and other failures as errors', async () => {
    expect(await createServerSessionAuth(fetchStub(401, { error: 'unauthenticated', message: 'x' })).getSession()).toBeNull();
    await expect(createServerSessionAuth(fetchStub(503, { error: 'auth_unavailable', message: 'down' })).getSession()).rejects.toBeInstanceOf(AuthRequestError);
  });
  it('sends admin actions with a JSON body and encoded IDs', async () => {
    const fetcher = fetchStub(200, {});
    await createWorkspaceAdminApi(fetcher).disable('a/b');
    expect(fetcher.mock.calls[0]![0]).toBe('/api/admin/members/a%2Fb/disable');
    expect(fetcher.mock.calls[0]![1]).toMatchObject({ method: 'POST', body: '{}' });
  });
});

function access(overrides: Partial<AccountAccess> = {}): AccountAccess { return { requestRecovery: vi.fn(async () => 'If an active Hourvia account uses that email, a 6-digit reset code and link are on the way.'), completeRecovery: vi.fn(async () => 'ok'), acceptInvitation: vi.fn(async () => 'ok'), ...overrides }; }
function Where() { const l = useLocation(); return <output data-testid="where">{l.pathname + l.search + l.hash}</output>; }
function mount(path: string, a: AccountAccess) {
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider service={{ getSession: async () => null, signIn: async () => principal, signOut: async () => {} }} access={a}><App/><Where/></AuthProvider></MemoryRouter>);
}
const type = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe('recovery and invitation UI', () => {
  it('shows the generic response and completes recovery with a 6-digit code', async () => {
    const a = access(); mount('/forgot-password', a);
    type('Work email', 'c@t.test'); fireEvent.click(screen.getByRole('button', { name: /Send reset code/ }));
    expect(await screen.findByText(/If an active Hourvia account uses that email/)).toBeTruthy();
    type('6-digit code', '482913'); type('New password', 'a long passphrase'); type('Confirm new password', 'a long passphrase');
    fireEvent.click(screen.getByRole('button', { name: /Set new password/ }));
    expect(await screen.findByText('Your password is set. Sign in to continue.')).toBeTruthy();
    expect(a.completeRecovery).toHaveBeenCalledWith({ email: 'c@t.test', code: '482913', password: 'a long passphrase' });
  });
  it('rejects mismatched and short passwords before calling the server', async () => {
    const a = access(); mount('/accept-invite#token_hash=abcdefabcdefabcdef1234', a);
    type('New password', 'a long passphrase'); type('Confirm new password', 'different passphrase');
    fireEvent.click(screen.getByRole('button', { name: /Create password/ }));
    expect(await screen.findByText('Passwords do not match.')).toBeTruthy();
    type('New password', 'short'); type('Confirm new password', 'short'); fireEvent.click(screen.getByRole('button', { name: /Create password/ }));
    expect(await screen.findByText('Use at least 12 characters.')).toBeTruthy();
    expect(a.acceptInvitation).not.toHaveBeenCalled();
  });
  it('reads the invitation token from the fragment, strips it from the URL, and submits it once', async () => {
    const a = access(); mount('/accept-invite#token_hash=abcdefabcdefabcdef1234', a);
    expect(await screen.findByRole('heading', { name: 'Create your password.' })).toBeTruthy();
    expect(screen.getByTestId('where').textContent).toBe('/accept-invite');
    type('New password', 'a long passphrase'); type('Confirm new password', 'a long passphrase');
    fireEvent.click(screen.getByRole('button', { name: /Create password/ }));
    expect(await screen.findByText('Your password is set. Sign in to continue.')).toBeTruthy();
    expect(a.acceptInvitation).toHaveBeenCalledWith({ tokenHash: 'abcdefabcdefabcdef1234', password: 'a long passphrase' });
  });
  it('explains a missing invitation token instead of showing a form', async () => {
    mount('/accept-invite', access());
    expect(await screen.findByText(/This invitation link is incomplete/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Create password/ })).toBeNull();
  });
  it('shows server errors from sign-in without exposing details', async () => {
    render(<MemoryRouter initialEntries={['/login']}><AuthProvider service={{ getSession: async () => null, signIn: async () => { throw new AuthRequestError('Email or password is incorrect, or this account does not have active workspace access.', 401, 'login_failed'); }, signOut: async () => {} }}><App/></AuthProvider></MemoryRouter>);
    await screen.findByRole('heading', { name: 'Your workday starts here.' });
    type('Work email', 'c@t.test'); type('Password', 'wrong');
    fireEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Email or password is incorrect');
  });
});

describe('frontend secret boundary (static scan of src/)', () => {
  const files = (dir: string): string[] => readdirSync(dir).flatMap(name => { const p = join(dir, name); return statSync(p).isDirectory() ? files(p) : [p]; });
  it('never references privileged keys, the Supabase SDK, or server modules', () => {
    for (const file of files(join(process.cwd(), 'src')).filter(f => !f.endsWith('.test.tsx') && !f.endsWith('.test.ts'))) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).not.toMatch(/SERVICE_ROLE|service_role|SUPABASE_|@supabase\/|RESEND|HOURVIA_AUTH_HASH_KEY|import\.meta\.env|server\/auth|localStorage|sessionStorage/);
    }
  });
});
