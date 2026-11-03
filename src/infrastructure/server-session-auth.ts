import type { AcceptInvitationInput, AccountAccess, AdminInviteInput, Authentication, RecoveryCompleteInput } from '../domain/contracts';
import type { Principal } from '../domain/permissions';

/**
 * Browser adapter for Hourvia's server-managed session. It never sees a provider token, refresh token, or
 * service credential: the session is an HttpOnly cookie set by /api/auth/*. Nothing is written to
 * web storage or document.cookie.
 */
export class AuthRequestError extends Error {
  constructor(message: string, readonly status: number, readonly code: string, readonly fields: Record<string, string> = {}) { super(message); }
}

type Fetch = typeof fetch;
async function call<T>(fetcher: Fetch, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetcher(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch { throw new AuthRequestError('Hourvia could not be reached. Check your connection and try again.', 0, 'network'); }
  if (response.status === 204) return undefined as T;
  const data = await response.json().catch(() => ({})) as { message?: string; error?: string; fields?: Record<string, string> } & T;
  if (!response.ok) throw new AuthRequestError(data.message ?? 'Something went wrong. Try again.', response.status, data.error ?? 'error', data.fields);
  return data;
}

export function createServerSessionAuth(fetcher: Fetch = (...args) => fetch(...args)): Authentication & AccountAccess {
  return {
    async getSession() {
      try { return (await call<{ principal: Principal }>(fetcher, '/api/auth/session')).principal; }
      catch (error) { if (error instanceof AuthRequestError && error.status === 401) return null; throw error; }
    },
    async signIn(input) { return (await call<{ principal: Principal }>(fetcher, '/api/auth/login', input)).principal; },
    async signOut() { await call(fetcher, '/api/auth/logout', {}); },
    async requestRecovery(email) { return (await call<{ message: string }>(fetcher, '/api/auth/recovery/request', { email })).message; },
    async completeRecovery(input: RecoveryCompleteInput) { return (await call<{ message: string }>(fetcher, '/api/auth/recovery/complete', input)).message; },
    async acceptInvitation(input: AcceptInvitationInput) { return (await call<{ message: string }>(fetcher, '/api/auth/invitations/accept', input)).message; },
  };
}

export interface WorkspaceMember { id: string; email: string; name: string; role: Principal['role']; status: 'invited' | 'active' | 'disabled'; createdAt: string }
export function createWorkspaceAdminApi(fetcher: Fetch = (...args) => fetch(...args)) {
  return {
    async listMembers() { return (await call<{ members: WorkspaceMember[] }>(fetcher, '/api/admin/members')).members; },
    async invite(input: AdminInviteInput) { return (await call<{ member: WorkspaceMember }>(fetcher, '/api/admin/invitations', input)).member; },
    async disable(id: string) { await call(fetcher, `/api/admin/members/${encodeURIComponent(id)}/disable`, {}); },
    async revokeSessions(id: string) { await call(fetcher, `/api/admin/members/${encodeURIComponent(id)}/revoke-sessions`, {}); },
  };
}
export type WorkspaceAdminApi = ReturnType<typeof createWorkspaceAdminApi>;
export const serverSessionAuth = createServerSessionAuth();
