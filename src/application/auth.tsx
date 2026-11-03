import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import type { AccountAccess, Authentication, LoginInput } from '../domain/contracts';
import type { Principal } from '../domain/permissions';
import type { WorkspaceAdminApi } from '../infrastructure/server-session-auth';
interface AuthState { user: Principal | null; loading: boolean; failed: boolean; access: AccountAccess | null; admin: WorkspaceAdminApi | null; signIn(input: LoginInput): Promise<void>; signOut(): Promise<void> }
const AuthContext = createContext<AuthState | null>(null);
const RECHECK_MS = 5 * 60 * 1000;
export function AuthProvider({ service, access = null, admin = null, children }: { service: Authentication; access?: AccountAccess | null; admin?: WorkspaceAdminApi | null; children: ReactNode }) {
  const [user, setUser] = useState<Principal | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  useEffect(() => { let active = true; service.getSession().then(session => { if (active) setUser(session); }).catch(() => { if (active) { setUser(null); setFailed(true); } }).finally(() => { if (active) setLoading(false); }); return () => { active = false; }; }, [service]);
  // Server-side expiry, revocation and disabled-member checks surface here: a rejected session closes the UI.
  useEffect(() => {
    if (!user) return;
    let active = true;
    const recheck = () => { if (document.visibilityState === 'visible') service.getSession().then(session => { if (active) setUser(session); }).catch(() => { if (active) { setUser(null); setFailed(true); } }); };
    const timer = window.setInterval(recheck, RECHECK_MS);
    document.addEventListener('visibilitychange', recheck);
    return () => { active = false; window.clearInterval(timer); document.removeEventListener('visibilitychange', recheck); };
  }, [service, user?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  return <AuthContext.Provider value={{ user, loading, failed, access, admin, async signIn(input) { setFailed(false); setUser(await service.signIn(input)); }, async signOut() { setUser(null); await service.signOut(); } }}>{children}</AuthContext.Provider>;
}
export function useAuth() { const auth = useContext(AuthContext); if (!auth) throw new Error('AuthProvider is required'); return auth; }
export function safeDestination(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000- ]/.test(value) || ['/login', '/forgot-password', '/reset-password', '/accept-invite'].includes(value.split(/[?#]/)[0]!)) return '/dashboard';
  return value;
}
