import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import type { Authentication, LoginInput } from '../domain/contracts';
import type { Principal } from '../domain/permissions';
interface AuthState { user: Principal | null; loading: boolean; failed: boolean; signIn(input: LoginInput): Promise<void>; signOut(): Promise<void> }
const AuthContext = createContext<AuthState | null>(null);
export function AuthProvider({ service, children }: { service: Authentication; children: ReactNode }) {
  const [user, setUser] = useState<Principal | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  useEffect(() => { let active = true; service.getSession().then(session => { if (active) setUser(session); }).catch(() => { if (active) { setUser(null); setFailed(true); } }).finally(() => { if (active) setLoading(false); }); return () => { active = false; }; }, [service]);
  return <AuthContext.Provider value={{ user, loading, failed, async signIn(input) { setUser(await service.signIn(input)); }, async signOut() { setUser(null); await service.signOut(); } }}>{children}</AuthContext.Provider>;
}
export function useAuth() { const auth = useContext(AuthContext); if (!auth) throw new Error('AuthProvider is required'); return auth; }
export function safeDestination(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u0020]/.test(value) || value.split(/[?#]/)[0] === '/login') return '/dashboard';
  return value;
}
