import { readServerEnv } from './config';
import { createClient, isAuthError, type SupabaseClient } from '@supabase/supabase-js';
import { ProviderConflictError, type IdentityProvider, type OtpVerification, type ProviderSession } from './types';

// Refuse default network transport outside a verified production Function. Injected transports exist only for offline tests.
const productionFetch: typeof fetch = async (input, init) => {
  const context = typeof Netlify === 'undefined' ? null : Netlify.context;
  if (!context || 'unavailable' in readServerEnv(name => Netlify.env.get(name), context.deploy?.context, {
    siteId: context.site?.id, deployId: context.deploy?.id, published: context.deploy?.published,
  })) throw new Error('identity_provider_context_not_enabled');
  return fetch(input, init);
};

// Server-only: no session persistence, no auto refresh, no URL session detection. Each call uses a fresh
// client so no token state can leak between requests that share a warm function instance.
const serverClient = (url: string, key: string, fetchImpl?: typeof fetch): SupabaseClient => createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  global: { fetch: fetchImpl ?? productionFetch },
});

/** A 4xx from Supabase Auth is a credential/verification rejection; anything else is an outage. */
function rejectedOrThrow(error: unknown): null {
  if (isAuthError(error) && typeof error.status === 'number' && error.status >= 400 && error.status < 500 && error.status !== 429) return null;
  throw new Error('identity_provider_unavailable');
}
function sessionOf(data: { session: { access_token: string } | null; user: { id: string } | null }): ProviderSession | null {
  return data.session && data.user ? { userId: data.user.id, accessToken: data.session.access_token } : null;
}

export class SupabaseIdentityProvider implements IdentityProvider {
  constructor(private readonly url: string, private readonly anonKey: string, private readonly serviceRoleKey: string, private readonly fetchImpl?: typeof fetch) {}
  private user() { return serverClient(this.url, this.anonKey, this.fetchImpl); }
  private admin() { return serverClient(this.url, this.serviceRoleKey, this.fetchImpl).auth.admin; }

  async signInWithPassword(email: string, password: string) {
    const { data, error } = await this.user().auth.signInWithPassword({ email, password });
    return error ? rejectedOrThrow(error) : sessionOf(data);
  }

  async verifyEmailOtp(params: OtpVerification) {
    const { data, error } = await this.user().auth.verifyOtp('code' in params
      ? { email: params.email, token: params.code, type: 'recovery' }
      : { token_hash: params.tokenHash, type: params.type });
    return error ? rejectedOrThrow(error) : sessionOf(data);
  }

  async revokeSession(accessToken: string, scope: 'local' | 'global') {
    const { error } = await this.admin().signOut(accessToken, scope);
    if (error) throw new Error('identity_provider_revoke_failed');
  }

  async inviteUser(email: string, redirectTo: string) {
    // Deliberately no user_metadata: roles live only in Hourvia's workspace_members table.
    const { data, error } = await this.admin().inviteUserByEmail(email, { redirectTo });
    if (error) {
      if (isAuthError(error) && (error.code === 'email_exists' || error.status === 422)) throw new ProviderConflictError('identity_exists');
      throw new Error('identity_provider_unavailable');
    }
    return { userId: data.user.id };
  }

  async sendRecovery(email: string, redirectTo: string) {
    const { error } = await this.user().auth.resetPasswordForEmail(email, { redirectTo });
    if (error) throw new Error('identity_provider_unavailable');
  }

  async setPassword(userId: string, password: string) {
    // Supabase Auth hashes and stores the password; Hourvia never hashes or compares passwords.
    const { error } = await this.admin().updateUserById(userId, { password });
    if (error) throw isAuthError(error) && error.status === 422 ? new ProviderConflictError('weak_password') : new Error('identity_provider_unavailable');
  }

  async banUser(userId: string) {
    const { error } = await this.admin().updateUserById(userId, { ban_duration: '876000h' });
    if (error) throw new Error('identity_provider_unavailable');
  }
}
