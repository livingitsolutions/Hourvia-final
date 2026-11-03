// MOCKED HTTP TESTS for the Supabase adapter: real @supabase/supabase-js, fake fetch. No network.
import { describe, expect, it } from 'vitest';
import { SupabaseIdentityProvider } from './provider-supabase';
import { ProviderConflictError } from './types';

interface Seen { url: URL; method: string; headers: Headers; body: any }
function fakeFetch(reply: (seen: Seen) => { status: number; body: unknown }) {
  const calls: Seen[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const seen = { url: new URL(req.url), method: req.method, headers: req.headers, body: req.method === 'GET' ? null : await req.json().catch(() => null) };
    calls.push(seen);
    const { status, body } = reply(seen);
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { impl, calls };
}
const user = { id: '11111111-1111-4111-8111-111111111111', aud: 'authenticated', email: 'c@t.test', app_metadata: {}, user_metadata: {}, created_at: '2026-01-01T00:00:00Z' };
const session = { access_token: 'access.jwt.value', refresh_token: 'refresh-secret', expires_in: 3600, token_type: 'bearer', user };
const make = (f: ReturnType<typeof fakeFetch>) => new SupabaseIdentityProvider('https://proj.supabase.co', 'anon-key', 'service-key', f.impl);

describe('SupabaseIdentityProvider (mocked HTTP)', () => {
  it('signs in with the anon key and returns only the user id and access token', async () => {
    const f = fakeFetch(() => ({ status: 200, body: session }));
    expect(await make(f).signInWithPassword('c@t.test', 'pw')).toEqual({ userId: user.id, accessToken: 'access.jwt.value' });
    expect(f.calls[0]!.url.pathname).toBe('/auth/v1/token'); expect(f.calls[0]!.url.searchParams.get('grant_type')).toBe('password');
    expect(f.calls[0]!.headers.get('apikey')).toBe('anon-key');
  });
  it('maps credential rejections to null and outages or provider throttling to errors', async () => {
    expect(await make(fakeFetch(() => ({ status: 400, body: { code: 'invalid_credentials', msg: 'Invalid login credentials' } }))).signInWithPassword('c@t.test', 'x')).toBeNull();
    await expect(make(fakeFetch(() => ({ status: 500, body: { msg: 'boom' } }))).signInWithPassword('c@t.test', 'x')).rejects.toThrow('identity_provider_unavailable');
    await expect(make(fakeFetch(() => ({ status: 429, body: { code: 'over_request_rate_limit' } }))).signInWithPassword('c@t.test', 'x')).rejects.toThrow('identity_provider_unavailable');
  });
  it('verifies invite token hashes and recovery codes through /verify', async () => {
    const f = fakeFetch(() => ({ status: 200, body: session }));
    await make(f).verifyEmailOtp({ type: 'invite', tokenHash: 'abc123abc123abc123' });
    await make(f).verifyEmailOtp({ type: 'recovery', email: 'c@t.test', code: '123456' });
    expect(f.calls.map(c => [c.url.pathname, c.body])).toEqual([
      ['/auth/v1/verify', expect.objectContaining({ token_hash: 'abc123abc123abc123', type: 'invite' })],
      ['/auth/v1/verify', expect.objectContaining({ email: 'c@t.test', token: '123456', type: 'recovery' })],
    ]);
    expect(await make(fakeFetch(() => ({ status: 403, body: { code: 'otp_expired' } }))).verifyEmailOtp({ type: 'recovery', email: 'c@t.test', code: '000000' })).toBeNull();
  });
  it('invites with the service key, a redirect, and no user metadata', async () => {
    const f = fakeFetch(() => ({ status: 200, body: user }));
    expect(await make(f).inviteUser('c@t.test', 'https://preview.test/accept-invite')).toEqual({ userId: user.id });
    const call = f.calls[0]!;
    expect(call.url.pathname).toBe('/auth/v1/invite'); expect(call.url.searchParams.get('redirect_to')).toBe('https://preview.test/accept-invite');
    expect(call.headers.get('authorization')).toBe('Bearer service-key');
    expect(call.body).toEqual({ email: 'c@t.test' });
    await expect(make(fakeFetch(() => ({ status: 422, body: { code: 'email_exists' } }))).inviteUser('c@t.test', 'https://p.test')).rejects.toBeInstanceOf(ProviderConflictError);
  });
  it('revokes provider sessions with the admin logout endpoint', async () => {
    const f = fakeFetch(() => ({ status: 204, body: {} }));
    await make(f).revokeSession('access.jwt.value', 'global');
    expect(f.calls[0]!.url.pathname).toBe('/auth/v1/logout'); expect(f.calls[0]!.url.searchParams.get('scope')).toBe('global');
    expect(f.calls[0]!.headers.get('authorization')).toBe('Bearer access.jwt.value');
  });
  it('sets passwords and bans users via the admin API, never hashing locally', async () => {
    const f = fakeFetch(() => ({ status: 200, body: user }));
    await make(f).setPassword(user.id, 'a long new passphrase'); await make(f).banUser(user.id);
    expect(f.calls.map(c => [c.method, c.url.pathname, c.body])).toEqual([
      ['PUT', `/auth/v1/admin/users/${user.id}`, { password: 'a long new passphrase' }],
      ['PUT', `/auth/v1/admin/users/${user.id}`, { ban_duration: '876000h' }],
    ]);
    await expect(make(fakeFetch(() => ({ status: 422, body: { code: 'weak_password' } }))).setPassword(user.id, 'password1234')).rejects.toBeInstanceOf(ProviderConflictError);
  });
  it('requests recovery emails with a redirect to the reset page', async () => {
    const f = fakeFetch(() => ({ status: 200, body: {} }));
    await make(f).sendRecovery('c@t.test', 'https://preview.test/reset-password');
    expect(f.calls[0]!.url.pathname).toBe('/auth/v1/recover'); expect(f.calls[0]!.url.searchParams.get('redirect_to')).toBe('https://preview.test/reset-password');
  });
});
