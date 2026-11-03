// LIVE PROVIDER INTEGRATION TESTS — skipped unless explicitly enabled against a NONPRODUCTION Supabase project:
//   HOURVIA_LIVE_SUPABASE_TESTS=nonproduction SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_ROLE_KEY=… npx vitest run server/auth/supabase.live.test.ts
// Optional: HOURVIA_LIVE_TEST_EMAIL / HOURVIA_LIVE_TEST_PASSWORD for a disposable, already-confirmed test user.
// These tests never send invitation or recovery email.
import { describe, expect, it } from 'vitest';
import { SupabaseIdentityProvider } from './provider-supabase';

const env = process.env;
const enabled = env.HOURVIA_LIVE_SUPABASE_TESTS === 'nonproduction' && !!env.SUPABASE_URL && !!env.SUPABASE_ANON_KEY && !!env.SUPABASE_SERVICE_ROLE_KEY;
const provider = () => new SupabaseIdentityProvider(env.SUPABASE_URL!, env.SUPABASE_ANON_KEY!, env.SUPABASE_SERVICE_ROLE_KEY!);

describe.skipIf(!enabled)('LIVE Supabase Auth (nonproduction)', () => {
  it('has public self-registration disabled and email auth enabled', async () => {
    const res = await fetch(`${env.SUPABASE_URL}/auth/v1/settings`, { headers: { apikey: env.SUPABASE_ANON_KEY! } });
    const settings = await res.json() as { disable_signup: boolean; external: { email: boolean } };
    expect(settings.disable_signup).toBe(true);
    expect(settings.external.email).toBe(true);
  });
  it('rejects unknown credentials without throwing', async () => {
    expect(await provider().signInWithPassword(`nobody-${Date.now()}@example.invalid`, 'not the password')).toBeNull();
  });
  it('rejects forged invite and recovery token hashes', async () => {
    expect(await provider().verifyEmailOtp({ type: 'invite', tokenHash: 'f'.repeat(56) })).toBeNull();
    expect(await provider().verifyEmailOtp({ type: 'recovery', tokenHash: 'e'.repeat(56) })).toBeNull();
  });
  it('rejects a forged access token at the admin logout endpoint', async () => {
    await expect(provider().revokeSession('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.forged', 'global')).rejects.toThrow();
  });
  it.skipIf(!env.HOURVIA_LIVE_TEST_EMAIL || !env.HOURVIA_LIVE_TEST_PASSWORD)('signs in a test user and revokes the provider session', async () => {
    const session = await provider().signInWithPassword(env.HOURVIA_LIVE_TEST_EMAIL!, env.HOURVIA_LIVE_TEST_PASSWORD!);
    expect(session?.userId).toMatch(/^[0-9a-f-]{36}$/);
    await provider().revokeSession(session!.accessToken, 'global');
  });
});
