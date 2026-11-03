// LIVE PROVIDER INTEGRATION TESTS — skipped unless explicitly enabled. Run only from a trusted operator shell,
// never from CI or shared logs, and only after the production smoke-test window is authorized:
//   HOURVIA_LIVE_SUPABASE_TESTS=production-smoke SUPABASE_URL=… SUPABASE_PUBLISHABLE_KEY=… SUPABASE_SECRET_KEY=… \
//     npx vitest run server/auth/supabase.live.test.ts
// (HOURVIA_LIVE_SUPABASE_TESTS=nonproduction is still accepted for a disposable project; legacy key names too.)
// Optional: HOURVIA_LIVE_TEST_EMAIL / HOURVIA_LIVE_TEST_PASSWORD for a designated, already-active test account.
// In production-smoke mode that email must also appear in HOURVIA_AUTH_SMOKE_TEST_EMAILS.
// These tests never send invitation or recovery email and never create, change or delete any user.
import { describe, expect, it } from 'vitest';
import { SupabaseIdentityProvider } from './provider-supabase';

const env = process.env;
const mode = env.HOURVIA_LIVE_SUPABASE_TESTS;
const publishableKey = env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY;
const secretKey = env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY;
const enabled = (mode === 'nonproduction' || mode === 'production-smoke') && !!env.SUPABASE_URL && !!publishableKey && !!secretKey;
const provider = () => new SupabaseIdentityProvider(env.SUPABASE_URL!, publishableKey!, secretKey!);
const smokeList = (env.HOURVIA_AUTH_SMOKE_TEST_EMAILS ?? '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const testEmail = env.HOURVIA_LIVE_TEST_EMAIL?.trim().toLowerCase();
const testUserAllowed = !!testEmail && !!env.HOURVIA_LIVE_TEST_PASSWORD && (mode !== 'production-smoke' || smokeList.includes(testEmail));

describe.skipIf(!enabled)(`LIVE Supabase Auth (${mode})`, () => {
  it('has public self-registration disabled and email auth enabled', async () => {
    const res = await fetch(`${env.SUPABASE_URL}/auth/v1/settings`, { headers: { apikey: env.SUPABASE_ANON_KEY! } });
    const settings = await res.json() as { disable_signup: boolean; mailer_autoconfirm?: boolean; external: Record<string, boolean> };
    expect(settings.disable_signup).toBe(true);
    expect(settings.external.email).toBe(true);
    // Confirm email on; every other provider (OAuth, phone, anonymous) off.
    expect(settings.mailer_autoconfirm).not.toBe(true);
    expect(Object.entries(settings.external).filter(([name, on]) => name !== 'email' && on).map(([name]) => name)).toEqual([]);
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
  it.skipIf(!testUserAllowed)('signs in a designated test user and revokes the provider session', async () => {
    const session = await provider().signInWithPassword(testEmail!, env.HOURVIA_LIVE_TEST_PASSWORD!);
    expect(session?.userId).toMatch(/^[0-9a-f-]{36}$/);
    await provider().revokeSession(session!.accessToken, 'global');
  });
});
