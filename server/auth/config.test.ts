import { describe, expect, it } from 'vitest';
import { readServerEnv } from './config';
import { handleAuthRequest } from './http';
const full: Record<string, string> = { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_ANON_KEY: 'anon', SUPABASE_SERVICE_ROLE_KEY: 'service', HOURVIA_AUTH_HASH_KEY: 'h'.repeat(40), HOURVIA_APP_ORIGIN: 'https://preview.hourvia.test', HOURVIA_EMAIL_DELIVERY_AUTHORIZED: 'true' };
const env = (vars: Record<string, string>) => (name: string) => vars[name];
describe('server environment', () => {
  it('fails closed when anything required is missing or unsafe', () => {
    for (const name of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'HOURVIA_AUTH_HASH_KEY']) { const vars = { ...full }; delete vars[name]; expect(readServerEnv(env(vars), 'dev')).toEqual({ unavailable: 'not_configured' }); }
    expect(readServerEnv(env({ ...full, SUPABASE_URL: 'http://example.supabase.co' }), 'dev')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...full, HOURVIA_AUTH_HASH_KEY: 'short' }), 'dev')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...full, SUPABASE_ANON_KEY: 'same', SUPABASE_SERVICE_ROLE_KEY: 'same' }), 'dev')).toEqual({ unavailable: 'misconfigured' });
  });
  it('never runs in deploy previews, branch deploys or unknown contexts, even fully configured', () => {
    const everything = { ...full, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true', HOURVIA_AUTH_LAUNCH_STAGE: 'general' };
    for (const context of ['deploy-preview', 'branch-deploy', 'staging', '', undefined]) expect(readServerEnv(env(everything), context)).toEqual({ unavailable: 'context_not_enabled' });
  });
  it('stays disabled in production until explicitly enabled', () => {
    expect(readServerEnv(env(full), 'production')).toEqual({ unavailable: 'production_not_enabled' });
    expect(readServerEnv(env({ ...full, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true' }), 'production')).toEqual({ unavailable: 'launch_stage_not_set' });
    expect('config' in readServerEnv(env({ ...full, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true', HOURVIA_AUTH_LAUNCH_STAGE: 'smoke', HOURVIA_AUTH_SMOKE_TEST_EMAILS: 'a@t.test' }), 'production')).toBe(true);
  });
  it('requires an explicit origin and launch stage in production', () => {
    const prod = { ...full, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true' };
    expect(readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'general', HOURVIA_APP_ORIGIN: '' }), 'production')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'live' }), 'production')).toEqual({ unavailable: 'launch_stage_not_set' });
    expect(readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'smoke' }), 'production')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'smoke', HOURVIA_AUTH_SMOKE_TEST_EMAILS: 'ok@t.test,not an email' }), 'production')).toEqual({ unavailable: 'misconfigured' });
    const smoke = readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'smoke', HOURVIA_AUTH_SMOKE_TEST_EMAILS: ' Admin.Smoke@T.test , c.smoke@t.test' }), 'production');
    expect('config' in smoke && [...smoke.config.smokeTestEmails!]).toEqual(['admin.smoke@t.test', 'c.smoke@t.test']);
    const general = readServerEnv(env({ ...prod, HOURVIA_AUTH_LAUNCH_STAGE: 'general' }), 'production');
    expect('config' in general && general.config.smokeTestEmails).toBeNull();
  });
  it('accepts new-style Supabase key names, preferring them, and rejects swapped key types', () => {
    const base = { ...full }; delete (base as Record<string, string>).SUPABASE_ANON_KEY; delete (base as Record<string, string>).SUPABASE_SERVICE_ROLE_KEY;
    const r = readServerEnv(env({ ...base, SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_x', SUPABASE_SECRET_KEY: 'sb_secret_y', SUPABASE_SERVICE_ROLE_KEY: 'legacy' }), 'dev');
    expect('supabase' in r && [r.supabase.anonKey, r.supabase.serviceRoleKey]).toEqual(['sb_publishable_x', 'sb_secret_y']);
    expect(readServerEnv(env({ ...base, SUPABASE_PUBLISHABLE_KEY: 'sb_secret_y', SUPABASE_SECRET_KEY: 'sb_publishable_x' }), 'dev')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...base, VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_x', SUPABASE_SECRET_KEY: 'sb_secret_y' }), 'dev')).toEqual({ unavailable: 'not_configured' });
  });
  it('requires explicit authorization and an https origin before any email is sent', () => {
    const preview = readServerEnv(env({ ...full, HOURVIA_EMAIL_DELIVERY_AUTHORIZED: 'false' }), 'dev');
    expect('config' in preview && preview.config.emailDeliveryAuthorized).toBe(false);
    const badOrigin = readServerEnv(env({ ...full, HOURVIA_APP_ORIGIN: 'javascript:alert(1)' }), 'dev');
    expect('config' in badOrigin && badOrigin.config.emailDeliveryAuthorized).toBe(false);
  });
  it('bounds session timeouts', () => {
    const r = readServerEnv(env({ ...full, HOURVIA_SESSION_IDLE_SECONDS: '999999', HOURVIA_SESSION_ABSOLUTE_SECONDS: '5' }), 'dev');
    expect('config' in r && [r.config.idleTimeoutSeconds, r.config.absoluteTimeoutSeconds]).toEqual([1800, 43200]);
  });
  it('responds 503 without details when unconfigured', async () => {
    const res = await handleAuthRequest(new Request('https://h.test/api/auth/session'), '1.1.1.1', async () => ({ unavailable: 'not_configured' }));
    expect(res.status).toBe(503); expect(await res.text()).not.toContain('not_configured');
  });
});
