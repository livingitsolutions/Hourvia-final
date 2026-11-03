import { describe, expect, it } from 'vitest';
import { readServerEnv } from './config';
import { handleAuthRequest } from './http';
const full: Record<string, string> = { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_ANON_KEY: 'anon', SUPABASE_SERVICE_ROLE_KEY: 'service', HOURVIA_AUTH_HASH_KEY: 'h'.repeat(40), HOURVIA_APP_ORIGIN: 'https://preview.hourvia.test', HOURVIA_EMAIL_DELIVERY_AUTHORIZED: 'true' };
const env = (vars: Record<string, string>) => (name: string) => vars[name];
describe('server environment', () => {
  it('fails closed when anything required is missing or unsafe', () => {
    for (const name of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'HOURVIA_AUTH_HASH_KEY']) { const vars = { ...full }; delete vars[name]; expect(readServerEnv(env(vars), 'deploy-preview')).toEqual({ unavailable: 'not_configured' }); }
    expect(readServerEnv(env({ ...full, SUPABASE_URL: 'http://example.supabase.co' }), 'deploy-preview')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...full, HOURVIA_AUTH_HASH_KEY: 'short' }), 'deploy-preview')).toEqual({ unavailable: 'misconfigured' });
    expect(readServerEnv(env({ ...full, SUPABASE_ANON_KEY: 'same', SUPABASE_SERVICE_ROLE_KEY: 'same' }), 'deploy-preview')).toEqual({ unavailable: 'misconfigured' });
  });
  it('stays disabled in production until explicitly enabled', () => {
    expect(readServerEnv(env(full), 'production')).toEqual({ unavailable: 'production_not_enabled' });
    expect('config' in readServerEnv(env({ ...full, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true' }), 'production')).toBe(true);
  });
  it('requires explicit authorization and an https origin before any email is sent', () => {
    const preview = readServerEnv(env({ ...full, HOURVIA_EMAIL_DELIVERY_AUTHORIZED: 'false' }), 'deploy-preview');
    expect('config' in preview && preview.config.emailDeliveryAuthorized).toBe(false);
    const badOrigin = readServerEnv(env({ ...full, HOURVIA_APP_ORIGIN: 'javascript:alert(1)' }), 'deploy-preview');
    expect('config' in badOrigin && badOrigin.config.emailDeliveryAuthorized).toBe(false);
  });
  it('bounds session timeouts', () => {
    const r = readServerEnv(env({ ...full, HOURVIA_SESSION_IDLE_SECONDS: '999999', HOURVIA_SESSION_ABSOLUTE_SECONDS: '5' }), 'deploy-preview');
    expect('config' in r && [r.config.idleTimeoutSeconds, r.config.absoluteTimeoutSeconds]).toEqual([1800, 43200]);
  });
  it('responds 503 without details when unconfigured', async () => {
    const res = await handleAuthRequest(new Request('https://h.test/api/auth/session'), '1.1.1.1', async () => ({ unavailable: 'not_configured' }));
    expect(res.status).toBe(503); expect(await res.text()).not.toContain('not_configured');
  });
});
