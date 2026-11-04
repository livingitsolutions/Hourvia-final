import { describe, expect, it, vi } from 'vitest';
vi.mock('./deployment-identity', () => ({ deploymentIdentity: {
  siteId: '48d7a24b-6072-40bc-866f-0d6e43a921ea', branch: 'main', context: 'production', deployId: 'a'.repeat(24), commit: 'b'.repeat(40),
} }));
import { readServerEnv } from './config';
import { deploymentAllowed, PRODUCTION_SITE, PRODUCTION_ORIGIN } from './production-policy';
import { handleAuthRequest } from './http';
const id = '11111111-1111-4111-8111-111111111111';
const protectedId = '22222222-2222-4222-8222-222222222222';
const policy = { identities: [{ email: 'synthetic@example.test', memberId: id, authUserId: id }], protectedEmails: ['protected@example.test'], protectedMemberIds: [protectedId], protectedAuthUserIds: [protectedId] };
const full: Record<string, string> = {
  SUPABASE_URL: 'https://example.supabase.co', SUPABASE_PUBLISHABLE_KEY: 'public-test-fixture', SUPABASE_SECRET_KEY: 'private-test-fixture',
  HOURVIA_AUTH_HASH_KEY: 'h'.repeat(40), HOURVIA_APP_ORIGIN: PRODUCTION_ORIGIN, HOURVIA_AUTH_ALLOW_PRODUCTION: 'true',
  HOURVIA_AUTH_LAUNCH_STAGE: 'smoke', HOURVIA_AUTH_SMOKE_TEST_EMAILS: 'synthetic@example.test', HOURVIA_SYNTHETIC_IDENTITY_POLICY: JSON.stringify(policy),
};
const runtime = { siteId: PRODUCTION_SITE, deployId: 'a'.repeat(24), published: true };
const read = (changes: Record<string, string> = {}, context: string | undefined = 'production') => readServerEnv(n => ({ ...full, ...changes })[n], context, runtime);
describe('production-only pre-launch environment', () => {
  it('rejects every nonproduction context before reading credentials', () => {
    for (const c of ['dev', 'deploy-preview', 'branch-deploy', 'agent', '', undefined]) {
      const get = vi.fn();
      expect(readServerEnv(get, c, runtime)).toEqual({ unavailable: 'context_not_enabled' });
      expect(get).not.toHaveBeenCalled();
    }
  });
  it('requires published site/deploy identity and a production main artifact', () => {
    const build = { siteId: PRODUCTION_SITE, branch: 'main', context: 'production', deployId: runtime.deployId, commit: 'b'.repeat(40) };
    expect(deploymentAllowed(runtime, build)).toBe(true);
    for (const change of [{ siteId: 'wrong' }, { deployId: 'wrong' }, { published: false }]) expect(deploymentAllowed({ ...runtime, ...change }, build)).toBe(false);
    for (const change of [{ siteId: 'wrong' }, { deployId: '' }, { commit: '' }, { branch: 'staging' }, { context: 'deploy-preview' }]) expect(deploymentAllowed(runtime, { ...build, ...change })).toBe(false);
    expect(readServerEnv(n => full[n], 'production')).toEqual({ unavailable: 'deployment_not_verified' });
  });
  it('requires explicit enable, smoke stage and the canonical origin', () => {
    expect('config' in read()).toBe(true);
    for (const stage of ['', 'general', 'public']) expect(read({ HOURVIA_AUTH_LAUNCH_STAGE: stage })).toEqual({ unavailable: 'smoke_required' });
    expect(read({ HOURVIA_AUTH_ALLOW_PRODUCTION: '' })).toEqual({ unavailable: 'production_not_enabled' });
    expect(read({ HOURVIA_APP_ORIGIN: 'https://staging.example.test' })).toEqual({ unavailable: 'misconfigured' });
  });
  it('defaults email off and requires complete credentials', () => {
    const r = read(); expect('config' in r && r.config.emailDeliveryAuthorized).toBe(false);
    for (const key of ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY', 'HOURVIA_AUTH_HASH_KEY']) expect(read({ [key]: '' })).toEqual({ unavailable: 'not_configured' });
    expect(read({ SUPABASE_PUBLISHABLE_KEY: 'sb_secret_wrong' })).toEqual({ unavailable: 'misconfigured' });
  });
  it('rejects absent, malformed, overlapping and ambiguous identity policies', () => {
    for (const raw of ['', '{}', JSON.stringify({ ...policy, protectedAuthUserIds: [id] }), JSON.stringify({ ...policy, identities: [...policy.identities, ...policy.identities] })]) {
      expect(read({ HOURVIA_SYNTHETIC_IDENTITY_POLICY: raw })).toEqual({ unavailable: 'synthetic_policy_invalid' });
    }
    for (const emails of ['', 'synthetic@example.test,wrong', 'other@example.test']) expect(read({ HOURVIA_AUTH_SMOKE_TEST_EMAILS: emails })).toEqual({ unavailable: 'synthetic_policy_invalid' });
  });
  it('bounds timeouts and keeps unavailable responses generic', async () => {
    const r = read({ HOURVIA_SESSION_IDLE_SECONDS: '999999', HOURVIA_SESSION_ABSOLUTE_SECONDS: '5' });
    expect('config' in r && [r.config.idleTimeoutSeconds, r.config.absoluteTimeoutSeconds]).toEqual([1800, 43200]);
    const res = await handleAuthRequest(new Request(PRODUCTION_ORIGIN + '/api/auth/session'), undefined, async () => ({ unavailable: 'database_not_verified' }));
    expect(res.status).toBe(503); expect(await res.text()).not.toContain('database_not_verified');
  });
});
