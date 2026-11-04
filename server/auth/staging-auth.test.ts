import type { Context } from '@netlify/functions';
import handler from '../../netlify/functions/auth-api.mjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readServerEnv, STAGING_ORIGIN, STAGING_SITE_ID } from './config';
import { runtimeDeps } from './runtime';
import { stagingDatabaseReady, STAGING_DATABASE_CHECK } from './staging-database';
import { createHarness } from './testing/harness';
import { handleAuthRequest } from './http';

const manifest = vi.hoisted(() => ({ branch:'staging',siteId:'48d7a24b-6072-40bc-866f-0d6e43a921ea',deployId:'synthetic-deploy' }));
vi.mock('./deployment-identity', () => ({ deploymentIdentity:manifest }));
const db = vi.hoisted(() => ({ connect: vi.fn(), query: vi.fn() }));
vi.mock('@netlify/database', () => ({ getDatabase: () => ({ pool: db }) }));
const identity = { siteId: STAGING_SITE_ID, branch: 'staging' };
const vars: Record<string, string> = {
  HOURVIA_AUTH_ALLOW_STAGING: 'true', HOURVIA_APP_ORIGIN: STAGING_ORIGIN,
  HOURVIA_AUTH_LAUNCH_STAGE: 'smoke', HOURVIA_AUTH_SMOKE_TEST_EMAILS: 'hourvia-staging+admin@example.test,hourvia-staging+contractor@example.test',
  NETLIFY_DB_URL: 'postgresql://synthetic:synthetic@staging.example.db.netlify.com/netlifydb',
  HOURVIA_STAGING_DATABASE_VERIFIED_TARGET: 'staging:M7:staging.example.db.netlify.com',
  SUPABASE_URL: 'https://synthetic.supabase.co', SUPABASE_PUBLISHABLE_KEY: 'synthetic-public',
  SUPABASE_SECRET_KEY: 'synthetic-secret', HOURVIA_AUTH_HASH_KEY: 's'.repeat(40),
  HOURVIA_EMAIL_DELIVERY_AUTHORIZED: 'false',
};
const reader = (overrides: Record<string, string> = {}) => (name: string) => ({ ...vars, ...overrides })[name];
const config = () => {
  const result = readServerEnv(reader(), 'branch-deploy', identity);
  if ('unavailable' in result) throw new Error(result.unavailable);
  return result.config;
};
afterEach(() => { vi.clearAllMocks(); vi.unstubAllGlobals(); manifest.branch='staging'; });
describe('explicit staging authorization', () => {
  it('accepts only the exact site, staging branch, origin, opt-in and smoke allowlist', () => {
    expect(STAGING_ORIGIN).toBe('https://staging.hourvia.livingitsolutions.com');
    expect(config()).toMatchObject({ appOrigin: STAGING_ORIGIN, emailDeliveryAuthorized: false });
    expect([...config().smokeTestEmails!]).toEqual(['hourvia-staging+admin@example.test','hourvia-staging+contractor@example.test']);
  });
  it('rejects previews, unknown contexts, missing identity and other sites/branches even with staging secrets', () => {
    for (const context of ['deploy-preview','unknown','staging',undefined])
      expect(readServerEnv(reader(), context, identity)).toHaveProperty('unavailable');
    for (const id of [undefined, {}, { ...identity, siteId: 'another-site' }, { ...identity, branch: 'main' }, { ...identity, branch: 'Staging' }])
      expect(readServerEnv(reader(), 'branch-deploy', id)).toEqual({ unavailable: 'context_not_enabled' });
  });
  it.each([
    ['HOURVIA_AUTH_ALLOW_STAGING',''], ['HOURVIA_AUTH_LAUNCH_STAGE','general'],
    ['HOURVIA_APP_ORIGIN','https://hourvia.livingitsolutions.com'],
    ['HOURVIA_APP_ORIGIN','https://staging--hourvia-tracker.netlify.app'], ['HOURVIA_APP_ORIGIN',STAGING_ORIGIN+'/'],
    ['HOURVIA_AUTH_SMOKE_TEST_EMAILS',''], ['HOURVIA_AUTH_SMOKE_TEST_EMAILS','person@example.test'],
    ['HOURVIA_AUTH_SMOKE_TEST_EMAILS','hourvia-staging+admin@example.test,invalid'],
    ['HOURVIA_STAGING_DATABASE_VERIFIED_TARGET',''], ['HOURVIA_STAGING_DATABASE_VERIFIED_TARGET','staging:M7:other.db.netlify.com'],
    ['NETLIFY_DB_URL',''], ['NETLIFY_DB_URL','https://staging.example.db.netlify.com'],
    ['SUPABASE_SECRET_KEY',''], ['HOURVIA_AUTH_HASH_KEY','short'],
  ])('fails closed for %s misconfiguration', (key,value) => {
    expect(readServerEnv(reader({ [key]:value }), 'branch-deploy', identity)).toHaveProperty('unavailable');
  });
  it('does not change production gates, even when staging variables are present', () => {
    expect(readServerEnv(reader(), 'production', identity)).toEqual({ unavailable: 'production_not_enabled' });
    const production = readServerEnv(reader({ HOURVIA_AUTH_ALLOW_PRODUCTION:'true', HOURVIA_APP_ORIGIN:'https://hourvia.livingitsolutions.com', HOURVIA_AUTH_LAUNCH_STAGE:'general' }), 'production', identity);
    expect('config' in production && production.config.smokeTestEmails).toBeNull();
  });
  it('rejects unauthorized deployments before connecting to a database', async () => {
    const result = await runtimeDeps(reader(), 'deploy-preview', identity)();
    expect(result).toHaveProperty('unavailable'); expect(db.connect).not.toHaveBeenCalled();
  });
  it('binds build branch/site metadata to the actual function deploy, ignoring spoofed request headers', async () => {
    vi.stubGlobal('Netlify', { env:{ get:reader() } });
    db.connect.mockResolvedValue({ query:vi.fn().mockResolvedValue({ rows:[{ ok:true }] }), release:vi.fn() });
    const context={ ip:'203.0.113.10',site:{ id:STAGING_SITE_ID },deploy:{ context:'branch-deploy',id:'synthetic-deploy' } } as Context;
    const request=()=>new Request(STAGING_ORIGIN+'/api/auth/session',{ headers:{ 'x-branch':'staging','x-nf-site-id':STAGING_SITE_ID } });
    expect((await handler(request(),context)).status).toBe(401);
    db.connect.mockClear();
    for (const bad of [
      { ...context, deploy:{ ...context.deploy,id:'another-deploy' } },
      { ...context, site:{ id:'another-site' } },
      { ...context, deploy:{ ...context.deploy,context:'deploy-preview' } },
    ]) expect((await handler(request(),bad as Context)).status).toBe(503);
    manifest.branch='feature/staging';
    expect((await handler(request(),context)).status).toBe(503);
    expect(db.connect).not.toHaveBeenCalled();
  });
  it('blocks runtime wiring when live database readiness is false', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ ok:false }] });
    const release = vi.fn(); db.connect.mockResolvedValue({ query, release });
    expect(await runtimeDeps(reader(), 'branch-deploy', identity)()).toEqual({ unavailable:'staging_database_not_ready' });
    expect(query.mock.calls.map(c=>c[0])).toEqual(['BEGIN READ ONLY',STAGING_DATABASE_CHECK,'ROLLBACK']);
    expect(release).toHaveBeenCalledWith(undefined);
  });
  it('allows runtime wiring only after a successful read-only readiness check', async () => {
    db.connect.mockResolvedValue({ query:vi.fn().mockResolvedValue({ rows:[{ ok:true }] }), release:vi.fn() });
    expect(await runtimeDeps(reader(), 'branch-deploy', identity)()).toHaveProperty('provider');
  });
  it('fails on missing schema and destroys a connection if rollback fails', async () => {
    const release = vi.fn();
    const query = vi.fn().mockResolvedValueOnce({ rows:[] }).mockRejectedValueOnce(new Error('missing schema')).mockResolvedValueOnce({ rows:[] });
    await expect(stagingDatabaseReady({ connect:async()=>({ query, release }) })).rejects.toThrow('missing schema');
    expect(release).toHaveBeenCalledWith(undefined);
    const broken = vi.fn().mockResolvedValueOnce({ rows:[] }).mockResolvedValueOnce({ rows:[{ ok:true }] }).mockRejectedValueOnce(new Error('rollback'));
    await expect(stagingDatabaseReady({ connect:async()=>({ query:broken, release }) })).rejects.toThrow('staging_check_rollback_failed');
    expect(release).toHaveBeenLastCalledWith(expect.any(Error));
  });
});

describe('staging HTTP and invitation behavior with synthetic identities only', () => {
  it('enforces staging origin/CSRF, allowlist, cookie flags and invitation redirects', async () => {
    const h = await createHarness({ config:config() });
    try {
      // Validate the readiness query against the real synthetic M7 schema as well as mocked failure paths.
      expect((await h.pg.query<{ ok:boolean }>(STAGING_DATABASE_CHECK)).rows[0]?.ok).toBe(true);
      const makeDeps = async () => h.deps;
      const request = (path:string, body:unknown, origin=STAGING_ORIGIN, cookie?:string) => handleAuthRequest(new Request(STAGING_ORIGIN+path, {
        method:'POST', headers:{ origin, 'content-type':'application/json', ...(cookie?{ cookie:`__Host-hourvia_session=${cookie}` }:{}) }, body:JSON.stringify(body),
      }), '203.0.113.10', makeDeps);
      for (const origin of ['https://alias.example.test','https://staging--hourvia-tracker.netlify.app'])
        expect((await handleAuthRequest(new Request(origin+'/api/auth/session'), '203.0.113.10', makeDeps)).status).toBe(421);
      for (const origin of ['https://evil.example.test','https://staging--hourvia-tracker.netlify.app'])
        expect((await request('/api/auth/login',{},origin)).status).toBe(403);
      await h.seedMember('outsider@example.test','contractor');
      expect((await request('/api/auth/login',{ email:'outsider@example.test', password:'correct horse battery' })).status).toBe(401);
      expect(h.provider.issued).toHaveLength(0);
      const admin=await h.seedMember('hourvia-staging+admin@example.test','workspace_admin');
      const login=await request('/api/auth/login',{ email:admin.email,password:admin.password });
      expect(login.status).toBe(200);
      const cookieHeader=login.headers.get('set-cookie')!;
      for (const flag of ['__Host-hourvia_session=','HttpOnly','Secure','SameSite=Strict','Path=/']) expect(cookieHeader).toContain(flag);
      expect(cookieHeader).not.toMatch(/Domain=/i);
      const token=cookieHeader.match(/^__Host-hourvia_session=([^;]+)/)![1]!;
      const invite={ email:'hourvia-staging+contractor@example.test',role:'contractor' };
      expect((await request('/api/admin/invitations',invite,STAGING_ORIGIN,token)).status).toBe(503);
      expect(h.provider.invited).toHaveLength(0);
      h.config.emailDeliveryAuthorized=true; // Fake provider only: no SMTP or Supabase traffic.
      const inviteSpy=vi.spyOn(h.provider,'inviteUser');
      expect((await request('/api/admin/invitations',invite,STAGING_ORIGIN,token)).status).toBe(201);
      expect(inviteSpy).toHaveBeenCalledWith(invite.email,'https://staging.hourvia.livingitsolutions.com/accept-invite');
      const tokenHash=h.provider.tokenFor(invite.email,h.provider.inviteTokens)!;
      expect((await request('/api/auth/invitations/accept',{ tokenHash,password:'synthetic long passphrase' })).status).toBe(200);
      const recoverySpy=vi.spyOn(h.provider,'sendRecovery');
      expect((await request('/api/auth/recovery/request',{ email:admin.email })).status).toBe(202);
      expect(recoverySpy).toHaveBeenCalledWith(admin.email,'https://staging.hourvia.livingitsolutions.com/reset-password');
    } finally { await h.pg.close(); }
  });
});
