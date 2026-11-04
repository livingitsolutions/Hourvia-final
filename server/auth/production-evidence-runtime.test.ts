// End-to-end offline wiring: real evidence parser, readiness checks and cache with the real pool handling.
import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('./deployment-identity', () => ({ deploymentIdentity: {
  siteId: '48d7a24b-6072-40bc-866f-0d6e43a921ea', branch: 'main', context: 'production', deployId: 'a'.repeat(24), commit: 'b'.repeat(40),
} }));
vi.mock('@netlify/database', () => ({ getDatabase: vi.fn(), getConnectionString: vi.fn() }));
vi.mock('./config', () => ({ readServerEnv: vi.fn() }));
import { getDatabase, getConnectionString } from '@netlify/database';
import { readServerEnv } from './config';
import { deploymentIdentity as build } from './deployment-identity';
import { catalogDigest, CATALOG_FINGERPRINT, MIGRATION_HISTORY_SOURCE, MIGRATIONS, resetReadinessCache, targetDigest } from './production-database';
import { resetPlatformPoolForTests, runtimeDeps } from './runtime';

const url = 'postgresql://production.db.netlify.com/netlifydb';
const rotated = 'postgresql://fixture-user:fixture-rotated@production.db.netlify.com/netlifydb';
const runtime = { siteId: build.siteId, deployId: build.deployId, published: true };
const evidence = JSON.stringify({
  siteId: build.siteId, commit: build.commit, branch: 'production', targetDigest: targetDigest(url), catalogDigest: catalogDigest({ fixture: true }),
  migrationHistory: { source: MIGRATION_HISTORY_SOURCE, target: 'production', applied: [...MIGRATIONS], pending: [], missingOnDisk: [], outOfOrder: [] },
  reviewer: 'offline reviewer', approvalRef: 'offline-test',
  verifiedAt: new Date(Date.now() - 7200_000).toISOString(), smokeWindowStart: new Date(Date.now() - 3600_000).toISOString(),
  smokeWindowEnd: new Date(Date.now() + 86400_000).toISOString(),
});
const env = (key: string) => key === 'NETLIFY_DB_URL' ? url : key === 'HOURVIA_PRODUCTION_DATABASE_EVIDENCE' ? evidence : undefined;
const makePool = () => {
  const query = vi.fn(async (sql: string) => sql === CATALOG_FINGERPRINT ? { rows: [{ catalog: { fixture: true } }] } : { rows: [{ ok: true }], command: 'COMMIT' });
  return { query, connect: vi.fn(async () => ({ query, release: vi.fn() })), on: vi.fn(), end: vi.fn(async () => undefined) };
};
const readinessRuns = (pool: ReturnType<typeof makePool>) => pool.query.mock.calls.filter(c => c[0] === CATALOG_FINGERPRINT).length;
beforeEach(() => {
  vi.clearAllMocks(); resetPlatformPoolForTests(); resetReadinessCache();
  vi.mocked(readServerEnv).mockReturnValue({ config: {} as never, supabase: { url: 'https://offline.example.test', anonKey: 'public-fixture', serviceRoleKey: 'private-fixture' } });
});
describe('evidence-gated runtime wiring', () => {
  it('caches a verified success, and re-verifies after credential rotation on a rebuilt pool', async () => {
    const first = makePool(), second = makePool();
    vi.mocked(getDatabase).mockReturnValueOnce({ pool: first } as never).mockReturnValueOnce({ pool: second } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    expect('store' in await runtimeDeps(env, 'production', runtime)()).toBe(true);
    expect('store' in await runtimeDeps(env, 'production', runtime)()).toBe(true);
    expect(readinessRuns(first)).toBe(1);
    vi.mocked(getConnectionString).mockReturnValue(rotated);
    expect('store' in await runtimeDeps(env, 'production', runtime)()).toBe(true);
    expect(readinessRuns(second)).toBe(1);
    expect(first.end).toHaveBeenCalledOnce();
  });
  it('refuses wrong runtime deployment identity and missing evidence before any pool exists', async () => {
    for (const [e, r] of [[env, { ...runtime, deployId: 'c'.repeat(24) }], [env, { ...runtime, published: false }],
      [(key: string) => key === 'NETLIFY_DB_URL' ? url : undefined, runtime]] as const) {
      expect(await runtimeDeps(e, 'production', r)()).toEqual({ unavailable: 'database_not_verified' });
    }
    expect(getDatabase).not.toHaveBeenCalled();
  });
  it('fails closed when a warm instance binding moves to another target', async () => {
    vi.mocked(getDatabase).mockReturnValue({ pool: makePool() } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    expect('store' in await runtimeDeps(env, 'production', runtime)()).toBe(true);
    vi.mocked(getConnectionString).mockReturnValue('postgresql://other.db.netlify.com/netlifydb');
    await expect(runtimeDeps(env, 'production', runtime)()).rejects.toThrow('database_binding_mismatch');
    expect(getDatabase).toHaveBeenCalledOnce();
  });
});
