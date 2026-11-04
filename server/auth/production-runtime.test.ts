import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('@netlify/database', () => ({ getDatabase: vi.fn(), getConnectionString: vi.fn() }));
vi.mock('./config', () => ({ readServerEnv: vi.fn() }));
vi.mock('./production-database', async original => ({ ...await original<object>(), productionDatabaseReady: vi.fn() }));
import { getDatabase, getConnectionString } from '@netlify/database';
import { readServerEnv } from './config';
import { productionDatabaseReady } from './production-database';
import { platformPool, resetPlatformPoolForTests, runtimeDeps } from './runtime';
import { targetDigest } from './production-database';
// Credential-free fixtures; the "rotated" variants differ only in fixture user/password text.
const url = 'postgresql://production.db.netlify.com/netlifydb';
const rotated = 'postgresql://fixture-user:fixture-rotated@production.db.netlify.com/netlifydb?sslmode=require';
const env = (key: string) => key === 'NETLIFY_DB_URL' ? url : undefined;
const makePool = () => {
  const query = vi.fn(async () => ({ rows: [], command: 'COMMIT' }));
  return { query, connect: vi.fn(async () => ({ query, release: vi.fn() })), on: vi.fn(), end: vi.fn(async () => undefined) };
};
beforeEach(() => { vi.clearAllMocks(); resetPlatformPoolForTests(); });
describe('runtime pool and target binding', () => {
  it('does not initialize a database or provider when configuration refuses access', async () => {
    vi.mocked(readServerEnv).mockReturnValue({ unavailable: 'context_not_enabled' });
    expect(await runtimeDeps(env, 'dev')()).toEqual({ unavailable: 'context_not_enabled' });
    expect(getDatabase).not.toHaveBeenCalled(); expect(productionDatabaseReady).not.toHaveBeenCalled();
  });
  it('refuses when readiness fails, without exposing a store', async () => {
    vi.mocked(readServerEnv).mockReturnValue({ config: {} as never, supabase: { url: 'https://offline.example.test', anonKey: 'public-fixture', serviceRoleKey: 'private-fixture' } });
    vi.mocked(productionDatabaseReady).mockResolvedValue(false);
    expect(await runtimeDeps(env, 'production')()).toEqual({ unavailable: 'database_not_verified' });
  });
  it('uses the same checked pool for store queries', async () => {
    // No provider method is invoked; dependency configuration is mocked for this wiring test only.
    vi.mocked(readServerEnv).mockReturnValue({ config: {} as never, supabase: { url: 'https://offline.example.test', anonKey: 'public-fixture', serviceRoleKey: 'private-fixture' } });
    const pool = makePool();
    vi.mocked(getDatabase).mockReturnValue({ pool } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    vi.mocked(productionDatabaseReady).mockImplementation(async factory => { expect(factory()).toBe(pool); return true; });
    const deps = await runtimeDeps(env, 'production')();
    expect('store' in deps).toBe(true);
    if ('store' in deps) await deps.store.organization();
    expect(pool.connect).toHaveBeenCalled(); expect(pool.query).toHaveBeenCalled(); expect(getDatabase).toHaveBeenCalledOnce();
  });
  it('rebuilds the pool on credential rotation for the same target and retires the old pool', async () => {
    const first = makePool(), second = makePool();
    vi.mocked(getDatabase).mockReturnValueOnce({ pool: first } as never).mockReturnValueOnce({ pool: second } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    const expected = targetDigest(url)!;
    expect(platformPool(expected)).toBe(first);
    expect(platformPool(expected)).toBe(first);
    vi.mocked(getConnectionString).mockReturnValue(rotated);
    expect(platformPool(expected)).toBe(second);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(first.end).toHaveBeenCalledOnce(); expect(second.end).not.toHaveBeenCalled();
    expect(platformPool(expected)).toBe(second);
    expect(getDatabase).toHaveBeenCalledTimes(2);
  });
  it('fails closed on a warm-instance target change and on a binding that does not match the evidence target', async () => {
    const pool = makePool();
    vi.mocked(getDatabase).mockReturnValue({ pool } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    expect(platformPool(targetDigest(url)!)).toBe(pool);
    const other = 'postgresql://other.db.netlify.com/netlifydb';
    vi.mocked(getConnectionString).mockReturnValue(other);
    // Even if the expected target also moved, the warm instance never adopts a different database target.
    expect(() => platformPool(targetDigest(other)!)).toThrow('database_target_changed');
    expect(() => platformPool(targetDigest(url)!)).toThrow('database_binding_mismatch');
    vi.mocked(getConnectionString).mockReturnValue('postgresql://evil.example.test/netlifydb');
    expect(() => platformPool(targetDigest(url)!)).toThrow('database_binding_mismatch');
    expect(getDatabase).toHaveBeenCalledOnce(); expect(pool.end).not.toHaveBeenCalled();
  });
  it('surfaces a target change through the dependency factory as a failure', async () => {
    vi.mocked(readServerEnv).mockReturnValue({ config: {} as never, supabase: { url: 'https://offline.example.test', anonKey: 'public-fixture', serviceRoleKey: 'private-fixture' } });
    vi.mocked(getDatabase).mockReturnValue({ pool: makePool() } as never);
    vi.mocked(getConnectionString).mockReturnValue(url);
    vi.mocked(productionDatabaseReady).mockImplementation(async factory => { factory(); return true; });
    expect('store' in await runtimeDeps(env, 'production')()).toBe(true);
    vi.mocked(getConnectionString).mockReturnValue('postgresql://other.db.netlify.com/netlifydb');
    await expect(runtimeDeps(env, 'production')()).rejects.toThrow('database_binding_mismatch');
  });
});
