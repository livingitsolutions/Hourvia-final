import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('./deployment-identity', () => ({ deploymentIdentity: {
  siteId: '48d7a24b-6072-40bc-866f-0d6e43a921ea', branch: 'main', context: 'production', deployId: 'a'.repeat(24), commit: 'b'.repeat(40),
} }));
import { deploymentIdentity as build } from './deployment-identity';
import {
  catalogDigest, CATALOG_FINGERPRINT, databaseEvidence, MAX_SMOKE_WINDOW_MS, MIGRATION_HISTORY_SOURCE, MIGRATIONS, MIGRATION_DIGESTS,
  productionDatabaseReady, READINESS_CACHE_MS, resetReadinessCache, targetDigest,
} from './production-database';
import { CATALOG_CHECKS } from './production-catalog';

const NOW = Date.parse('2026-11-05T12:00:00.000Z');
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const HOUR = 3600_000;
const runtime = { siteId: build.siteId, deployId: build.deployId, published: true };
const url = 'postgresql://production.db.netlify.com/netlifydb'; // Credential-free fixture only.
const history = () => ({ source: MIGRATION_HISTORY_SOURCE, target: 'production', applied: [...MIGRATIONS], pending: [], missingOnDisk: [], outOfOrder: [] });
const evidence = () => ({
  siteId: build.siteId, commit: build.commit, branch: 'production', targetDigest: targetDigest(url), catalogDigest: catalogDigest({ fixture: true }),
  migrationHistory: history(), reviewer: 'offline reviewer', approvalRef: 'offline-test',
  verifiedAt: iso(-2 * HOUR), smokeWindowStart: iso(-HOUR), smokeWindowEnd: iso(24 * HOUR),
});
const envOf = (raw: string | undefined, target = url) => (key: string) => key === 'NETLIFY_DB_URL' ? target : key === 'HOURVIA_PRODUCTION_DATABASE_EVIDENCE' ? raw : undefined;
const env = (change: Record<string, unknown> = {}, target = url) => envOf(JSON.stringify({ ...evidence(), ...change }), target);
function fake(opts: { fail?: string; rollback?: boolean; catalog?: unknown; notOk?: string } = {}) {
  const query = vi.fn(async (sql: string) => {
    if (sql === 'ROLLBACK' && opts.rollback) throw new Error('offline rollback failure');
    if (sql === opts.fail) throw new Error('offline query failure');
    if (sql === opts.notOk) return { rows: [{ ok: false }] };
    if (sql === CATALOG_FINGERPRINT) return { rows: [{ catalog: opts.catalog ?? { fixture: true } }] };
    return { rows: [{ ok: true }] };
  });
  const release = vi.fn(); const connect = vi.fn(async () => ({ query, release }));
  const pool = { connect };
  const factory = vi.fn(() => pool); return { factory, query, release, connect, pool };
}
const ready = (f: ReturnType<typeof fake>, e = env(), r: typeof runtime = runtime, now = NOW) => productionDatabaseReady(f.factory, e, r, now);
beforeEach(() => resetReadinessCache());

describe('operator evidence binding', () => {
  it('accepts exact site/commit/branch/target/catalog evidence with attested migration history', () => {
    expect(databaseEvidence(env(), runtime, NOW)).toEqual({ targetDigest: targetDigest(url), catalogDigest: catalogDigest({ fixture: true }), smokeWindowEnd: NOW + 24 * HOUR });
  });
  it('refuses missing, malformed or non-object operator evidence', () => {
    for (const raw of [undefined, '', 'not json', 'null', '[]', '"x"', '{}']) expect(databaseEvidence(envOf(raw), runtime, NOW)).toBeNull();
  });
  it('refuses a legacy deployId field, unknown fields and missing fields', () => {
    expect(databaseEvidence(env({ deployId: build.deployId }), runtime, NOW)).toBeNull();
    expect(databaseEvidence(env({ expiresAt: iso(HOUR) }), runtime, NOW)).toBeNull();
    for (const field of Object.keys(evidence())) {
      const e = evidence() as Record<string, unknown>; delete e[field];
      expect(databaseEvidence(envOf(JSON.stringify(e)), runtime, NOW)).toBeNull();
    }
  });
  it('refuses wrong deployment identity even with otherwise valid evidence', () => {
    for (const r of [undefined, { ...runtime, deployId: 'c'.repeat(24) }, { ...runtime, published: false }, { ...runtime, siteId: 'wrong' }, { siteId: runtime.siteId }])
      expect(databaseEvidence(env(), r as typeof runtime, NOW)).toBeNull();
  });
  it('refuses wrong site, commit, branch, digests and reviewer metadata', () => {
    for (const change of [{ siteId: 'wrong' }, { commit: 'c'.repeat(40) }, { branch: 'main' }, { branch: 'deploy-preview' }, { catalogDigest: 'short' },
      { catalogDigest: 'A'.repeat(64) }, { reviewer: '' }, { reviewer: ' ' }, { approvalRef: '' }, { approvalRef: 7 }, { reviewer: 'x'.repeat(201) }])
      expect(databaseEvidence(env(change), runtime, NOW)).toBeNull();
  });
  it('refuses a target mismatch between evidence and the injected binding', () => {
    expect(databaseEvidence(env({ targetDigest: targetDigest('postgresql://other.db.netlify.com/netlifydb') }), runtime, NOW)).toBeNull();
    expect(databaseEvidence(env({}, 'postgresql://other.db.netlify.com/netlifydb'), runtime, NOW)).toBeNull();
    expect(databaseEvidence(env({}, 'postgresql://production.db.netlify.com/otherdb'), runtime, NOW)).toBeNull();
    expect(databaseEvidence(env({}, 'postgresql://evil.example.test/netlifydb'), runtime, NOW)).toBeNull();
    expect(databaseEvidence(env({}, ''), runtime, NOW)).toBeNull();
    // Credentials and query parameters are not part of the target identity.
    expect(targetDigest('postgresql://u:p@production.db.netlify.com/netlifydb?sslmode=require')).toBe(targetDigest(url));
    expect(targetDigest('https://example.test')).toBeNull();
  });
  it('requires production migration history attested from supported Netlify tooling', () => {
    const h = (change: Record<string, unknown>) => ({ migrationHistory: { ...history(), ...change } });
    for (const change of [h({ source: 'manual' }), h({ target: 'main' }), h({ applied: MIGRATIONS.slice(0, 6) }), h({ applied: [...MIGRATIONS].reverse() }),
      h({ applied: [...MIGRATIONS, '20261201000000_unexpected'] }), h({ pending: [{ name: 'x' }] }), h({ missingOnDisk: [{ name: 'x' }] }),
      h({ outOfOrder: [{ name: 'x' }] }), h({ pending: undefined }), h({ checksum: 'x' }), { migrationHistory: null }, { migrationHistory: [] }])
      expect(databaseEvidence(env(change), runtime, NOW)).toBeNull();
  });
});

describe('bounded smoke window', () => {
  it('accepts an exact 7-day window and rejects an excessive one', () => {
    expect(databaseEvidence(env({ verifiedAt: iso(-HOUR), smokeWindowStart: iso(-HOUR), smokeWindowEnd: iso(MAX_SMOKE_WINDOW_MS - HOUR) }), runtime, NOW)).not.toBeNull();
    expect(databaseEvidence(env({ verifiedAt: iso(-HOUR), smokeWindowStart: iso(-HOUR), smokeWindowEnd: iso(MAX_SMOKE_WINDOW_MS - HOUR + 1) }), runtime, NOW)).toBeNull();
  });
  it('rejects expired, future, inverted, stale and out-of-order windows', () => {
    for (const change of [
      { smokeWindowEnd: iso(0) }, { smokeWindowEnd: iso(-1) },                                            // expired (end is exclusive)
      { verifiedAt: iso(1), smokeWindowStart: iso(2) },                                                  // future verification/start
      { smokeWindowStart: iso(HOUR), verifiedAt: iso(-HOUR) },                                           // window not started
      { smokeWindowStart: iso(25 * HOUR) }, { smokeWindowStart: iso(24 * HOUR) },                        // inverted / empty
      { verifiedAt: iso(-HOUR / 2) },                                                                    // verified after start
      { verifiedAt: iso(-7 * 24 * HOUR), smokeWindowStart: iso(-HOUR) },                                 // evidence older than 7 days at end
    ]) expect(databaseEvidence(env(change), runtime, NOW)).toBeNull();
  });
  it('rejects missing or malformed timestamps', () => {
    for (const field of ['verifiedAt', 'smokeWindowStart', 'smokeWindowEnd'])
      for (const value of [undefined, null, '', 123, '2026-11-05', '2026-11-05T12:00:00+01:00', '2026-11-05 12:00:00Z', '2026-02-30T00:00:00Z', 'tomorrow'])
        expect(databaseEvidence(env({ [field]: value }), runtime, NOW)).toBeNull();
  });
  it('fails closed at runtime once the window ends, even with a cached success', async () => {
    const f = fake();
    expect(await ready(f)).toBe(true);
    expect(await ready(f, env(), runtime, NOW + 24 * HOUR)).toBe(false);
    expect(f.connect).toHaveBeenCalledOnce();
  });
});

describe('live read-only checks', () => {
  it('runs structural postconditions and the fingerprint without querying the platform ledger', async () => {
    const f = fake(); expect(await ready(f)).toBe(true);
    const sent = f.query.mock.calls.map(c => c[0]);
    expect(sent).toEqual(['BEGIN READ ONLY', "SET LOCAL statement_timeout = '5s'", ...CATALOG_CHECKS, CATALOG_FINGERPRINT, 'ROLLBACK']);
    expect(sent.some(sql => /netlify\.migrations/.test(sql))).toBe(false);
  });
  it('refuses evidence problems before opening or connecting a pool', async () => {
    for (const e of [envOf(undefined), env({ commit: 'c'.repeat(40) }), env({ smokeWindowEnd: iso(-1) }), env({ targetDigest: '0'.repeat(64) })]) {
      const f = fake(); expect(await ready(f, e)).toBe(false); expect(f.factory).not.toHaveBeenCalled();
    }
    const f = fake(); expect(await ready(f, env(), { ...runtime, deployId: 'c'.repeat(24) })).toBe(false); expect(f.factory).not.toHaveBeenCalled();
  });
  it('refuses schema drift against the approved catalog digest', async () => {
    const f = fake({ catalog: { fixture: 'drifted' } }); expect(await ready(f)).toBe(false); expect(f.query).toHaveBeenLastCalledWith('ROLLBACK');
  });
  it('refuses every failed or false catalog postcondition and rolls back', async () => {
    for (const check of CATALOG_CHECKS) {
      for (const f of [fake({ fail: check }), fake({ notOk: check })]) {
        expect(await ready(f)).toBe(false); expect(f.query).toHaveBeenLastCalledWith('ROLLBACK');
        expect(f.query.mock.calls.map(c => c[0])).not.toContain(CATALOG_FINGERPRINT);
      }
    }
    const f = fake({ fail: CATALOG_FINGERPRINT }); expect(await ready(f)).toBe(false);
  });
  it('destroys a connection after rollback failure and refuses readiness', async () => {
    const f = fake({ rollback: true }); expect(await ready(f)).toBe(false); expect(f.release).toHaveBeenCalledWith(expect.any(Error));
    expect(await ready(fake())).toBe(true); // Nothing was cached from the failed attempt.
  });
  it('propagates a binding/target failure from the pool factory', async () => {
    const factory = vi.fn(() => { throw new Error('database_target_changed'); });
    await expect(productionDatabaseReady(factory, env(), runtime, NOW)).rejects.toThrow('database_target_changed');
  });
});

describe('bounded readiness success cache', () => {
  it('reuses a success for the same pool and evidence within the bound, then re-checks', async () => {
    const f = fake();
    expect(await ready(f)).toBe(true);
    expect(await ready(f, env(), runtime, NOW + READINESS_CACHE_MS - 1)).toBe(true);
    expect(f.connect).toHaveBeenCalledOnce();
    expect(f.factory).toHaveBeenCalledTimes(2); // The live binding is re-validated even on a cache hit.
    expect(await ready(f, env(), runtime, NOW + READINESS_CACHE_MS)).toBe(true);
    expect(f.connect).toHaveBeenCalledTimes(2);
  });
  it('never caches failures', async () => {
    const bad = fake({ catalog: { fixture: 'drifted' } });
    expect(await ready(bad)).toBe(false); expect(await ready(bad)).toBe(false);
    expect(bad.connect).toHaveBeenCalledTimes(2);
  });
  it('misses on evidence change, a rebuilt pool, and is cleared by invalid evidence or identity', async () => {
    const f = fake();
    expect(await ready(f)).toBe(true);
    expect(await ready(f, env({ approvalRef: 'renewed' }))).toBe(true); expect(f.connect).toHaveBeenCalledTimes(2);
    const rebuilt = fake(); expect(await productionDatabaseReady(rebuilt.factory, env({ approvalRef: 'renewed' }), runtime, NOW)).toBe(true);
    expect(rebuilt.connect).toHaveBeenCalledOnce();
    expect(await productionDatabaseReady(rebuilt.factory, env({ approvalRef: 'renewed' }), { ...runtime, published: false }, NOW)).toBe(false);
    expect(await productionDatabaseReady(rebuilt.factory, env({ approvalRef: 'renewed' }), runtime, NOW)).toBe(true);
    expect(rebuilt.connect).toHaveBeenCalledTimes(2);
  });
  it('detects drift on the first check after the cache bound', async () => {
    let catalog: object = { fixture: true };
    const f = fake(); f.query.mockImplementation(async (sql: string) => sql === CATALOG_FINGERPRINT ? { rows: [{ catalog }] } : { rows: [{ ok: true }] });
    expect(await ready(f)).toBe(true);
    catalog = { fixture: 'drifted' };
    expect(await ready(f, env(), runtime, NOW + READINESS_CACHE_MS)).toBe(false);
    expect(await ready(f, env(), runtime, NOW + READINESS_CACHE_MS + 1)).toBe(false);
  });
});

describe('migration immutability', () => {
  it('M1–M7 files on disk match their original reviewed digests', () => {
    for (const name of MIGRATIONS) {
      const bytes = readFileSync(new URL(`../../netlify/database/migrations/${name}.sql`, import.meta.url));
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(MIGRATION_DIGESTS[name]);
    }
  });
});

describe('readiness queries on disposable PostgreSQL', () => {
  it('checks real M1–M7 fixtures and detects disabled guards', async () => {
    const { createHarness } = await import('./testing/harness');
    const h = await createHarness();
    try {
      for (const sql of CATALOG_CHECKS) {
        const result = await h.pg.query<{ ok: boolean }>(sql);
        expect(result.rows).toHaveLength(1); expect(result.rows[0]!.ok).toBe(true);
      }
      const before = await h.pg.query<{ catalog: unknown }>(CATALOG_FINGERPRINT);
      await h.pg.exec('ALTER TABLE organizations DISABLE TRIGGER organizations_guard');
      const after = await h.pg.query<{ catalog: unknown }>(CATALOG_FINGERPRINT);
      expect(catalogDigest(before.rows[0]!.catalog)).not.toBe(catalogDigest(after.rows[0]!.catalog));
      const triggerCheck = await h.pg.query<{ ok: boolean }>(CATALOG_CHECKS[7]!);
      expect(triggerCheck.rows[0]!.ok).toBe(false);
    } finally { await h.pg.close(); }
  });
});
