import { createHash } from 'node:crypto';
import type { EnvReader } from './config';
import { deploymentIdentity } from './deployment-identity';
import { deploymentAllowed, type RuntimeIdentity } from './production-policy';
import { CATALOG_CHECKS } from './production-catalog';

export const MIGRATIONS = [
  '20261103170000_create-auth-foundation', '20261103170100_restrict-auth-runtime-role',
  '20261104120000_super-admin-role', '20261104130000_platform-privileges-correction',
  '20261104150000_platform-administration-read-access', '20261104160000_pin-function-search-path-pg-temp',
  '20261104170000_organizations-expand',
] as const;
export const MIGRATION_DIGESTS = {
  "20261103170000_create-auth-foundation": "fa614b04e8caf8faf4ee82ff211c5fb78c2853f16cba765775919452bd39fe2a",
  "20261103170100_restrict-auth-runtime-role": "58be1ffd2ca6bc247ebbee88662aa3035d1a183492746004a4de413f7525f037",
  "20261104120000_super-admin-role": "8476f1a8ba50cacd083d53d67bdda01b4903494bf3cb982f93cb39e38bef132f",
  "20261104130000_platform-privileges-correction": "1c275a67a062e76c51cfc16558ab30fac4f0ee4193ef2c0ef333928693c1591e",
  "20261104150000_platform-administration-read-access": "b1f199ea303d7e1c437c5a56d6060a9f33bd746392c7e8a6bca8c659c255aea0",
  "20261104160000_pin-function-search-path-pg-temp": "a1ff5af790a69ff9b83c6a8ff49f4718707cb8db8be71a79a1e94df0c6544d44",
  "20261104170000_organizations-expand": "9f483233ba7dc2e762ae50890e029478b2d57a4c618e7cc4e3f76e7bfc502576"
} as const;
interface Client { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; release(error?: boolean | Error): void }
interface Pool { connect(): Promise<Client> }
const hash = (s: string) => createHash('sha256').update(s).digest('hex');

/** No credentials in the digest: normalized endpoint, port and database only. Never log the input. */
export function targetDigest(raw: string | undefined): string | null {
  try {
    const u = new URL(raw ?? '');
    if (!['postgres:', 'postgresql:'].includes(u.protocol) || !u.hostname.endsWith('.db.netlify.com') || u.pathname.length < 2) return null;
    return hash(JSON.stringify([u.hostname.toLowerCase(), u.port || '5432', decodeURIComponent(u.pathname)]));
  } catch { return null; }
}

// Definitions and ACLs, not account/session/audit rows. Include source and enabled trigger state to detect drift.
export const CATALOG_FINGERPRINT = `SELECT jsonb_build_object(
 'tables', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.relname) FROM (
   SELECT c.relname,c.relowner::regrole::text,c.relacl,c.relrowsecurity,c.relforcerowsecurity
   FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p')) t),
 'columns', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.relname,t.attnum) FROM (
   SELECT c.relname,a.attnum,a.attname,a.atttypid::regtype::text,a.attnotnull,a.attacl,pg_get_expr(d.adbin,d.adrelid) AS def
   FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped) t),
 'constraints', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.relname,t.conname) FROM (
   SELECT c.conrelid::regclass::text AS relname,c.conname,c.convalidated,pg_get_constraintdef(c.oid) AS def
   FROM pg_constraint c WHERE c.connamespace='public'::regnamespace) t),
 'functions', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.signature) FROM (
   SELECT p.oid::regprocedure::text AS signature,p.proowner::regrole::text,p.proacl,pg_get_functiondef(p.oid) AS def
   FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hourvia\\_%') t),
 'triggers', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.relname,t.tgname) FROM (
   SELECT g.tgrelid::regclass::text AS relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid) AS def
   FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace='public'::regnamespace AND NOT g.tgisinternal) t),
 'role', (SELECT to_jsonb(t) FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls
   FROM pg_roles WHERE rolname='hourvia_auth_runtime') t),
 'memberships', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.role,t.member) FROM (
   SELECT roleid::regrole::text AS role,member::regrole::text AS member,admin_option
   FROM pg_auth_members WHERE roleid='hourvia_auth_runtime'::regrole OR member='hourvia_auth_runtime'::regrole) t)
) AS catalog`;
export const catalogDigest = (catalog: unknown): string => hash(JSON.stringify(catalog));

export const MAX_SMOKE_WINDOW_MS = 7 * 24 * 3600_000;
export const READINESS_CACHE_MS = 60_000;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const instant = (value: unknown): number | null => {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === value.slice(0, 19) ? ms : null;
};
const text = (value: unknown) => typeof value === 'string' && value.trim().length > 0 && value.length <= 200;
const emptyList = (value: unknown) => Array.isArray(value) && value.length === 0;
const exactKeys = (value: unknown, keys: readonly string[]) => !!value && typeof value === 'object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
export const EVIDENCE_FIELDS = ['siteId', 'commit', 'branch', 'targetDigest', 'catalogDigest', 'migrationHistory',
  'reviewer', 'approvalRef', 'verifiedAt', 'smokeWindowStart', 'smokeWindowEnd'] as const;
export const MIGRATION_HISTORY_FIELDS = ['source', 'target', 'applied', 'pending', 'missingOnDisk', 'outOfOrder'] as const;
export const MIGRATION_HISTORY_SOURCE = 'netlify db status --branch production --json';
export interface DatabaseEvidence { targetDigest: string; catalogDigest: string; smokeWindowEnd: number }

/**
 * Operator attestation, bound to the exact site, commit, production database branch, live target digest and approved
 * catalog digest. It deliberately carries no deploy ID: Function environment is fixed per deploy, so an operator can
 * only bind evidence to a commit and publish it with a reviewed redeploy of that same commit. The running artifact is
 * still bound to its own build-stamped deploy ID by deploymentAllowed(). Any unknown, missing or extra field fails.
 */
export function databaseEvidence(env: EnvReader, runtime: RuntimeIdentity | undefined, now = Date.now()): DatabaseEvidence | null {
  try {
    if (!deploymentAllowed(runtime)) return null;
    const p = JSON.parse(env('HOURVIA_PRODUCTION_DATABASE_EVIDENCE') ?? '');
    if (!exactKeys(p, EVIDENCE_FIELDS)) return null;
    const target = targetDigest(env('NETLIFY_DB_URL'));
    if (!target || p.targetDigest !== target || p.siteId !== deploymentIdentity.siteId || p.commit !== deploymentIdentity.commit
      || p.branch !== 'production' || !/^[a-f0-9]{64}$/.test(p.catalogDigest) || !text(p.reviewer) || !text(p.approvalRef)) return null;
    const h = p.migrationHistory;
    if (!exactKeys(h, MIGRATION_HISTORY_FIELDS) || h.source !== MIGRATION_HISTORY_SOURCE || h.target !== 'production'
      || JSON.stringify(h.applied) !== JSON.stringify(MIGRATIONS)
      || !emptyList(h.pending) || !emptyList(h.missingOnDisk) || !emptyList(h.outOfOrder)) return null;
    const verifiedAt = instant(p.verifiedAt), start = instant(p.smokeWindowStart), end = instant(p.smokeWindowEnd);
    if (verifiedAt === null || start === null || end === null) return null;
    // Verification precedes the window; the whole window, and the evidence age at its end, are at most 7 days.
    if (verifiedAt > start || start >= end || end - start > MAX_SMOKE_WINDOW_MS || end - verifiedAt > MAX_SMOKE_WINDOW_MS
      || verifiedAt > now || start > now || end <= now) return null;
    return { targetDigest: target, catalogDigest: p.catalogDigest, smokeWindowEnd: end };
  } catch { return null; }
}

// One per-instance success entry. Failures are never cached. The key covers runtime and build identity, the live
// target digest and the exact evidence text; the pool object must also be the same (a rebuilt pool misses).
let readinessSuccess: { key: string; pool: Pool; until: number } | null = null;
export function resetReadinessCache(): void { readinessSuccess = null; }
const readinessKey = (env: EnvReader, runtime: RuntimeIdentity | undefined, evidence: DatabaseEvidence) => hash(JSON.stringify([
  runtime?.siteId, runtime?.deployId, runtime?.published, deploymentIdentity, evidence.targetDigest,
  env('HOURVIA_PRODUCTION_DATABASE_EVIDENCE') ?? '',
]));

/**
 * Evidence is operator-controlled, independently verified metadata, never inferred from a successful connection.
 * Production migration history is verified by the operator through supported Netlify tooling and attested in the
 * evidence; the platform ledger is not queried here. The live structural postconditions and full catalog fingerprint
 * are checked in one read-only transaction.
 */
export async function productionDatabaseReady(pool: () => Pool, env: EnvReader, runtime: RuntimeIdentity | undefined,
  now = Date.now()): Promise<boolean> {
  const evidence = databaseEvidence(env, runtime, now);
  if (!evidence) { readinessSuccess = null; return false; }
  const verifiedPool = pool(); // Re-validates the live binding against the expected target on every request.
  const key = readinessKey(env, runtime, evidence);
  if (readinessSuccess && readinessSuccess.key === key && readinessSuccess.pool === verifiedPool && now < readinessSuccess.until) return true;
  readinessSuccess = null;
  const client = await verifiedPool.connect();
  let destroy: Error | undefined;
  let ready = false;
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SET LOCAL statement_timeout = '5s'");
    for (const sql of CATALOG_CHECKS) {
      const result = await client.query(sql);
      if (result.rows.length !== 1 || (result.rows[0] as { ok?: unknown }).ok !== true) return false;
    }
    const result = await client.query(CATALOG_FINGERPRINT);
    ready = result.rows.length === 1 && catalogDigest((result.rows[0] as { catalog: unknown }).catalog) === evidence.catalogDigest;
  } catch { ready = false; }
  finally {
    try { await client.query('ROLLBACK'); } catch { destroy = new Error('readiness_rollback_failed'); }
    client.release(destroy);
  }
  if (!ready || destroy) return false;
  readinessSuccess = { key, pool: verifiedPool, until: Math.min(now + READINESS_CACHE_MS, evidence.smokeWindowEnd) };
  return true;
}
