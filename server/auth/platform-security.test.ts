// PLATFORM SECURITY HARDENING TESTS (Sprint 1.8B). Embedded Postgres (PGlite) only, never a Netlify database.
// H-1: temporary-table shadowing of relations inside hourvia_* functions. Each attack runs in a FRESH database (no cached
//      plan can mask the result) inside a runtime-role transaction that is always rolled back. It runs once against the
//      vulnerable baseline (migrations up to 20261104150000), proving the test really exercises the attack, and once
//      with 20261104160000 applied, where it must fail.
// M-1: platform request limits are checked before denial auditing and before audit-page reads.
import { describe, expect, it } from 'vitest';
import { PLATFORM_LIMITS } from './service';
import { sha256Hex } from './crypto';
import { ORGANIZATIONS_SQL, SEARCH_PATH_SQL, applyMigration, createHarness, type Harness } from './testing/harness';

const ROLLBACK = 'rollback-attack';
/** Runs fn as hourvia_auth_runtime (SET LOCAL ROLE) and always rolls back. */
async function asRuntimeRolledBack<T>(h: Harness, fn: (tx: { exec(sql: string): Promise<unknown>; query<R>(sql: string, params?: unknown[]): Promise<R[]> }) => Promise<T>): Promise<T> {
  let result: T | undefined;
  await h.sql.transaction(async tx => {
    const api = { exec: (sql: string) => tx.query(sql), query: async <R>(sql: string, params?: unknown[]) => (await tx.query<R>(sql, params)).rows };
    result = await fn(api);
    throw new Error(ROLLBACK);
  }).catch(error => { if (!(error instanceof Error) || error.message !== ROLLBACK) throw error; });
  return result as T;
}

const FORGED_HASH = 'a'.repeat(64);
const FORGED_UID = '99999999-9999-4999-8999-999999999999';

/** Attack 1: read the platform audit through the SECURITY DEFINER function with no session and no grant. */
async function platformAuditAttack(h: Harness) {
  return asRuntimeRolledBack(h, async tx => {
    for (const sql of [
      `CREATE TEMP TABLE auth_sessions (token_hash text, member_id uuid, revoked_at timestamptz, idle_expires_at timestamptz, absolute_expires_at timestamptz) ON COMMIT DROP`,
      `CREATE TEMP TABLE workspace_members (id uuid, workspace_id text, status text, auth_user_id uuid, email text, activated_at timestamptz, role text) ON COMMIT DROP`,
      `CREATE TEMP TABLE platform_super_admin_designation (auth_user_id uuid, designated_at timestamptz) ON COMMIT DROP`,
      `CREATE TEMP TABLE platform_privileges (auth_user_id uuid, privilege text, revoked_at timestamptz, granted_at timestamptz, grant_approval_ref text) ON COMMIT DROP`,
      `INSERT INTO auth_sessions VALUES ('${FORGED_HASH}', '${FORGED_UID}', NULL, now() + interval '1 hour', now() + interval '1 hour')`,
      `INSERT INTO workspace_members VALUES ('${FORGED_UID}', 'thrivesource', 'active', '${FORGED_UID}', 'livingitsolutions@gmail.com', now(), 'contractor')`,
      `INSERT INTO platform_super_admin_designation VALUES ('${FORGED_UID}', now())`,
      `INSERT INTO platform_privileges VALUES ('${FORGED_UID}', 'platform_super_admin', NULL, now(), 'FORGED-1')`,
    ]) await tx.exec(sql);
    const audit = (await tx.query<{ p: { events: { event_type: string; details: Record<string, unknown> }[] } | null }>(`SELECT hourvia_platform_audit_page($1, NULL, 10) AS p`, [FORGED_HASH]))[0]!.p;
    const overview = (await tx.query<{ o: unknown }>(`SELECT hourvia_platform_overview($1) AS o`, [FORGED_HASH]))[0]!.o;
    return { audit, overview };
  });
}

/** Attack 2: an ordinary Administrator promotes a Contractor to Administrator by shadowing platform_privileges. */
async function rolePromotionAttack(h: Harness, admin: { id: string; authUserId: string }, targetId: string) {
  return asRuntimeRolledBack(h, async tx => {
    await tx.exec(`CREATE TEMP TABLE platform_privileges (auth_user_id uuid, privilege text, revoked_at timestamptz) ON COMMIT DROP`);
    await tx.query(`INSERT INTO platform_privileges VALUES ($1, 'platform_super_admin', NULL)`, [admin.authUserId]);
    try {
      await tx.query(`UPDATE workspace_members SET role = 'workspace_admin', role_changed_by = $2, role_changed_at = now() WHERE id = $1`, [targetId, admin.id]);
      return { allowed: true as const, role: (await tx.query<{ role: string }>(`SELECT role FROM workspace_members WHERE id = $1`, [targetId]))[0]!.role };
    } catch (error) { return { allowed: false as const, error: (error as Error).message }; }
  });
}

async function seededAuditDatabase(searchPathFix: boolean) {
  const h = await createHarness({ now: new Date(), searchPathFix });
  // A confidential platform audit row, written by the owner, that no runtime caller may read without a holder session.
  await h.pg.query(`INSERT INTO platform_audit_events (event_type, outcome, details) VALUES ('platform_privilege_granted', 'success', '{"approval_ref":"SECRET-REF-1"}')`);
  return h;
}
async function seededRoleDatabase(searchPathFix: boolean) {
  const h = await createHarness({ now: new Date(), searchPathFix });
  const admin = await h.seedMember('ada@t.test', 'workspace_admin');
  const target = await h.seedMember('cy@t.test', 'contractor');
  return { h, admin, target };
}
const auditCount = async (h: Harness) => (await h.pg.query<{ n: number }>(`SELECT count(*)::int AS n FROM platform_audit_events`)).rows[0]!.n;

describe('H-1 regression: temporary-table shadowing', () => {
  it('baseline without 20261104160000: both attacks succeed (proves the tests exercise the real vector)', async () => {
    const a = await seededAuditDatabase(false);
    const stolen = await platformAuditAttack(a);
    expect(stolen.audit?.events.map(e => e.details.approval_ref)).toContain('SECRET-REF-1');
    expect(stolen.overview).not.toBeNull();
    expect(await auditCount(a)).toBe(1); // rolled back: the forged audit-read row did not persist

    const { h, admin, target } = await seededRoleDatabase(false);
    expect(await rolePromotionAttack(h, admin, target.id)).toEqual({ allowed: true, role: 'workspace_admin' });
    expect((await h.pg.query(`SELECT role FROM workspace_members WHERE id = $1`, [target.id])).rows).toEqual([{ role: 'contractor' }]); // rolled back
  });

  it('after 20261104160000: unauthorized platform audit access fails (NULL, nothing returned, nothing written)', async () => {
    const h = await seededAuditDatabase(true);
    const attempt = await platformAuditAttack(h);
    expect(attempt).toEqual({ audit: null, overview: null });
    expect(await auditCount(h)).toBe(1);
  });

  it('after 20261104160000: unauthorized workspace role promotion fails in the database guard', async () => {
    const { h, admin, target } = await seededRoleDatabase(true);
    const attempt = await rolePromotionAttack(h, admin, target.id);
    expect(attempt.allowed).toBe(false);
    expect(attempt).toMatchObject({ error: expect.stringMatching(/not authorized/) });
    expect((await h.pg.query(`SELECT role FROM workspace_members WHERE id = $1`, [target.id])).rows).toEqual([{ role: 'contractor' }]);
  });

  it('after 20261104160000: a Contractor disguised as an Administrator in a temp workspace_members cannot promote anyone', async () => {
    const { h, target } = await seededRoleDatabase(true);
    const other = await h.seedMember('dee@t.test', 'contractor');
    const attempt = await asRuntimeRolledBack(h, async tx => {
      await tx.exec(`CREATE TEMP TABLE workspace_members (id uuid, workspace_id text, status text, role text, auth_user_id uuid) ON COMMIT DROP`);
      await tx.query(`INSERT INTO workspace_members VALUES ($1, 'thrivesource', 'active', 'workspace_admin', $2)`, [target.id, target.authUserId]);
      await tx.exec(`CREATE TEMP TABLE platform_privileges (auth_user_id uuid, privilege text, revoked_at timestamptz) ON COMMIT DROP`);
      await tx.query(`INSERT INTO platform_privileges VALUES ($1, 'platform_super_admin', NULL)`, [target.authUserId]);
      try { await tx.query(`UPDATE public.workspace_members SET role = 'workspace_admin', role_changed_by = $2, role_changed_at = now() WHERE id = $1`, [other.id, target.id]); return 'allowed'; }
      catch (error) { return (error as Error).message; }
    });
    expect(attempt).toMatch(/not authorized/);
    expect((await h.pg.query(`SELECT role FROM workspace_members WHERE id = $1`, [other.id])).rows).toEqual([{ role: 'contractor' }]);
  });

  it('preserves signatures, SECURITY DEFINER flags, ownership and EXECUTE grants, and pins pg_temp last everywhere', async () => {
    const before = await createHarness({ searchPathFix: false });
    // Sprint 2.0B: compare against the database as 20261104160000 left it (M7 adds one function; its own test covers it).
    const after = await createHarness({ organizations: false });
    const catalog = (h: Harness) => h.pg.query<{ f: string; secdef: boolean; vol: string; owner: string; acl: string | null; body: string; config: string[] | null }>(
      `SELECT p.oid::regprocedure::text AS f, p.prosecdef AS secdef, p.provolatile AS vol, pg_get_userbyid(p.proowner) AS owner, p.proacl::text AS acl, p.prosrc AS body, p.proconfig AS config
       FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\\_%' ORDER BY 1`);
    const b = (await catalog(before)).rows; const a = (await catalog(after)).rows;
    expect(a).toHaveLength(15);
    expect(a.map(({ config: _c, ...rest }) => rest)).toEqual(b.map(({ config: _c, ...rest }) => rest));
    for (const row of a) expect(row.config, row.f).toEqual(['search_path=pg_catalog, public, pg_temp']);
    expect(a.filter(r => r.secdef).map(r => r.f)).toEqual(['hourvia_platform_audit_page(text,bigint,integer)', 'hourvia_platform_overview(text)']);
    expect((await after.pg.query(`SELECT has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE') AS c`)).rows).toEqual([{ c: false }]);
  });

  it('aborts (and rolls back) on an unexpected hourvia_* function or if the runtime can CREATE in public', async () => {
    const extra = await createHarness({ searchPathFix: false });
    await extra.pg.exec(`CREATE FUNCTION hourvia_unreviewed() RETURNS int LANGUAGE sql AS 'SELECT 1'`);
    await expect(applyMigration(extra.pg, SEARCH_PATH_SQL)).rejects.toThrow(/unexpected hourvia_\* functions/);
    expect((await extra.pg.query(`SELECT proconfig FROM pg_proc WHERE proname = 'hourvia_member_authority'`)).rows).toEqual([{ proconfig: ['search_path=pg_catalog, public'] }]);

    const create = await createHarness({ searchPathFix: false });
    await create.pg.exec(`GRANT CREATE ON SCHEMA public TO hourvia_auth_runtime`);
    await expect(applyMigration(create.pg, SEARCH_PATH_SQL)).rejects.toThrow(/can CREATE in public/);

    const early = await createHarness({ platformAdmin: false });
    await expect(applyMigration(early.pg, SEARCH_PATH_SQL)).rejects.toThrow(/apply 20261104150000 first/);
  });

  it('changes no row when applied over a live holder, and existing sessions keep working', async () => {
    const h = await createHarness({ now: new Date(), searchPathFix: false });
    const s = await h.seedPlatformSuperAdmin();
    // Sprint 2.0B: the current store needs M7, which requires 20261104160000, so the pre-existing session is created the
    // way the 799f042 store creates one (same INSERT, same column list) instead of through a login.
    const cookie = 'S'.repeat(43);
    await h.sql.query(`INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, now(), now(), now() + interval '30 minutes', now() + interval '12 hours')`, [sha256Hex(cookie), s.id]);
    const snapshot = async () => (await h.pg.query(`SELECT (SELECT json_agg(m ORDER BY m.id) FROM workspace_members m) AS m, (SELECT json_agg(p ORDER BY p.id) FROM platform_privileges p) AS p,
      (SELECT json_agg(e ORDER BY e.id) FROM platform_audit_events e) AS e, (SELECT json_agg(a ORDER BY a.id) FROM auth_audit_events a) AS a, (SELECT json_agg(x ORDER BY x.id) FROM auth_sessions x) AS s`)).rows[0];
    const before = await snapshot();
    await applyMigration(h.pg, SEARCH_PATH_SQL);
    expect(await snapshot()).toEqual(before);
    await applyMigration(h.pg, ORGANIZATIONS_SQL);
    expect((await h.call('GET', '/api/platform/overview', { cookie })).status).toBe(200);
    expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(200);
  });
});

describe('M-1: platform request limits', () => {
  const overview = (h: Harness, cookie: string, ip?: string) => h.call('GET', '/api/platform/overview', { cookie, ip });
  const count = async (h: Harness, sql: string) => (await h.pg.query<{ n: number }>(sql)).rows[0]!.n;
  const deniedRows = (h: Harness) => count(h, `SELECT count(*)::int AS n FROM auth_audit_events WHERE event_type = 'platform_access' AND outcome = 'denied'`);
  const limitedRows = (h: Harness, limit: string) => count(h, `SELECT count(*)::int AS n FROM auth_audit_events WHERE event_type = 'rate_limited' AND details->>'limit' = '${limit}'`);

  it('limits a non-holder before denial auditing: 403 up to the limit, then 429 with one rate_limited row per window', async () => {
    const h = await createHarness({ now: new Date() });
    const s = await h.seedPlatformSuperAdmin();
    const m = await h.seedMember('m@t.test', 'workspace_manager');
    const cookie = (await h.login(m.email)).cookie!;
    const max = PLATFORM_LIMITS.deniedPerMember.max;
    for (let i = 0; i < max; i++) expect((await overview(h, cookie)).status).toBe(403);
    for (let i = 0; i < 5; i++) {
      const res = await (i % 2 ? h.call('GET', '/api/platform/audit', { cookie }) : overview(h, cookie));
      expect(res.status).toBe(429);
      expect(res.text).not.toMatch(/platform_super_admin|approval|events/);
    }
    expect(await deniedRows(h)).toBe(max);
    expect(await limitedRows(h, 'platform_denied')).toBe(1);
    // Authorization is unchanged: the Manager still has no workspace administration, the holder is unaffected.
    expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(403);
    const holder = (await h.login(s.email)).cookie!;
    expect((await overview(h, holder)).status).toBe(200);
  });

  it('limits denials per IP across several non-holder accounts', async () => {
    const h = await createHarness({ now: new Date() });
    const cookies: string[] = [];
    for (const email of ['a1@t.test', 'a2@t.test', 'a3@t.test', 'a4@t.test']) { await h.seedMember(email, 'workspace_admin'); cookies.push((await h.login(email)).cookie!); }
    const statuses: number[] = [];
    for (const cookie of cookies) for (let i = 0; i < PLATFORM_LIMITS.deniedPerMember.max; i++) statuses.push((await overview(h, cookie, '198.51.100.7')).status);
    expect(statuses.filter(s => s === 403)).toHaveLength(PLATFORM_LIMITS.deniedPerIp.max);
    expect(statuses.slice(PLATFORM_LIMITS.deniedPerIp.max).every(s => s === 429)).toBe(true);
    expect(await deniedRows(h)).toBe(PLATFORM_LIMITS.deniedPerIp.max);
    // Another IP is not affected by the exhausted IP bucket (the member buckets were not exhausted).
    await h.seedMember('a5@t.test', 'workspace_admin');
    expect((await overview(h, (await h.login('a5@t.test')).cookie!, '203.0.113.200')).status).toBe(403);
  });

  it('limits the holder’s audit-page reads before the database call; overview and workspace administration continue', async () => {
    const h = await createHarness({ now: new Date() });
    const s = await h.seedPlatformSuperAdmin();
    const cookie = (await h.login(s.email)).cookie!;
    const reads = () => count(h, `SELECT count(*)::int AS n FROM platform_audit_events WHERE event_type = 'platform_audit_read'`);
    const max = PLATFORM_LIMITS.auditReadsPerMember.max;
    for (let i = 0; i < max; i++) expect((await h.call('GET', '/api/platform/audit?limit=1', { cookie })).status).toBe(200);
    expect((await h.call('GET', '/api/platform/audit?limit=1', { cookie })).status).toBe(429);
    expect((await h.call('GET', '/api/platform/audit', { cookie })).status).toBe(429);
    expect(await reads()).toBe(max);
    expect(await limitedRows(h, 'platform_audit_read')).toBe(1);
    expect((await h.call('GET', '/api/platform/audit?limit=0', { cookie })).status).toBe(400); // validation still first, writes nothing
    expect((await overview(h, cookie)).status).toBe(200);
    expect((await h.call('GET', '/api/admin/members', { cookie })).status).toBe(200);
  });

  it('does not rate-limit or audit unauthenticated requests (401), and never turns a 401 into a 429', async () => {
    const h = await createHarness({ now: new Date() });
    for (let i = 0; i < 15; i++) expect((await h.call('GET', '/api/platform/overview')).status).toBe(401);
    expect(await count(h, `SELECT count(*)::int AS n FROM auth_audit_events`)).toBe(0);
    expect(await count(h, `SELECT count(*)::int AS n FROM auth_rate_limits`)).toBe(0);
  });
});
