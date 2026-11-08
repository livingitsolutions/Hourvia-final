// Sprint 3.0.2: M8 security closure (offline, embedded PostgreSQL / PGlite).
//
//   G1  Disabled-member session resurrection. Disabling a member ends every session in the SAME transaction (application
//       path, on M7 and on M8), the M8 trigger also revokes on any transition into 'disabled' (attributed to disabled_by),
//       and leaving 'disabled' or 'suspended' sweeps anything still unrevoked. Reinstatement never restores a session.
//   G2  Session lifetime cap. The 24-hour cap in the M8 session insert guard is anchored to the database clock, so a
//       manipulated (future) created_at can neither be stored nor stretch the lifetime.
//
// The M8 proposal is applied only to these throwaway in-memory databases. The real-PostgreSQL evidence for the same
// behaviour under concurrency is in multi-organization.rehearsal.test.ts and platform-grant.rehearsal.test.ts.
import { describe, expect, it } from 'vitest';
import { sha256Hex } from './crypto';
import { statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { M8_PROPOSAL_SQL, REINSTATE_MEMBER_SQL, applyMigration, createHarness, fillOperatorSql, type Harness } from './testing/harness';
import type { SqlClient } from './types';

const HOUR = 3600_000;
const MINUTE = 60_000;
const rows = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows;
const sessionsOf = (h: Harness, memberId: string) => rows<{ reason: string | null; by: string | null; revoked: boolean }>(h,
  `SELECT revoked_reason AS reason, revoked_by_member_id::text AS by, revoked_at IS NOT NULL AS revoked FROM auth_sessions WHERE member_id = $1 ORDER BY created_at, id`, [memberId]);
const revocationAudit = (h: Harness, memberId: string) => rows<{ reason: string; authority: string; source: string; actor: string | null }>(h,
  `SELECT details->>'reason' AS reason, details->>'authority' AS authority, details->>'source' AS source, actor_member_id::text AS actor
   FROM auth_audit_events WHERE event_type = 'session_revocation' AND subject_member_id = $1 ORDER BY id`, [memberId]);
const unban = (h: Harness, email: string) => { h.provider.users.get(email)!.banned = false; };
const reinstate = (h: Harness, memberId: string) => h.pg.exec(fillOperatorSql(REINSTATE_MEMBER_SQL, { EXPECTED_MEMBER_ID: memberId }));

/** ThriveSource admin + contractor, both signed in twice (two live sessions for the contractor). */
async function signedIn(h: Harness) {
  const admin = await h.seedMember('admin@thrivesource.test', 'workspace_admin');
  const c = await h.seedMember('casey@thrivesource.test', 'contractor');
  const a = await h.login(admin.email);
  const c1 = await h.login(c.email), c2 = await h.login(c.email);
  expect([a.status, c1.status, c2.status]).toEqual([200, 200, 200]);
  return { admin, c, adminCookie: a.cookie!, cookies: [c1.cookie!, c2.cookie!] };
}

// ---------------------------------------------------------------------------------------------------------------------
describe('G1: disabling a member is atomic with session revocation (application path, M7 and M8)', () => {
  for (const variant of ['M7', 'M8'] as const) {
    it(`${variant}: disable ends every session in one transaction, attributed to the Administrator`, async () => {
      const h = await createHarness({ now: new Date(), multiOrganization: variant === 'M8' });
      const { admin, c, adminCookie, cookies } = await signedIn(h);
      const out = await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: adminCookie });
      expect(out.status).toBe(200);
      expect(out.json).toMatchObject({ sessionsRevoked: 2 });
      expect(await sessionsOf(h, c.id)).toEqual([
        { reason: 'member_disabled', by: admin.id, revoked: true }, { reason: 'member_disabled', by: admin.id, revoked: true }]);
      expect((await revocationAudit(h, c.id)).map(r => [r.reason, r.authority, r.source, r.actor])).toEqual([
        ['member_disabled', 'workspace_admin', 'application', admin.id], ['member_disabled', 'workspace_admin', 'application', admin.id]]);
      for (const cookie of cookies) expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
    });

    it(`${variant}: a failure after the status change rolls back the disable AND the revocation together`, async () => {
      const h = await createHarness({ now: new Date(), multiOrganization: variant === 'M8' });
      const { admin, c, cookies } = await signedIn(h);
      // Fail the last statement of the transaction (pending-invitation revocation), after member and sessions changed.
      const failing = (inner: SqlClient): SqlClient => ({
        query: (text, params) => /^UPDATE workspace_invitations SET status = 'revoked'/.test(text.trim()) ? Promise.reject(new Error('injected')) : inner.query(text, params),
        transaction: fn => inner.transaction(tx => fn(failing(tx))),
      });
      const store = new PostgresAuthStore(failing(statementGuardedSqlClient(h.sql)));
      await expect(store.disableMemberAndRevokeSessions(c.id, admin.id, new Date(h.clock.now))).rejects.toThrow(/injected/);
      expect((await rows(h, `SELECT status FROM workspace_members WHERE id = $1`, [c.id]))[0]).toEqual({ status: 'active' });
      expect(await sessionsOf(h, c.id)).toEqual([{ reason: null, by: null, revoked: false }, { reason: null, by: null, revoked: false }]);
      for (const cookie of cookies) expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(200);
    });

    it(`${variant}: disable → reinstate never restores the old sessions; the member must sign in again`, async () => {
      const h = await createHarness({ now: new Date(), multiOrganization: variant === 'M8' });
      const { c, adminCookie, cookies } = await signedIn(h);
      expect((await h.call('POST', `/api/admin/members/${c.id}/disable`, { cookie: adminCookie })).status).toBe(200);
      unban(h, c.email);
      await reinstate(h, c.id);
      expect((await rows(h, `SELECT status FROM workspace_members WHERE id = $1`, [c.id]))[0]).toEqual({ status: 'active' });
      for (const cookie of cookies) expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
      const fresh = await h.login(c.email);
      expect(fresh.status).toBe(200);
      expect((await h.call('GET', '/api/auth/session', { cookie: fresh.cookie })).status).toBe(200);
    });
  }

  it('M7: a stale session left by an operator (non-application) disable is swept by the reinstatement procedure', async () => {
    const h = await createHarness({ now: new Date() });
    const { c, cookies } = await signedIn(h);
    // Pre-3.0.2 failure mode: the status changed but the sessions were never revoked.
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]);
    expect((await sessionsOf(h, c.id)).every(s => !s.revoked)).toBe(true);
    await reinstate(h, c.id);
    expect(await sessionsOf(h, c.id)).toEqual([{ reason: 'member_reinstated', by: null, revoked: true }, { reason: 'member_reinstated', by: null, revoked: true }]);
    expect((await revocationAudit(h, c.id)).map(r => r.authority)).toEqual(['operator', 'operator']);
    const audit = await rows<{ d: { stale_sessions_revoked: number } }>(h, `SELECT details AS d FROM auth_audit_events WHERE event_type = 'member_reinstated' AND subject_member_id = $1`, [c.id]);
    expect(audit.map(a => a.d.stale_sessions_revoked)).toEqual([2]);
    for (const cookie of cookies) expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });

  it('a repeated disable of an already disabled member still sweeps leftover sessions (and reports no status change)', async () => {
    const h = await createHarness({ now: new Date() });
    const { admin, c } = await signedIn(h);
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]); // leaves sessions live
    const store = new PostgresAuthStore(statementGuardedSqlClient(h.sql));
    expect(await store.disableMemberAndRevokeSessions(c.id, admin.id, new Date(h.clock.now))).toEqual({ changed: false, sessionsRevoked: 2 });
    expect((await sessionsOf(h, c.id)).every(s => s.revoked && s.reason === 'member_disabled' && s.by === admin.id)).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('G1: the M8 trigger revokes on every transition into disabled, with correct attribution', () => {
  it('a runtime status UPDATE alone (no application revoke) revokes, attributed to disabled_by and re-authorized', async () => {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    const { admin, c } = await signedIn(h);
    await h.sql.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now(), disabled_by = $2 WHERE id = $1`, [c.id, admin.id]);
    expect(await sessionsOf(h, c.id)).toEqual([{ reason: 'member_disabled', by: admin.id, revoked: true }, { reason: 'member_disabled', by: admin.id, revoked: true }]);
    expect((await revocationAudit(h, c.id)).map(r => [r.authority, r.source])).toEqual([['workspace_admin', 'application'], ['workspace_admin', 'application']]);
  });

  it('an operator disable with no disabled_by revokes with operator attribution', async () => {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    const { c } = await signedIn(h);
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]);
    expect(await sessionsOf(h, c.id)).toEqual([{ reason: 'member_disabled', by: null, revoked: true }, { reason: 'member_disabled', by: null, revoked: true }]);
    expect((await revocationAudit(h, c.id)).map(r => [r.authority, r.source])).toEqual([['operator', 'operator_sql'], ['operator', 'operator_sql']]);
  });

  it('suspension keeps its attribution (operator) and suspended → disabled is attributed to the disabler', async () => {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    const { admin, c } = await signedIn(h);
    await h.pg.query(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [c.id]);
    expect((await sessionsOf(h, c.id)).map(s => [s.reason, s.by])).toEqual([['member_suspended', null], ['member_suspended', null]]);
    const store = new PostgresAuthStore(statementGuardedSqlClient(h.sql));
    expect(await store.disableMemberAndRevokeSessions(c.id, admin.id, new Date(h.clock.now))).toEqual({ changed: true, sessionsRevoked: 0 });
    expect((await sessionsOf(h, c.id)).map(s => [s.reason, s.by])).toEqual([['member_suspended', null], ['member_suspended', null]]); // final
  });

  it('a disable the runtime is not authorized to perform cannot revoke either: the whole transaction is refused', async () => {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    const { c } = await signedIn(h);
    const peer = await h.seedMember('peer@thrivesource.test', 'contractor');
    await expect(h.sql.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now(), disabled_by = $2 WHERE id = $1`, [c.id, peer.id]))
      .rejects.toThrow(/disable is not authorized/);
    expect((await sessionsOf(h, c.id)).every(s => !s.revoked)).toBe(true);
  });

  it('M8 trigger: a pre-M8 stale session is swept on reinstatement, even without the operator procedure', async () => {
    // Build the leftover on M7 (where no trigger exists), then apply M8 on top: M8 preserves it byte-for-byte.
    const h = await createHarness({ now: new Date() });
    const { c, cookies } = await signedIn(h);
    await h.pg.query(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [c.id]);
    await applyMigration(h.pg, M8_PROPOSAL_SQL);
    expect((await sessionsOf(h, c.id)).every(s => !s.revoked)).toBe(true);
    await h.pg.transaction(async tx => {
      await tx.query(`SELECT set_config('hourvia.member_reinstatement', 'approved', true)`);
      await tx.query(`UPDATE workspace_members SET status = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = $1`, [c.id]);
    });
    expect(await sessionsOf(h, c.id)).toEqual([{ reason: 'member_reinstated', by: null, revoked: true }, { reason: 'member_reinstated', by: null, revoked: true }]);
    unban(h, c.email);
    for (const cookie of cookies) expect((await h.call('GET', '/api/auth/session', { cookie })).status).toBe(401);
  });

  it('the trigger definition covers disable and reinstatement, and the self-check pins it', () => {
    expect(M8_PROPOSAL_SQL).toMatch(/CREATE TRIGGER workspace_members_status_session_revocation AFTER UPDATE OF status ON workspace_members\s+FOR EACH ROW WHEN \(OLD\.status IS DISTINCT FROM NEW\.status\s+AND \(NEW\.status IN \('suspended', 'disabled'\) OR OLD\.status IN \('suspended', 'disabled'\)\)\)/);
    expect(M8_PROPOSAL_SQL).not.toMatch(/workspace_members_suspension_revocation/);
    expect(M8_PROPOSAL_SQL).toMatch(/self-check failed: member session revocation does not cover suspension and disable/);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('G2: the absolute session lifetime is capped against the database clock', () => {
  async function m8() {
    const h = await createHarness({ now: new Date(), multiOrganization: true });
    const m = await h.seedMember('dana@thrivesource.test', 'contractor');
    const insert = (createdOffsetMs: number, lifetimeMs: number, tag: string) => h.pg.query(
      `INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
       VALUES ($1, $2, now() + $3 * interval '1 millisecond', now() + $3 * interval '1 millisecond', now() + $3 * interval '1 millisecond' + interval '1 minute',
               now() + ($3 + $4) * interval '1 millisecond')`, [sha256Hex(tag), m.id, createdOffsetMs, lifetimeMs]);
    return { h, m, insert };
  }

  it('refuses a future created_at that would push a "24-hour" session days past the real cap', async () => {
    const { insert } = await m8();
    await expect(insert(7 * 24 * HOUR, 24 * HOUR, 'week')).rejects.toThrow(/created_at is in the future/);
    await expect(insert(365 * 24 * HOUR, HOUR, 'year')).rejects.toThrow(/created_at is in the future/);
    await expect(insert(3 * MINUTE, HOUR, 'three-minutes')).rejects.toThrow(/created_at is in the future/);
  });

  it('accepts ordinary clock skew (up to two minutes) and past timestamps, but never more than 24 hours of database time', async () => {
    const { h, insert } = await m8();
    await insert(0, 24 * HOUR, 'exact');
    await insert(MINUTE, 24 * HOUR, 'skew'); // application clock one minute ahead
    await insert(-HOUR, 24 * HOUR, 'past'); // only shortens the session
    await expect(insert(-HOUR, 24 * HOUR + 1000, 'past-long')).rejects.toThrow(/absolute lifetime exceeds 24 hours/);
    await expect(insert(0, 25 * HOUR, 'long')).rejects.toThrow(/absolute lifetime exceeds 24 hours/);
    const { rows: r } = await h.pg.query<{ ok: boolean }>(`SELECT bool_and(absolute_expires_at <= now() + interval '24 hours 2 minutes') AS ok FROM auth_sessions`);
    expect(r[0]!.ok).toBe(true);
  });

  it('the application path is refused too: a store whose clock runs days ahead cannot create a session', async () => {
    const { h, m } = await m8();
    const store = new PostgresAuthStore(statementGuardedSqlClient(h.sql));
    const ahead = new Date(Date.now() + 3 * 24 * HOUR);
    await expect(store.createSession({ tokenHash: sha256Hex('ahead'), memberId: m.id, now: ahead, idleExpiresAt: new Date(ahead.getTime() + 1800_000), absoluteExpiresAt: new Date(ahead.getTime() + 12 * HOUR) }))
      .rejects.toThrow(/created_at is in the future/);
    const now = new Date();
    await store.createSession({ tokenHash: sha256Hex('now'), memberId: m.id, now, idleExpiresAt: new Date(now.getTime() + 1800_000), absoluteExpiresAt: new Date(now.getTime() + 12 * HOUR) });
  });

  it('created_at and absolute_expires_at stay immutable after insert, and touch can never extend past the absolute expiry', async () => {
    const { h, m, insert } = await m8();
    await insert(0, HOUR, 'fixed');
    await expect(h.pg.query(`UPDATE auth_sessions SET created_at = created_at + interval '1 day' WHERE member_id = $1`, [m.id])).rejects.toThrow(/immutable/);
    await expect(h.pg.query(`UPDATE auth_sessions SET absolute_expires_at = absolute_expires_at + interval '1 day' WHERE member_id = $1`, [m.id])).rejects.toThrow(/immutable/);
    const store = new PostgresAuthStore(statementGuardedSqlClient(h.sql));
    const id = (await rows<{ id: string }>(h, `SELECT id FROM auth_sessions WHERE member_id = $1`, [m.id]))[0]!.id;
    await store.touchSession(id, new Date(), new Date(Date.now() + 30 * 24 * HOUR));
    const { rows: r } = await h.pg.query<{ ok: boolean }>(`SELECT idle_expires_at <= absolute_expires_at AND absolute_expires_at <= now() + interval '1 hour 1 minute' AS ok FROM auth_sessions WHERE id = $1`, [id]);
    expect(r[0]!.ok).toBe(true);
  });

  it('the guard uses clock_timestamp() (real time), not the transaction start, and the self-check pins it', () => {
    expect(M8_PROPOSAL_SQL).toMatch(/IF NEW\.created_at > clock_timestamp\(\) \+ interval '2 minutes' THEN\s+RAISE EXCEPTION 'session created_at is in the future'/);
    expect(M8_PROPOSAL_SQL).toMatch(/IF NEW\.absolute_expires_at > clock_timestamp\(\) \+ interval '24 hours 2 minutes' THEN/);
    expect(M8_PROPOSAL_SQL).toMatch(/self-check failed: hourvia_guard_session_insert does not bound created_at by the database clock/);
  });
});
