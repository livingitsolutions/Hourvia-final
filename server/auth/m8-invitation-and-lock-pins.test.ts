// Sprint 3.0.5: M8 hardening (offline, embedded PostgreSQL / PGlite, synthetic data only).
//
//   M-2  Invitation state machine (hourvia_guard_invitation_update). pending -> accepted once, unexpired by the
//        database clock and at the claimed time, for the invited member of an active organization; pending -> revoked;
//        accepted and revoked are final; every other column is immutable, for the runtime AND for operator SQL.
//   M-1  The self-check pins the exclusive session lock and trigger of hourvia_revoke_organization_sessions, and the
//        shared session lock plus the fresh member/organization status re-check in hourvia_guard_session_insert.
//   L-4  The self-check pins both new M8 indexes.
//
// The M8 proposal is applied only to throwaway in-memory databases. Concurrent acceptance on separate PostgreSQL
// backends is rehearsed in multi-organization.rehearsal.test.ts (S12).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  THRIVESOURCE_ORGANIZATION_ID, mintMultiOrganizationCapabilityForOfflineTests, organizationContextForVerifiedMembership,
  type OrganizationContext, type OrganizationId,
} from '../../src/domain/organization';
import { statementGuardedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import { M8_PROPOSAL_SQL, applyMigration, createHarness, type Harness } from './testing/harness';

const ACME = '0b9f3c2e-7d41-4c55-9a1e-3f2d6c8b4a10' as OrganizationId;
const DAY = 86400_000;
const cap = mintMultiOrganizationCapabilityForOfflineTests();
const ctx = (org: OrganizationId, slug: string): OrganizationContext =>
  organizationContextForVerifiedMembership({ organizationId: org, workspaceId: slug }, { id: org, slug, status: 'active' }, cap);
const one = async <T = Record<string, unknown>>(h: Harness, text: string, params?: unknown[]) => (await h.pg.query<T>(text, params)).rows[0]!;
const SELF_CHECK_START = M8_PROPOSAL_SQL.indexOf('-- 9. Self-check');
/** Final Sprint 3.0.5 proposal digest. The Netlify preview rehearsal must run exactly this file. */
const M8_PROPOSAL_DIGEST = 'f401b7a3af458749a6078037d67cd284aac1672f0653c4b0540031f9a4e0b532';

/** An M8 database with ACME (seats), an active ACME Administrator, and an invited, linked contractor with a pending invitation. */
async function acme(seats = 5, invitation: { createdAgoMs?: number; expiresInMs?: number } = {}) {
  const h = await createHarness({ now: new Date(), multiOrganization: true });
  await h.pg.query(`INSERT INTO organizations (id, slug, name, kind, status) VALUES ($1, 'acme', 'ACME', 'customer', 'active')`, [ACME]);
  await h.pg.query(`INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, approval_ref)
    VALUES ($1, 'customer', 'standard', $2, 'CHG-TEST-305')`, [ACME, seats]);
  const addMember = async (email: string, role: string, status: string) => (await one<{ id: string }>(h,
    `INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
     VALUES ($1, 'acme', $2, $3, 'r', $4, $5, CASE WHEN $5 <> 'invited' THEN now() END) RETURNING id`,
    [ACME, h.provider.addUser(email, 'correct horse battery'), email, role, status])).id;
  const admin = await addMember('owner@acme.test', 'workspace_admin', 'active');
  const invite = async (memberId: string, email: string, createdAgoMs = 0, expiresInMs = DAY) => (await one<{ id: string }>(h,
    `INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
     VALUES ($1, 'acme', $2, $3, 'contractor', 'pending', $4, now() - $5 * interval '1 millisecond', now() + $6 * interval '1 millisecond') RETURNING id`,
    [ACME, memberId, email, admin, createdAgoMs, expiresInMs])).id;
  const casey = await addMember('casey@acme.test', 'contractor', 'invited');
  const inv = await invite(casey, 'casey@acme.test', invitation.createdAgoMs ?? 0, invitation.expiresInMs ?? DAY);
  const store = new PostgresAuthStore(statementGuardedSqlClient(h.sql), ctx(ACME, 'acme'));
  /** Raw statement as hourvia_auth_runtime (SET LOCAL ROLE), bypassing the application statement policy on purpose. */
  const runtime = (text: string, params?: unknown[]) => h.sql.query(text, params);
  const owner = (text: string, params?: unknown[]) => h.pg.query(text, params);
  const status = async (id = inv) => (await one<{ status: string }>(h, `SELECT status FROM workspace_invitations WHERE id = $1`, [id])).status;
  const consumed = async () => (await one<{ n: number }>(h, `SELECT ((SELECT count(*) FROM workspace_members WHERE organization_id = $1 AND status = 'active')
      + (SELECT count(*) FROM workspace_invitations i JOIN workspace_members m ON m.id = i.member_id
         WHERE i.organization_id = $1 AND i.status = 'pending' AND i.expires_at > now() AND m.status = 'invited'))::int AS n`, [ACME])).n;
  return { h, admin, casey, inv, store, runtime, owner, status, consumed, addMember, invite };
}

// ---------------------------------------------------------------------------------------------------------------------
// PR #23 billing correction: the three seat guards judge billing_expires_at by clock_timestamp(), not the
// transaction-start now(). Real-PostgreSQL evidence with separate backends is S14 in multi-organization.rehearsal.test.ts.
describe('PR #23: billing expiry is judged by the real clock on every seat path', () => {
  const billing = (t: Awaited<ReturnType<typeof acme>>, at: string) =>
    t.owner(`UPDATE organization_seat_entitlements SET billing_expires_at = ${at} WHERE organization_id = $1`, [ACME]);
  /** Runs `late` in a transaction opened while billing is valid, after sleeping past its real expiry. */
  const straddle = (t: Awaited<ReturnType<typeof acme>>, role: 'runtime' | 'operator', late: [string, unknown[]][]) =>
    t.h.pg.transaction(async tx => {
      if (role === 'runtime') await tx.query('SET LOCAL ROLE hourvia_auth_runtime');
      const before = (await tx.query<{ ok: boolean }>(`SELECT now() < billing_expires_at AS ok FROM organization_seat_entitlements WHERE organization_id = $1`, [ACME])).rows[0]!;
      expect(before.ok).toBe(true); // opened while billing was valid
      await tx.query(`SELECT pg_sleep(2)`);
      const after = (await tx.query<{ expired: boolean; stale: boolean }>(`SELECT clock_timestamp() >= billing_expires_at AS expired, now() < billing_expires_at AS stale
        FROM organization_seat_entitlements WHERE organization_id = $1`, [ACME])).rows[0]!;
      expect(after).toEqual({ expired: true, stale: true }); // really expired, while now() still says valid
      for (const [sql, params] of late) await tx.query(sql, params);
    });
  const EXPIRED = /organization seat entitlement has expired/;

  it('an already expired entitlement refuses every seat consumer; a valid one allows them', async () => {
    const t = await acme();
    const dana = await t.addMember('dana@acme.test', 'contractor', 'invited');
    await billing(t, `now() - interval '1 minute'`);
    await expect(t.runtime(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
      VALUES ($1, 'acme', $2, 'dana@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, dana, t.admin])).rejects.toThrow(EXPIRED);
    await expect(t.store.acceptInvitation(t.casey, new Date())).rejects.toThrow(EXPIRED);
    expect(await t.status()).toBe('pending'); // the acceptance rolled back with the refused activation
    await billing(t, `now() + interval '30 days'`);
    await t.runtime(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
      VALUES ($1, 'acme', $2, 'dana@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, dana, t.admin]);
    expect(await t.store.acceptInvitation(t.casey, new Date())).toBe(true);
  });

  it('a transaction opened before billing expiry cannot reserve or consume a seat after it', async () => {
    const t = await acme();
    const dana = await t.addMember('dana@acme.test', 'contractor', 'invited');
    const sus = await t.addMember('sus@acme.test', 'contractor', 'active');
    await t.owner(`UPDATE workspace_members SET status = 'suspended' WHERE id = $1`, [sus]);
    const cases: [string, 'runtime' | 'operator', [string, unknown[]][]][] = [
      ['runtime pending invitation', 'runtime', [[`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
        VALUES ($1, 'acme', $2, 'dana@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, dana, t.admin]]]],
      ['runtime activation after acceptance', 'runtime', [
        [`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1 AND status = 'pending'`, [t.inv]],
        [`UPDATE workspace_members SET status = 'active', activated_at = now() WHERE id = $1 AND organization_id = $2 AND status = 'invited'`, [t.casey, ACME]]]],
      ['operator reactivation', 'operator', [[`UPDATE workspace_members SET status = 'active' WHERE id = $2 AND organization_id = $1`, [ACME, sus]]]],
      ['operator active insert', 'operator', [[`INSERT INTO workspace_members (organization_id, workspace_id, auth_user_id, email, display_name, role, status, activated_at)
        VALUES ($1, 'acme', gen_random_uuid(), 'late@acme.test', 'r', 'contractor', 'active', now())`, [ACME]]]],
    ];
    for (const [name, role, late] of cases) {
      await billing(t, `clock_timestamp() + interval '1500 milliseconds'`);
      await expect(straddle(t, role, late), name).rejects.toThrow(EXPIRED);
    }
    expect(await t.status()).toBe('pending');
    expect((await one<{ s: string }>(t.h, `SELECT status s FROM workspace_members WHERE id = $1`, [sus])).s).toBe('suspended');
    expect(await t.consumed()).toBe(2); // admin + casey's reservation: nothing was consumed after expiry
  });

  it('control: the same long transaction still consumes a seat while billing is valid by the real clock', async () => {
    const t = await acme();
    const dana = await t.addMember('dana@acme.test', 'contractor', 'invited');
    await billing(t, `clock_timestamp() + interval '1 hour'`);
    await t.h.pg.transaction(async tx => {
      await tx.query('SET LOCAL ROLE hourvia_auth_runtime');
      await tx.query(`SELECT pg_sleep(1)`);
      await tx.query(`INSERT INTO workspace_invitations (organization_id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
        VALUES ($1, 'acme', $2, 'dana@acme.test', 'contractor', 'pending', $3, now(), now() + interval '1 day')`, [ACME, dana, t.admin]);
    });
    expect(await t.consumed()).toBe(3);
  });

  // Self-check: reverting any one of the three billing comparisons (or adding a now()-based one) aborts M8.
  const BILLING_FN = /self-check failed: hourvia_guard_(member_update|member_insert|invitation_insert)\(\) does not judge billing expiry by the real clock/;
  const BILLING = 'ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= clock_timestamp() THEN';
  const nth = (text: string, needle: string, n: number) => { let at = -1; for (let i = 0; i <= n; i++) at = text.indexOf(needle, at + 1); return at; };
  for (const [n, fn] of ['hourvia_guard_member_update', 'hourvia_guard_member_insert', 'hourvia_guard_invitation_insert'].entries()) {
    for (const [label, to] of [
      ['reverts to now()', 'ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= now() THEN'],
      ['adds a now()-based billing escape', 'ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= clock_timestamp() AND ent.billing_expires_at <= now() THEN'],
      ['drops the billing check', 'false THEN'],
    ] as const) {
      it(`self-check: ${fn} ${label}`, async () => {
        const at = nth(M8_PROPOSAL_SQL, BILLING, n);
        expect(at).toBeGreaterThan(M8_PROPOSAL_SQL.indexOf(`FUNCTION ${fn}()`));
        expect(at).toBeLessThan(SELF_CHECK_START);
        const mutated = M8_PROPOSAL_SQL.slice(0, at) + to + M8_PROPOSAL_SQL.slice(at + BILLING.length);
        const h = await createHarness({ now: new Date() }); // M1-M7
        await expect(applyMigration(h.pg, mutated)).rejects.toThrow(label === 'drops the billing check' ? /self-check failed: hourvia_guard_\w+\(\) does not judge billing expiry by the real clock/ : BILLING_FN);
        expect((await one<{ n: number }>(h, `SELECT count(*)::int n FROM pg_proc WHERE proname LIKE 'hourvia\\_%'`)).n).toBe(16); // rolled back
      });
    }
  }
});

// ---------------------------------------------------------------------------------------------------------------------
describe('M-2: the invitation state machine holds for the runtime and for operator SQL', () => {
  it('the application acceptance path still works and is single-use', async () => {
    const t = await acme();
    expect(await t.store.acceptInvitation(t.casey, new Date())).toBe(true);
    expect(await t.status()).toBe('accepted');
    expect((await one<{ status: string }>(t.h, `SELECT status FROM workspace_members WHERE id = $1`, [t.casey])).status).toBe('active');
    expect(await t.store.acceptInvitation(t.casey, new Date())).toBe(false); // the second acceptance finds nothing pending
  });

  it('pending -> revoked is allowed (re-invite and disable paths), and a revoked invitation can never become pending again', async () => {
    const t = await acme();
    await t.runtime(`UPDATE workspace_invitations SET status = 'revoked' WHERE id = $1 AND status = 'pending'`, [t.inv]);
    expect(await t.status()).toBe('revoked');
    for (const exec of [t.runtime, t.owner]) {
      await expect(exec(`UPDATE workspace_invitations SET status = 'pending' WHERE id = $1`, [t.inv])).rejects.toThrow(/accepted and revoked invitations are final/);
      await expect(exec(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [t.inv])).rejects.toThrow(/final/);
    }
    expect(await t.status()).toBe('revoked');
  });

  it('reviving a revoked invitation cannot re-reserve a seat in a full organization (the pre-3.0.5 bypass)', async () => {
    const t = await acme(2); // admin + casey's pending reservation = 2 of 2
    await t.runtime(`UPDATE workspace_invitations SET status = 'revoked' WHERE id = $1`, [t.inv]);
    const dana = await t.addMember('dana@acme.test', 'contractor', 'invited');
    await t.invite(dana, 'dana@acme.test'); // takes the freed seat
    expect(await t.consumed()).toBe(2);
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'pending' WHERE id = $1`, [t.inv])).rejects.toThrow(/final/);
    await expect(t.owner(`UPDATE workspace_invitations SET status = 'pending' WHERE id = $1`, [t.inv])).rejects.toThrow(/final/);
    expect(await t.consumed()).toBe(2);
  });

  it('accepted is final: no return to pending, no later revocation, no rewritten acceptance time', async () => {
    const t = await acme();
    expect(await t.store.acceptInvitation(t.casey, new Date())).toBe(true);
    for (const exec of [t.runtime, t.owner]) {
      await expect(exec(`UPDATE workspace_invitations SET status = 'pending', accepted_at = NULL WHERE id = $1`, [t.inv])).rejects.toThrow(/final/);
      await expect(exec(`UPDATE workspace_invitations SET status = 'revoked', accepted_at = NULL WHERE id = $1`, [t.inv])).rejects.toThrow(/final/);
      await expect(exec(`UPDATE workspace_invitations SET accepted_at = accepted_at - interval '1 hour' WHERE id = $1`, [t.inv])).rejects.toThrow(/acceptance is final/);
    }
    // A true no-op is allowed.
    expect((await t.runtime(`UPDATE workspace_invitations SET status = status WHERE id = $1 RETURNING id`, [t.inv])).rows).toHaveLength(1);
  });

  it('PR #23: a transaction opened BEFORE expiry cannot accept AFTER expiry (now() is the transaction start)', async () => {
    const t = await acme(5, { expiresInMs: 1500 }); // expires 1.5 s after creation
    const attempt = (claimed: string) => t.h.pg.transaction(async tx => {
      await tx.query('SET LOCAL ROLE hourvia_auth_runtime');
      const before = (await tx.query<{ ok: boolean }>(`SELECT now() < expires_at AS ok FROM workspace_invitations WHERE id = $1`, [t.inv])).rows[0]!;
      expect(before.ok).toBe(true); // the transaction started while the invitation was valid
      await tx.query(`SELECT pg_sleep(2)`);
      const after = (await tx.query<{ ok: boolean; stale: boolean }>(`SELECT clock_timestamp() > expires_at AS ok, now() < expires_at AS stale FROM workspace_invitations WHERE id = $1`, [t.inv])).rows[0]!;
      expect(after).toEqual({ ok: true, stale: true }); // really expired, but now() still says valid
      await tx.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = ${claimed} WHERE id = $1 AND status = 'pending'`, [t.inv]);
    });
    await expect(attempt('now()')).rejects.toThrow(/expired invitations cannot be accepted/);
    expect(await t.status()).toBe('pending');
    // Control: the same long-transaction shape still accepts a valid invitation.
    const ok = await acme(5, { expiresInMs: 60_000 });
    await ok.h.pg.transaction(async tx => {
      await tx.query('SET LOCAL ROLE hourvia_auth_runtime');
      await tx.query(`SELECT pg_sleep(1)`);
      await tx.query(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1 AND status = 'pending'`, [ok.inv]);
    });
    expect(await ok.status()).toBe('accepted');
  });

  it('an expired invitation cannot be accepted, even with a back-dated accepted_at or a stale application clock', async () => {
    const t = await acme(5, { createdAgoMs: 8 * DAY, expiresInMs: -DAY }); // created 8 days ago, expired yesterday
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [t.inv])).rejects.toThrow(/expired invitations cannot be accepted/);
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() - interval '2 days' WHERE id = $1`, [t.inv])).rejects.toThrow(/expired invitations cannot be accepted/);
    await expect(t.owner(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() - interval '2 days' WHERE id = $1`, [t.inv])).rejects.toThrow(/expired invitations cannot be accepted/);
    // The application's own predicate passes with a clock two days behind; the database still refuses, atomically.
    await expect(t.store.acceptInvitation(t.casey, new Date(Date.now() - 2 * DAY))).rejects.toThrow(/expired invitations cannot be accepted/);
    expect(await t.status()).toBe('pending');
    expect((await one<{ status: string }>(t.h, `SELECT status FROM workspace_members WHERE id = $1`, [t.casey])).status).toBe('invited');
  });

  it('accepted_at must lie between creation and database time, with 2 minutes of clock-skew tolerance each side', async () => {
    const t = await acme(5, { createdAgoMs: DAY });
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() + interval '1 hour' WHERE id = $1`, [t.inv])).rejects.toThrow(/accepted_at must lie between/);
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = created_at - interval '1 hour' WHERE id = $1`, [t.inv])).rejects.toThrow(/accepted_at must lie between/);
    await expect(t.owner(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = NULL WHERE id = $1`, [t.inv])).rejects.toThrow();
    expect(await t.status()).toBe('pending');
    // Skew tolerance: an acceptance stamped by an application clock slightly behind the database is valid
    // (the Sprint 3.0.5 grant rehearsal 6c found this with millisecond-truncated timestamps).
    await t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = created_at - interval '1 second' WHERE id = $1`, [t.inv]);
    expect(await t.status()).toBe('accepted');
  });

  it('only the invited, linked member of an active organization can accept', async () => {
    const disabled = await acme();
    await disabled.owner(`UPDATE workspace_members SET status = 'disabled', disabled_at = now() WHERE id = $1`, [disabled.casey]);
    await expect(disabled.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [disabled.inv])).rejects.toThrow(/only by the invited member of an active organization/);

    const suspendedOrg = await acme();
    await suspendedOrg.owner(`UPDATE organizations SET status = 'suspended', suspended_at = now(), suspended_reason = 'billing' WHERE id = $1`, [ACME]);
    await expect(suspendedOrg.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [suspendedOrg.inv])).rejects.toThrow(/only by the invited member of an active organization/);
    await expect(suspendedOrg.store.acceptInvitation(suspendedOrg.casey, new Date())).rejects.toThrow(/only by the invited member/);
    expect(await suspendedOrg.status()).toBe('pending');
  });

  it('a second acceptance that skips the status filter is refused (what a racing loser sees under READ COMMITTED)', async () => {
    const t = await acme();
    await t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [t.inv]);
    await expect(t.runtime(`UPDATE workspace_invitations SET status = 'accepted', accepted_at = now() WHERE id = $1`, [t.inv])).rejects.toThrow(/acceptance is final/);
  });

  it('identity, tenant and expiry columns are immutable for operators and not updatable by the runtime', async () => {
    const t = await acme();
    const other = await t.addMember('other@acme.test', 'contractor', 'invited');
    for (const [set, params] of [
      [`expires_at = expires_at + interval '30 days'`, []], [`created_at = created_at - interval '1 day'`, []],
      [`member_id = $2`, [other]], [`organization_id = '${THRIVESOURCE_ORGANIZATION_ID}'::uuid`, []],
      [`workspace_id = 'thrivesource'`, []], [`role = 'workspace_admin'`, []], [`email = 'x@acme.test'`, []], [`invited_by_member_id = NULL`, []],
    ] as [string, unknown[]][]) {
      await expect(t.owner(`UPDATE workspace_invitations SET ${set} WHERE id = $1`, [t.inv, ...params])).rejects.toThrow(/immutable|violates/);
      await expect(t.runtime(`UPDATE workspace_invitations SET ${set} WHERE id = $1`, [t.inv, ...params])).rejects.toThrow(/permission denied/);
    }
    await expect(t.owner(`UPDATE workspace_invitations SET status = 'expired' WHERE id = $1`, [t.inv])).rejects.toThrow();
    expect(await t.status()).toBe('pending');
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// Each mutation weakens one property of the M8 definition text (first occurrence, always before the self-check).
// Applied to an M7 database it must abort, and the whole migration rolls back.
describe('Sprint 3.0.5: M8 self-checks reject any weakened lock, status, invitation or index definition', () => {
  const ORG = /self-check failed: (organization suspension revocation trigger is not in its reviewed form|hourvia_revoke_organization_sessions does not revoke under the exclusive session lock)/;
  const INS = /self-check failed: hourvia_guard_session_insert does not re-check status under the shared session lock/;
  const INV = /self-check failed: (the invitation update guard trigger is not in its reviewed form|hourvia_guard_invitation_update does not enforce the invitation state machine|hourvia_auth_runtime can update unexpected workspace_invitations columns|guard or audit triggers are missing or disabled)/;
  const IDX = /self-check failed: an M8 index is missing or not in its reviewed form/;
  const ORG_LOCK = `PERFORM pg_advisory_xact_lock(hashtextextended('hourvia_sessions:' || NEW.id::text, 0));\n`;
  const ORG_UPDATE = `  UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'organization_' || NEW.status\n   WHERE organization_id = NEW.id AND revoked_at IS NULL;\n`;
  const INS_LOCK = `PERFORM pg_advisory_xact_lock_shared(hashtextextended('hourvia_sessions:' || NEW.organization_id::text, 0));\n`;
  const mutations: [string, string, string, RegExp][] = [
    ['A: organization revocation takes the SHARED session lock', ORG_LOCK, ORG_LOCK.replace('pg_advisory_xact_lock(', 'pg_advisory_xact_lock_shared('), ORG],
    ['A: organization revocation takes a try-lock', ORG_LOCK, ORG_LOCK.replace('PERFORM pg_advisory_xact_lock(', 'PERFORM pg_try_advisory_xact_lock('), ORG],
    ['A: organization revocation takes no session lock', `  ${ORG_LOCK}`, '', ORG],
    ['A: organization revocation revokes before locking', `  ${ORG_LOCK}${ORG_UPDATE}`, `${ORG_UPDATE}  ${ORG_LOCK}`, ORG],
    ['A: organization revocation skips some sessions', `WHERE organization_id = NEW.id AND revoked_at IS NULL;`, `WHERE organization_id = NEW.id AND revoked_at IS NULL AND false;`, ORG],
    ['A: organization revocation drops the READ COMMITTED requirement',
      `IF current_setting('transaction_isolation') <> 'read committed' THEN\n    RAISE EXCEPTION 'organization suspension requires READ COMMITTED isolation';\n  END IF;\n`, '', ORG],
    ['A: organization trigger fires on any column', `AFTER UPDATE OF status ON organizations`, `AFTER UPDATE ON organizations`, ORG],
    ['A: organization trigger WHEN clause loosened', `FOR EACH ROW WHEN (OLD.status = 'active' AND NEW.status <> 'active')`, `FOR EACH ROW WHEN (NEW.status = 'closed')`, ORG],
    ['A: organization trigger fires per statement', `CREATE TRIGGER organizations_suspension_revocation AFTER UPDATE OF status ON organizations\n  FOR EACH ROW WHEN (OLD.status = 'active' AND NEW.status <> 'active')`,
      `CREATE TRIGGER organizations_suspension_revocation AFTER UPDATE OF status ON organizations\n  FOR EACH STATEMENT`, ORG],
    ['B: session insert takes the EXCLUSIVE session lock', INS_LOCK, INS_LOCK.replace('_shared(', '('), INS],
    ['B: session insert takes no session lock', `  ${INS_LOCK}`, '', INS],
    ['B: session insert takes a try-lock', INS_LOCK, INS_LOCK.replace('pg_advisory_xact_lock_shared(', 'pg_try_advisory_xact_lock_shared('), INS],
    ['B: session insert reads status before the lock', `  ${INS_LOCK}`, `  IF NOT EXISTS (SELECT 1 FROM workspace_members WHERE id = NEW.member_id AND status = 'active') THEN RAISE EXCEPTION 'x'; END IF;\n  ${INS_LOCK}`, INS],
    ['B: session insert returns early before the status re-check', `  ${INS_LOCK}`, `  IF NEW.member_id IS NOT NULL THEN RETURN NEW; END IF;\n  ${INS_LOCK}`, INS],
    ['B: session insert accepts suspended members', `WHERE m.id = NEW.member_id AND m.organization_id = NEW.organization_id AND m.status = 'active'`,
      `WHERE m.id = NEW.member_id AND m.organization_id = NEW.organization_id AND m.status IN ('active', 'suspended')`, INS],
    ['B: session insert ignores the organization status', `AND m.auth_user_id IS NOT NULL AND o.status = 'active') THEN\n    RAISE EXCEPTION 'sessions can be created`,
      `AND m.auth_user_id IS NOT NULL) THEN\n    RAISE EXCEPTION 'sessions can be created`, INS],
    ['B: session insert drops the READ COMMITTED requirement', `IF current_setting('transaction_isolation') <> 'read committed' THEN\n    RAISE EXCEPTION 'session creation requires READ COMMITTED isolation';\n  END IF;\n`, '', INS],
    ['C: invitation guard trigger removed', `CREATE TRIGGER workspace_invitations_guard_update BEFORE UPDATE ON workspace_invitations\n  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_invitation_update();\n`, '', INV],
    ['C: invitation guard runs AFTER the update', `CREATE TRIGGER workspace_invitations_guard_update BEFORE UPDATE`, `CREATE TRIGGER workspace_invitations_guard_update AFTER UPDATE`, INV],
    ['C: invitation guard fires only on status updates', `BEFORE UPDATE ON workspace_invitations\n  FOR EACH ROW EXECUTE`, `BEFORE UPDATE OF status ON workspace_invitations\n  FOR EACH ROW EXECUTE`, INV],
    ['C: invitation guard has a WHEN escape', `BEFORE UPDATE ON workspace_invitations\n  FOR EACH ROW EXECUTE`, `BEFORE UPDATE ON workspace_invitations\n  FOR EACH ROW WHEN (current_user <> 'hourvia_auth_runtime') EXECUTE`, INV],
    ['C: revoked -> pending allowed', `IF OLD.status <> 'pending' THEN\n    RAISE EXCEPTION 'accepted and revoked`, `IF OLD.status = 'accepted' THEN\n    RAISE EXCEPTION 'accepted and revoked`, INV],
    ['C: expiry judged only at the claimed time', `IF OLD.expires_at <= greatest(clock_timestamp(), NEW.accepted_at) THEN`, `IF OLD.expires_at <= NEW.accepted_at THEN`, INV],
    ['C: expiry judged at transaction start (now()) instead of the real clock', `IF OLD.expires_at <= greatest(clock_timestamp(), NEW.accepted_at) THEN`, `IF OLD.expires_at <= greatest(now(), NEW.accepted_at) THEN`, INV],
    ['C: an extra now()-based expiry escape', `  IF NEW.status IS DISTINCT FROM 'accepted' THEN`, `  IF NEW.status = 'accepted' AND OLD.expires_at > now() AND false THEN\n    RAISE EXCEPTION 'x';\n  END IF;\n  IF NEW.status IS DISTINCT FROM 'accepted' THEN`, INV],
    ['C: accepted_at may predate creation by any amount', `OR NEW.accepted_at < OLD.created_at - interval '2 minutes'\n`, `OR NEW.accepted_at < OLD.created_at - interval '2 years'\n`, INV],
    ['C: accepted_at may lie in the future', `NEW.accepted_at > clock_timestamp() + interval '2 minutes' THEN`, `NEW.accepted_at > clock_timestamp() + interval '2 days' THEN`, INV],
    ['C: expires_at becomes mutable', `OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN\n    RAISE EXCEPTION 'workspace_invitations identity`,
      `OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN\n    RAISE EXCEPTION 'workspace_invitations identity`, INV],
    ['C: organization_id becomes mutable', `IF NEW.id IS DISTINCT FROM OLD.id OR NEW.organization_id IS DISTINCT FROM OLD.organization_id\n     OR NEW.workspace_id`, `IF NEW.id IS DISTINCT FROM OLD.id\n     OR NEW.workspace_id`, INV],
    ['C: acceptance no longer requires an invited member', `AND m.status = 'invited' AND m.role = OLD.role`, `AND m.role = OLD.role`, INV],
    ['C: acceptance ignores the organization status', `AND m.status = 'invited' AND m.role = OLD.role AND m.auth_user_id IS NOT NULL AND o.status = 'active') THEN`, `AND m.status = 'invited' AND m.role = OLD.role AND m.auth_user_id IS NOT NULL) THEN`, INV],
    ['C: early return for acceptance', `  IF NEW.status IS DISTINCT FROM 'accepted' THEN`, `  IF NEW.status = 'accepted' THEN\n    RETURN NEW;\n  END IF;\n  IF NEW.status IS DISTINCT FROM 'accepted' THEN`, INV],
    ['C: runtime may update expires_at', `GRANT INSERT (organization_id) ON workspace_members, workspace_invitations, auth_sessions, auth_audit_events TO hourvia_auth_runtime;`,
      `GRANT INSERT (organization_id) ON workspace_members, workspace_invitations, auth_sessions, auth_audit_events TO hourvia_auth_runtime;\nGRANT UPDATE (expires_at) ON workspace_invitations TO hourvia_auth_runtime;`, INV],
    ['D: membership identity index dropped', `CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id) WHERE auth_user_id IS NOT NULL;\n`, '', IDX],
    ['D: membership identity index without its predicate', `CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id) WHERE auth_user_id IS NOT NULL;`, `CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id);`, IDX],
    ['D: membership identity index on the wrong column', `CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id) WHERE auth_user_id IS NOT NULL;`, `CREATE INDEX workspace_members_auth_user ON workspace_members (email) WHERE auth_user_id IS NOT NULL;`, IDX],
    ['D: membership identity index uses hash', `CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id)`, `CREATE INDEX workspace_members_auth_user ON workspace_members USING hash (auth_user_id)`, IDX],
    ['D: pending-invitation index dropped', `CREATE INDEX workspace_invitations_organization_pending ON workspace_invitations (organization_id, expires_at) WHERE status = 'pending';\n`, '', IDX],
    ['D: pending-invitation index columns reordered', `workspace_invitations (organization_id, expires_at) WHERE status = 'pending'`, `workspace_invitations (expires_at, organization_id) WHERE status = 'pending'`, IDX],
    ['D: pending-invitation index predicate changed', `workspace_invitations (organization_id, expires_at) WHERE status = 'pending'`, `workspace_invitations (organization_id, expires_at) WHERE status <> 'revoked'`, IDX],
    ['D: pending-invitation index made unique', `CREATE INDEX workspace_invitations_organization_pending`, `CREATE UNIQUE INDEX workspace_invitations_organization_pending`, IDX],
  ];
  for (const [name, from, to, error] of mutations) {
    it(name, async () => {
      const at = M8_PROPOSAL_SQL.indexOf(from);
      expect(at).toBeGreaterThanOrEqual(0);
      expect(at).toBeLessThan(SELF_CHECK_START); // the mutation hits the definition, never the self-check pattern
      const mutated = M8_PROPOSAL_SQL.replace(from, to);
      expect(mutated).not.toBe(M8_PROPOSAL_SQL);
      const h = await createHarness({ now: new Date() }); // M1-M7
      await expect(applyMigration(h.pg, mutated)).rejects.toThrow(error);
      expect((await one<{ n: number }>(h, `SELECT count(*)::int n FROM pg_proc WHERE proname LIKE 'hourvia\\_%'`)).n).toBe(16); // rolled back to M7
      expect((await one<{ n: number }>(h, `SELECT count(*)::int n FROM pg_class WHERE relname = 'organization_seat_entitlements'`)).n).toBe(0);
    });
  }

  it('the proposal is byte-identical to the reviewed Sprint 3.0.5 digest (any edit invalidates review and rehearsal)', () => {
    expect(createHash('sha256').update(M8_PROPOSAL_SQL).digest('hex')).toBe(M8_PROPOSAL_DIGEST);
    expect(readFileSync(fileURLToPath(new URL('../../db/proposals/sprint-3.0/README.md', import.meta.url)), 'utf8')).toContain(M8_PROPOSAL_DIGEST);
    expect(readFileSync(fileURLToPath(new URL('../../docs/m8-preview-rehearsal-runbook.md', import.meta.url)), 'utf8')).toContain(M8_PROPOSAL_DIGEST);
  });

  it('the read-only preview verification script, run as netlifydb_readonly, distinguishes M7 from M8 exactly', async () => {
    const script = readFileSync(fileURLToPath(new URL('../../db/verification/sprint-3.0.5-m8-preview-readonly.sql', import.meta.url)), 'utf8');
    for (const multiOrganization of [false, true]) {
      const h = await createHarness({ now: new Date(), multiOrganization });
      await h.pg.exec('SET SESSION AUTHORIZATION netlifydb_readonly');
      const results = await h.pg.exec(script);
      await h.pg.exec('SET SESSION AUTHORIZATION netlifydb_owner');
      const checks = results.find(r => r.rows.length)!.rows as { check: string; ok: boolean }[];
      expect(checks).toHaveLength(9);
      expect(checks.map(c => c.ok)).toEqual(checks.map(c => c.check.startsWith('M8-0') ? !multiOrganization : multiOrganization));
    }
  });

  it('the unmodified proposal passes, installs 23 pinned functions and the invitation guard, and refuses a second run', async () => {
    const h = await createHarness({ now: new Date() });
    await applyMigration(h.pg, M8_PROPOSAL_SQL);
    expect((await one<{ n: number }>(h, `SELECT count(*)::int n FROM pg_proc WHERE proname LIKE 'hourvia\\_%'`)).n).toBe(23);
    expect((await one<{ n: number }>(h, `SELECT count(*)::int n FROM pg_trigger WHERE tgname = 'workspace_invitations_guard_update' AND tgenabled = 'O'`)).n).toBe(1);
    expect((await one<{ x: boolean }>(h, `SELECT has_function_privilege('hourvia_auth_runtime', 'hourvia_guard_invitation_update()', 'EXECUTE')
      OR has_function_privilege('netlifydb_readonly', 'hourvia_guard_invitation_update()', 'EXECUTE') AS x`)).x).toBe(false);
    await expect(applyMigration(h.pg, M8_PROPOSAL_SQL)).rejects.toThrow(/already exists/);
  });
});
