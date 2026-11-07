# Sprint 3.0 — M8 proposal: multi-organization memberships

**Status: PROPOSAL. Not applied anywhere.** `20261106120000_multi-organization-memberships.sql` lives here, outside `netlify/database/migrations/`, so Netlify never applies it to a preview or production database branch. It has been exercised only on disposable databases: embedded PostgreSQL (PGlite) in `server/auth/multi-organization*.test.ts` and `server/auth/m8-security-closure.test.ts`, and throwaway local PostgreSQL 18 clusters created and deleted by `scripts/rehearsal/`.

## Dependencies

- **Requires exactly M1–M7**, in their pinned form (`server/auth/production-database.ts`, `docs/operations-status.md`). Preconditions abort unless:
  - the database is in the M7 state: `organizations` and `organizations_single_tenant_m7` exist, the global `workspace_members_auth_user_id_key` is present, and the 16 expected `hourvia_*` functions are all pinned;
  - ThriveSource is the only organization and every row belongs to it;
  - RLS is off.
- **The M7 production ledger provenance issue is not resolved.** The production ledger recorded M7 before it reached `main`, and no deploy records the write ([operations status](../../../docs/operations-status.md)). M8 must not be promoted until all three of these have happened:
  1. The owner has run `netlify db status --branch production --json` and confirmed exactly M1–M7, with nothing pending, missing or out of order.
  2. The production catalog has been independently verified against M7, for example with `db/verification/sprint-2.0b-preview-readonly.sql`.
  3. The M7 provenance finding has been closed or explicitly accepted by the owner.

## What M8 changes

| Area | Change |
|---|---|
| Organizations | Drops `organizations_single_tenant_m7`. ThriveSource's UUID ⇔ slug `thrivesource` is permanent (CHECK). `internal` kind ⇔ ThriveSource (CHECK). Adds `updated_at` (guard-maintained) and `(id, slug)` and `(id, kind)` keys. |
| Workspace binding | `CHECK (workspace_id = 'thrivesource')` on members, invitations, assignments and audit is replaced by FK `(organization_id, workspace_id) → organizations (id, slug)`. The FK is validated *before* the CHECK is dropped. |
| Identities | Global `UNIQUE (auth_user_id)` is replaced by `UNIQUE (organization_id, auth_user_id)`. One Supabase identity can hold one membership per organization, each with its own role and status. |
| Status | Adds `suspended` (requires a previously activated member). Only operators set or clear it. The runtime guard refuses it. `disabled` remains the deactivated/removed state. |
| Immutability | `organization_id` can't be updated on members or sessions, for any role. The runtime has no UPDATE privilege on it anywhere. |
| Seats | New `organization_seat_entitlements` table, with plan `internal_unlimited` (ThriveSource only, no limit, no billing expiry) or `standard` (customer, 1–100000 seats, optional billing expiry). Guards on member insert or activation and on pending-invitation insert enforce the limit under a per-organization advisory lock. |
| Audit triggers | `hourvia_audit_member_change` and `hourvia_audit_session_revocation` write the member's `organization_id` explicitly. These were the Sprint 2.0C prerequisites found in M7 testing. |
| Platform | `hourvia_is_verified_platform_candidate` accepts only the designated mailbox's **ThriveSource** membership. A same-email membership in another organization can never be designated or granted. |
| Platform authority (3.0.1) | `hourvia_member_authority` returns `platform_super_admin` only for the holder's **ThriveSource** Administrator membership. In a customer organization the same identity has plain `workspace_admin` authority, so it can't invite, promote, demote, disable or end sessions of Administrators there. |
| Sessions (3.0.1) | New `BEFORE INSERT` guard on `auth_sessions`: the member and organization must be active (re-read under a shared per-organization advisory lock), the row must be unrevoked, and the absolute lifetime is at most 24 hours. |
| Suspension (3.0.1) | Suspending a member, or suspending or closing an organization, revokes its unrevoked sessions in the same transaction (reasons `member_suspended`, `organization_suspended`, `organization_closed`), under the exclusive per-organization lock. Revocation is final, so reactivation never restores a session; users sign in again. The revocations are audited (authority `operator`). |
| Disable (3.0.2, G1) | The member trigger (`workspace_members_status_session_revocation`, renamed from `workspace_members_suspension_revocation`) also fires on every transition into `disabled`: reason `member_disabled`, `revoked_by_member_id = disabled_by`, so the audit names the disabling Administrator with their authority (re-checked by the session guard for the runtime), or `operator` when operator SQL leaves `disabled_by` empty. Leaving `disabled` or `suspended` sweeps any still-unrevoked session (reason `member_reinstated`), which covers sessions left behind by a pre-3.0.2 non-atomic disable. Same exclusive lock as suspension. |
| Session lifetime (3.0.2, G2) | The session insert guard refuses `created_at` more than 2 minutes ahead of the database clock (`clock_timestamp()`) and any absolute expiry beyond database time + 24 h 2 min, so a manipulated timestamp can't extend the cap. Past `created_at` only shortens a session. The self-check pins both. |
| Isolation (3.0.1) | Seat consumers (pending invitation, activation, reactivation), session creation and suspension refuse to run unless `transaction_isolation` is `read committed`. The advisory locks are only sufficient at that level. |
| Runtime inserts (3.0.1) | Outside ThriveSource, an application audit row must name an actor or subject member (then bound to the organization by the composite FKs). A member row the runtime inserts must have an invitation from an inviter by COMMIT (deferred constraint trigger), so the runtime can't create unauthorized member rows in any organization. |
| Runtime grants | `INSERT (organization_id)` on `workspace_members`, `workspace_invitations`, `auth_sessions` and `auth_audit_events`. `SELECT (organization_id, plan, seat_limit, billing_expires_at)` on entitlements. Nothing else changes. |

**Seat rule.** These consume a seat:
- active members;
- pending, unexpired invitations to invited members, which reserve a seat.

These do not consume a seat:
- invited members without a pending invitation;
- suspended members;
- disabled members.

Organizations are counted independently. An organization with no entitlement row can't invite or activate anyone, so it fails closed. Re-sending an invitation replaces its own reservation.

**Lock protocol (3.0.1).** Two advisory locks, per organization:
- `hourvia_seats:<org>`, exclusive, taken by every seat consumer. It serializes the count-then-insert, so concurrent consumers can't over-allocate.
- `hourvia_sessions:<org>`, shared for session creation and exclusive for suspension. A session committed concurrently with a suspension is either refused (suspension first) or revoked by it (session first).

Both are verified on a disposable PostgreSQL 18 cluster by `scripts/rehearsal/multi-organization-rehearsal.sh` (S1–S11). Sprint 3.0.2 adds deterministic interleavings for: switch winning before logout and the reverse; switch racing administrator revocation in both orders; organization suspension during an open switch transaction in both orders; and disable racing a switch, followed by reinstatement. `scripts/rehearsal/platform-grant-rehearsal.sh m8` runs the 16 AP-PSA-GRANT scenarios on M1–M7 + M8.

**Known, accepted semantics (3.0.2).** Administrator session revocation (`revoke-sessions`) is point-in-time: a session committed after it (for example, a switch that was mid-transaction) is a new sign-in and stays valid (S9c). A lasting block is disable or suspension, which serialize with session creation under the per-organization lock (S10, S11).

## Backfill

None is needed, and none is performed:
- No row is inserted, updated or deleted except the single seeded ThriveSource entitlement.
- Existing rows already satisfy every new constraint: all of them are ThriveSource with `workspace_id = 'thrivesource'`.
- `updated_at` takes a single non-volatile default, which is catalog-only.
- Validations are read-only scans, so append-only audit triggers never fire.

The self-check compares counts and content fingerprints of all ten affected tables before and after, and aborts on any difference.

## Authorization and RLS implications

- **No RLS.** One runtime role (`hourvia_auth_runtime`) serves every organization. Policies keyed on a session setting would depend on a value the runtime sets itself, and the statement policy deliberately forbids `set_config`. Isolation is layered instead:
  1. **Database.** Composite foreign keys keep every child row in its member's organization. The workspace FK binds the legacy key to the slug. `organization_id` is immutable. Guards check inviter and actor authority *within the row's organization* (`hourvia_member_authority`). The runtime can't write organizations or entitlements.
  2. **Statement layer.** `server/auth/tenant-sql.ts` requires an `organization_id = $n` predicate bound to the request's server-built context on every tenant table, including the M8 table and reserved future business tables. Explicit `organization_id` INSERTs must bind a bare parameter equal to the context.
  3. **Identity directory.** Only two fixed, allowlisted statements read across organizations. The identity always comes from the session row and is never taken from caller input.
  4. **Service.** The organization context is derived from the session. A client-supplied organization id is only a switch *request*, matched against the identity's own memberships.

  Adding RLS later as defence in depth is a separate decision for a future sprint.
- **Administrator management** still requires an Administrator membership *in the same organization* plus the platform privilege, which since Sprint 3.0.1 only counts in ThriveSource. So nobody can manage Administrators of a customer organization through the application; until an owner role exists, that is operator SQL only. **Open product decision:** whether customer organizations should get an organization-owner role able to manage their own Administrators. M8 does not add one.
- `hourvia_platform_overview` still reports ThriveSource counts only. That is unchanged and harmless.

## Promotion and forward-only deployment strategy

1. Owner approval of this proposal and the Sprint 3.0 code review.
2. Resolve every dependency listed above.
3. In one reviewed PR:
   - copy this file byte-for-byte into `netlify/database/migrations/`;
   - pin its SHA-256 next to M1–M7 (`MIGRATIONS` / `MIGRATION_DIGESTS`, `docs/operations-status.md`, `migration-readiness.test.ts`);
   - extend `server/auth/production-catalog.ts` and the evidence `migrationHistory` to the M8 catalog;
   - replace the test-only capability with an evidence-bound check.

   Until all of that happens, production refuses an M8 database. The evidence gate pins exactly M1–M7, so authentication stays unavailable.
4. Apply the migration first to an isolated preview database branch, never production. Run read-only catalog verification there.
5. Merge to `main` only with explicit owner approval. The production deploy applies M8 in one transaction.
6. Contract step, as a separate later migration once no deployed code relies on them: drop the ThriveSource `organization_id` column defaults.

## Rollback limitations

- **During application:** the file runs in one transaction. Any precondition, statement or self-check failure rolls back everything.
- **After commit:** M8 is forward-only, so there is no down migration. Republishing a pre-M8 deploy is prohibited, because it no longer carries M8 and the platform reports a migration-history error. Roll back only to a deploy built from a commit that contains M1–M8.
- **Code compatibility:** M8 keeps the ThriveSource defaults and every runtime grant, so the Sprint 2.0B and 3.0 application code (ThriveSource-only HTTP paths) keeps working unchanged on an M8 database. A test covers this.
- **Irreversibility:** once any identity holds memberships in two organizations, or a second organization or entitlement exists, global `auth_user_id` uniqueness and `organizations_single_tenant_m7` can't be restored without deleting tenant data. Any undo must be a reviewed forward migration.
- Operator reinstatement or unsuspension into a full organization is refused by the seat guard. The operator must free a seat or raise the entitlement first.
- Operator SQL that suspends members or organizations, or reactivates or reinstates members, must run at `READ COMMITTED` (the PostgreSQL default). Any other level is refused.
