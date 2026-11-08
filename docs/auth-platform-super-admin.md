# Hourvia Platform Super Admin privilege

**Status: schema deployed; privilege not usable while authentication is fail-closed.** Netlify deploy metadata records migrations `20261104120000` and `20261104130000` as applied to the production database by deploy `6aea8aec9a00df94dd253407` (2026-11-04 01:31 UTC). Whether anyone holds the privilege in production is **unverified**: production database reads are unavailable from Agent Runner (401). No grant has been authorized by any sprint. See [operations status](operations-status.md).

This privilege replaces the withdrawn workspace role `super_admin`, which came from migration `20261104120000`. That migration stays unchanged. Migration `20261104130000_platform-privileges-correction` corrects it, forward-only.

## 1. Model: two independent planes

| Plane | Where it is stored | Values | Who changes it |
| --- | --- | --- | --- |
| **Organization role** | `workspace_members.role`, one row per organization membership | `workspace_admin` (Administrator), `workspace_manager` (Manager), `contractor` (Contractor). Owner is designed for a later sprint. | The application, within the caller's authority (section 2) |
| **Platform privilege** | `platform_privileges`, keyed by Supabase Auth UID, not by membership | `platform_super_admin` | **Only** the approved operator procedures (section 4). The application can read it, never write it. |

The rules that connect the two planes:
- **No implication.** An organization role never implies a platform privilege, and a platform privilege never implies an organization role. Living IT Solutions keeps its ThriveSource `workspace_admin` membership, its member ID, sessions, login and history. The grant doesn't touch that row.
- **Eligibility.** A database trigger enforces who can hold the privilege. It must be:
  - the **designated** UID, which is written once and immutable afterwards;
  - and that UID must be bound to the **active, invitation-verified** membership of `livingitsolutions@gmail.com`.

  There can be at most one active holder.
- **No cross-organization data access.** Organization data permissions come only from the organization role. The platform privilege adds exactly one capability, `administrators.manage`, and only inside an organization where the holder is an **active Administrator**. A holder who is a Manager, or who isn't a member, manages nobody.
- **Principal.** The principal is `{ …, role, platformPrivileges: ['platform_super_admin'] | [] }`. It is rebuilt from the database on every request, so revoking the privilege takes effect on the next request.

## 2. Authorization matrix

The API is authoritative. The database triggers enforce the same rules again for the restricted runtime role.

| Action | Administrator + Platform Super Admin | Administrator | Manager | Contractor | Anonymous |
| --- | --- | --- | --- | --- | --- |
| List members, open Workspace Settings | ✅ | ✅ | 403 | 403 | 401 |
| Invite, change, disable or end the sessions of a Manager or Contractor | ✅ | ✅ | 403 | 403 | 401 |
| Invite an Administrator, promote to it, demote from it, disable one or end one's sessions | ✅ | 403 (database: `not authorized`) | 403 | 403 | 401 |
| Request `platform_super_admin` or `super_admin` through an invitation or role change | 400, audited | 400, audited | 403 | 403 | 401 |
| Grant or revoke a platform privilege | ✖ (operator procedure only) | ✖ | ✖ | ✖ | ✖ |
| Change own role or disable self | 403 / 409 | 403 / 409 | 403 | 403 | — |
| End own sessions | ✅ | ✅ | via logout | via logout | — |
| Organization time data | Per organization role | All in the organization | Assigned Contractors | Own | — |
| Another organization's data | ✖ | ✖ | ✖ | ✖ | ✖ |

## 3. Database enforcement (`20261104130000`)

- **Withdraws `super_admin`.** The migration drops the designated-email CHECK and the one-holder index, and restores the role CHECK to the three organization roles. It aborts if any `super_admin` row exists.
- **New tables:**
  - `platform_super_admin_designation`: a single row, immutable.
  - `platform_privileges`: grant history. A row can be revoked once. Rows are never deleted or edited, and reinstatement inserts a new row.
  - `platform_audit_events`: append-only.

  Each has a guard trigger and an audit trigger, and none can be truncated.
- **Membership guards.** These replace the earlier function bodies; the triggers are unchanged. For the runtime role:
  - Every role change and disable must name an actor who is an active Administrator of the **same** organization and isn't the member being changed.
  - Anything involving `workspace_admin` also needs that actor to hold the active platform privilege, checked through `hourvia_member_authority(actor, organization)`.
  - Invitations follow the same rules.

  Disabling remains terminal for the application. Operators may reinstate a member only through the approved procedure.
- **Session attribution.**
  - The new column `auth_sessions.revoked_by_member_id` is required for every revocation made by the application.
  - Revoking someone else's sessions needs the same authority as managing them.
  - Revocation is final: none of its fields can change once it is set. Identity columns are immutable.
  - Every revocation writes an audit row, `session_revocation`, recording the actor, the reason, the authority (`self`, `workspace_admin`, `platform_super_admin` or `operator`) and the source.
- **Runtime privileges.** The runtime gets SELECT on `platform_privileges (auth_user_id, privilege, revoked_at)` only. It gets nothing on the designation or the platform audit, and no write access at all. `netlifydb_readonly` and PUBLIC get nothing. A self-check at the end of the migration aborts the deploy if any of this differs.

## 4. Operator procedures (`db/operations/platform/`)

Each procedure is owner SQL that needs its own written approval. Each one locks, checks its guards, is idempotent, records an approval reference, writes an audit row and deletes nothing.

| Procedure | Approval | Effect |
| --- | --- | --- |
| `grant-platform-super-admin.sql` | AP-PSA-GRANT | Locks the Living IT Solutions membership row (`SELECT … FOR UPDATE`), then verifies that the UID **and** the member ID match it, that it is `active` and activated, and that its role is `workspace_admin` (Administrator). A Manager or Contractor membership is refused and nothing is written. Writes the designation on the first run. Inserts the grant. A re-run while the grant is active writes nothing. After a revocation, a new run with a new approval reinstates it. |
| `revoke-platform-super-admin.sql` | AP-PSA-REVOKE | Revokes the active grant, with a reason. Optionally ends every session of that identity, audited as `operator`. Doesn't change the membership. Re-running it is a no-op. |
| `reinstate-disabled-member.sql` | AP-MEMBER-REINSTATE | Restores a member who was disabled in error to `active`, with the **same** role. Unban the Supabase user first, under the same approval. Doesn't restore ended sessions and doesn't grant any privilege. Since Sprint 3.0.2 it first revokes any session of the member that is still unrevoked (reason `member_reinstated`, counted in the audit row as `stale_sessions_revoked`), so reinstatement can never revive an old session. |

Changing the designated UID, for example if the Supabase identity is permanently lost, deliberately needs a reviewed forward migration. Membership identity is also immutable, so a new identity for the same mailbox needs a reviewed procedure in any case.

**Grant run sheet** (production only, after the release prerequisites in the change record):
1. **Q1, read-only:** `SELECT id, auth_user_id, role, status, activated_at IS NOT NULL AS activated FROM workspace_members WHERE email = 'livingitsolutions@gmail.com';` Expect exactly one row with `role = 'workspace_admin'`, `status = 'active'` and `activated = true`. **Stop if the role is anything other than `workspace_admin`.** The grant refuses it (`grant_guard: the membership role is …, not workspace_admin`), and changing the role is a separate, separately approved application action, never part of this procedure. Copy `id` and `auth_user_id`; don't type them.
2. **Q2, read-only:** `SELECT count(*) FROM platform_privileges WHERE revoked_at IS NULL;` Expect `0`.
3. Run the grant procedure with the three placeholders replaced. Expect the notice `platform_super_admin_granted`.
   - Run it as a single statement, outside any explicit transaction you opened yourself, so that it commits or rolls back on its own.
   - Don't change the Living IT Solutions membership (role, status, sessions) while the procedure runs. The procedure holds the row lock until it commits, and a conflicting change waits for it. If the procedure can't take its locks within 5 seconds, it fails with a lock timeout and writes nothing. Re-run Q1 and Q2, then retry.
   - Any `grant_input`, `grant_guard` or `grant_selfcheck` error means the whole run rolled back: no designation, no grant and no audit row. Re-run Q1 before deciding what to do next.
   - Lock order, shared with the other procedures: designation table, then `platform_privileges`, then the membership row, then sessions and audit. Don't run ad-hoc SQL that locks these in a different order while a procedure is running.
4. **Verify:**
   - `SELECT event_type FROM platform_audit_events ORDER BY id;` should return `platform_designation_set` and `platform_privilege_granted`.
   - The membership role is still `workspace_admin`.
   - After a reload, the sidebar shows the **Platform Super Admin** badge.

## 5. Runtime database role: limits that remain

- **Session user.** The function connects as `netlifydb_owner` and runs every statement under `SET LOCAL ROLE hourvia_auth_runtime`. Any code able to run arbitrary SQL could `RESET ROLE` and act as owner, bypassing the runtime-only rules. Everything else here is defence in depth. A hard boundary needs a dedicated LOGIN role with its own credential, and it isn't confirmed that Netlify Database supports that. **Unresolved** — see the Sprint 1.8 investigation in section 7.
- **Temporary-table shadowing (fixed in Sprint 1.8B, section 8).** `PUBLIC`, and so the runtime, holds `TEMPORARY` on the database. Before `20261104160000`, every `hourvia_*` function resolved table names from `pg_temp` first, so runtime SQL could shadow guarded tables with temp tables.
- **What still holds for the owner:**
  - identity immutability
  - append-only audit tables
  - immutable designation and grant history
  - eligibility of the designated UID
  - the one-active-holder index
  - the role CHECK
  - the ban on re-enabling a disabled member without the reinstatement flag
- **What doesn't hold for the owner:** the approval flags (`hourvia.member_reinstatement`) only guard against mistakes; anyone with owner access can set them. Only change control and the audit trail detect misuse.
- **Existing mitigations:** the SQL is fixed-text and parameterized, and a static test forbids any database access outside the role-scoped client. Audit triggers fire for every role.

## 6. Residual risks

- While `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false`, every application invitation returns 503. Role changes don't need email.
- In smoke mode, only allowlisted emails can be invited or administered.
- The new isolation and seat-race guarantees for SaaS are design only. See [saas-pwa-architecture.md](saas-pwa-architecture.md).

## 7. Platform Administration console (Sprint 1.8, `20261104150000`)

A read-only console for the active Platform Super Admin. Grant, revoke and reinstatement stay operator-only (section 4).

**Authorization planes.** Platform permissions (`platform.console`, `platform.overview.read`, `platform.audit.read`, in `src/domain/platform.ts`) come only from active platform privileges, never from the organization role. Workspace permissions are unchanged, and the platform privilege still adds only `administrators.manage` inside an organization where the holder is an Administrator. Consequence: a holder who is a Manager (reachable only through direct owner SQL) can open the console but administers nobody.

**Enforcement, three layers.**
1. **UI.** The Platform sidebar group and `/platform`, `/platform/audit` routes are shown only for `platform.console`. Other users get the restricted page and no API call is made.
2. **API.** `GET /api/platform/overview` and `GET /api/platform/audit?limit=1..100&before=<id>` require a valid session (401 otherwise) and the platform permission (403 `platform_forbidden` otherwise, audited as `platform_access` / `denied` in `auth_audit_events`). Query parameters are validated after authorization. Responses are `no-store`. Cross-site, same-site, navigation and foreign-Origin requests are refused. There are no platform write, grant, revoke, impersonation or organization-listing routes.
3. **Database.** The runtime calls `hourvia_platform_overview(token_hash)` and `hourvia_platform_audit_page(token_hash, before, limit)`. They are `SECURITY DEFINER` with a pinned `search_path`, and EXECUTE is granted to `hourvia_auth_runtime` only. Each function re-authorizes from the **session**: unrevoked, unexpired by the database clock, active ThriveSource membership, designated and verified identity, active grant. Otherwise it returns NULL and the API returns 403. No table privilege was added: the runtime still cannot read `platform_audit_events`, the designation or grant approval references directly, and cannot write any platform table.

**What the console shows.** The holder's own active grant (date, approval reference), the designation date, grant history counts, **aggregate** ThriveSource membership counts (no identities, no other tenant), and the platform audit trail newest first. Other identities appear only as a 4-character UID suffix, and detail keys are allowlisted. Every audit page read is itself recorded as `platform_audit_read`.

**Fail-closed behaviour.**
- Revoking the grant denies the next request; the workspace session continues unless `END_SESSIONS=true`.
- Disabling the holder's membership ends access (401), even though the grant row stays active.
- Session expiry and logout end access.

**Owner connection / dedicated LOGIN role — investigation.**
- `@netlify/database` `getDatabase()` accepts a `connectionString` override, and `netlifydb_owner` has `CREATEROLE`. Mechanically, a `LOGIN` role with a password could therefore be created and used.
- It is **not confirmed as supported** by Netlify Database. Nothing documents that the platform connection proxy authenticates custom roles. A password would have to be set out of band (it must never appear in a migration) and stored as a secret. Each database branch would need the role and credential provisioned separately.
- No change was made. Until a preview-branch experiment confirms support, the boundary stays `SET LOCAL ROLE` under the owner session (defence in depth, not a hard boundary).
- The new platform functions do not widen this risk: code able to `RESET ROLE` already had owner access to these tables.

**Deployment notes.** `20261104150000` creates functions only and changes no table, grant or row. Its self-check aborts the deploy if the function security properties or the platform table privileges are not as expected. It is applied on the preview branch and pinned by SHA-256 (`b1f199ea…aea0`); it must never be edited. Its `search_path` is corrected forward-only by `20261104160000` (section 8). Netlify applies it on deploy. Verify on a preview branch before production.

## 8. Security hardening (Sprint 1.8B, `20261104160000`)

**H-1: `pg_temp` pinned last.**
- **The problem.** When `pg_temp` is not listed in a function's `search_path`, PostgreSQL searches the temporary schema **first** for tables. The Sprint 1.8A audit showed that runtime-role SQL could use temp tables named like the guarded tables to:
  - read the platform audit through `hourvia_platform_audit_page` without a holder session;
  - let an ordinary Administrator promote a Contractor to Administrator past `hourvia_guard_member_update`.
  A third variant was also found: a Contractor disguised as an Administrator in a temp `workspace_members` table.
- **The fix.** `20261104160000` runs `ALTER FUNCTION … SET search_path = pg_catalog, public, pg_temp` on all 15 `hourvia_*` functions, listed explicitly. Functions and operators are never resolved from `pg_temp`, and tables now resolve to `public` first.
- **Unchanged:** function signatures, bodies, volatility, `SECURITY DEFINER` flags, ownership and EXECUTE grants. No privilege is granted or revoked, and no row changes.
- **Self-check.** The migration aborts if:
  - the set of `hourvia_*` functions differs from the reviewed list;
  - any function's config isn't exactly `search_path=pg_catalog, public, pg_temp`;
  - `SECURITY DEFINER` is set anywhere other than the two platform read functions;
  - a function isn't owned by the migration role, or its EXECUTE grants changed;
  - the runtime can `CREATE` in `public` or create schemas.
- **New functions.** Any future `hourvia_*` function must declare `SET search_path = pg_catalog, public, pg_temp` itself. Otherwise this migration's list no longer matches, and a later self-check should be added.
- **Not done: revoking TEMP.** Revoking `TEMPORARY` from `PUBLIC` would also close the vector, but it removes TEMP from `netlifydb_readonly` and possibly from platform tooling. It is left for a separately tested change.

**M-1: platform request limits** (`PLATFORM_LIMITS` in `server/auth/service.ts`). These are fixed one-hour windows, keyed by HMAC.
- **Denials:** 10 per member and 30 per IP. The limit is checked **before** the denial is audited. Past it, the caller gets 429, and only the first rejection in each window writes a `rate_limited` row.
- **Audit-page reads:** 60 per member. The limit is checked after authorization and parameter validation, and **before** the database call that writes `platform_audit_read`.
- **Unaffected:** unauthenticated requests (401) are neither limited nor audited, and the holder's overview and workspace administration are not limited.
- **Authorization is unchanged.** A 429 never carries platform data, and a rate-limited holder still passes every other check.

**Tests** (`server/auth/platform-security.test.ts`). Each attack runs in a fresh PGlite database, as `hourvia_auth_runtime`, inside a transaction that is always rolled back. It is shown succeeding without `20261104160000` and failing with it. Other tests cover catalog preservation, the self-check's abort paths, applying over a live holder without changing data, and every rate-limit path.


## 9. Runtime hardening (Sprint 1.9C, corrected in Sprint 1.9C.1; code only)

No migration, role, grant, credential or environment variable changed. Authorization semantics are unchanged. Sprint 1.9C.1 corrected three gate findings: F-1 (a policy bypass), F-2 (a transaction-handle window) and F-3 (a lock-order deadlock).

**Statement policy** (`server/auth/sql-role.ts`)
- **Scope.** The store's client is `statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool)))`, so every store statement passes the policy before it reaches the database. The policy scans the whole statement text, string literals included, so quoting can't hide a token.
- **A statement is rejected if it:**
  - contains `;`, so only one statement is allowed;
  - contains `--` or `/*`;
  - contains a double quote or a `U&` escape. Quoted or Unicode-escaped identifiers, such as `"set_config"`, were the 1.9C bypass, and store SQL uses neither;
  - doesn't start with `SELECT`, `INSERT` or `UPDATE`;
  - mentions `set_config` or `pg_settings` anywhere, in any case. `UPDATE pg_settings` calls `set_config` internally.
- **Failure mode.** A violation throws before the database is contacted, and the request returns 503. Tests prove the rejected statement never reaches the client, both in `query()` and inside `transaction()`.
- **Limits.**
  - It is a lexical rule set, not a SQL parser. It is defence in depth on top of fixed-text, parameterized SQL.
  - It does not protect against code execution inside the Function (section 5).
  - New store SQL must not use quoted identifiers, comments or semicolons; such SQL would fail closed.

**Transaction lifecycle** (`poolSqlClient` in `server/auth/runtime.ts`)
1. `BEGIN`, then the callback runs with a transaction handle.
2. The handle closes the moment the callback settles, before `COMMIT` or `ROLLBACK` is sent. After that, every `tx.query` is rejected with `TransactionClosedError` and never reaches the connection. This covers:
   - delayed timers;
   - detached continuations;
   - a sibling `Promise` branch still running after another branch threw;
   - retained references.
3. Queries the callback started but didn't await are drained first. If one of them failed, the transaction rolls back and the error is thrown.
4. A `COMMIT` that the server reports as `ROLLBACK` (an already-aborted transaction) is treated as a failure.
5. If `ROLLBACK` itself fails, the connection is destroyed rather than returned to the pool. The original error is reported.

As before, `SET LOCAL ROLE` reverts at `COMMIT` or `ROLLBACK`. Tests on one reused physical connection show it never carries over to the next checkout.

**Lock order for membership writes** (`server/auth/store-postgres.ts`)
- **The order.** The `workspace_members` row is locked first, then its invitations. This holds for `upsertInvitation`, `disableMember` (whose status change, session revocation and invitation revocation are one transaction since Sprint 3.0.2: member row lock, sessions, member status, invitations) and `acceptInvitation`.
- **The change.** `acceptInvitation` now starts with `SELECT … FOR NO KEY UPDATE` on the member row. That is the same lock its activation `UPDATE` already took, so foreign-key inserts that reference the member are not blocked.
- **Effect.** A concurrent accept and disable on the same member now serialize instead of deadlocking.
- **Outcomes.**
  - Disable first: the invitation is revoked and the acceptance is refused.
  - Accept first: the member is activated, then disabled.
  - Each status change is audited by the database as before.
- **Not changed.** Acceptance, revocation and audit semantics. Operator procedures lock in their own documented order (section 4) and don't write invitations.

**HTTP** (`server/auth/http.ts`, `server/auth/runtime-log.ts`)
- A declared body over 8 KB, a malformed `Content-Length` or a broken request stream gets 400.
- Internal failures get a generic 503 and log one `hourvia_auth_error` line with only the error class and SQLSTATE code. The message is never logged.
- An idle pool-client error is logged instead of crashing the Function instance.

**Verification**
- **Unit and integration tests** (`server/auth/runtime-hardening.test.ts`): run with PGlite for single-connection semantics. The harness store uses the same policy as production, and `h.sql` stays raw so tests can still prove what the database itself denies.
- **Real concurrency** (`server/auth/platform-grant.rehearsal.test.ts`, tests 6a–6c and 7a–7b): run on a disposable PostgreSQL 18 cluster with `bash scripts/rehearsal/platform-grant-rehearsal.sh`. The template now applies all six applied migrations.
- **Regression proof.** Against the previous `acceptInvitation`, tests 6b and 6c reproduce a real `40P01 deadlock detected`, and 6a shows accept holding the invitation lock first.
