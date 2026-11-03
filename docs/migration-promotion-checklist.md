# Hourvia Sprint 1.7: auth migration readiness and promotion checklist (2026-11-03)

This review covers the two staged files in `db/proposals/sprint-1.7-auth/`. **Nothing was applied to any Netlify database.** Nothing was merged, deployed, emailed or created, and authentication stays disabled. Both files stay outside `netlify/database/migrations/`, which doesn't exist in the repository.

This document replaces the "Migration promotion checklist (Gate 2)" in [auth-preflight.md](auth-preflight.md). That checklist's P5 membership query expected one row; on a real non-superuser platform there are two (see V4).

**Evidence sources:**
- read-only catalog queries through the `netlifydb_readonly` CLI credential on this session's preview database branch (a copy of production, PostgreSQL 18.6)
- Netlify's local migration tooling source (`@netlify/database-dev`)
- the local test suite on disposable PGlite (PostgreSQL 18)

No credentials were read or printed.

## Gate results

| # | Gate | Result |
| --- | --- | --- |
| 1 | Migration ordering and compatibility with the current production schema | **PASS** |
| 2 | `netlifydb_readonly` cannot access sensitive auth tables (effective, inherited and default grants) | **PASS** (fixed in this change; on-platform confirmation in V5 and V6) |
| 3 | Restricted role can be created and granted by Netlify's actual migration role | **PASS** in non-superuser emulation (it was **failing** before this change); **BLOCKED** for final proof until the promotion preview deploy (P4) |
| 4 | All auth queries use the restricted role and fail closed | **PASS** |
| 5 | Invitation, session, membership, audit and rate-limit constraints | **PASS** (tightened in this change) |
| 6 | Full local suite on disposable PostgreSQL | **PASS**: 104 passed, 0 failed, 5 skipped (live Supabase tests, which need authorization); `tsc --noEmit` clean |
| 7 | Promotion checklist, preview validation, production verification, rollback | **PASS** (below) |
| — | **Migration promotion** | **BLOCKED** until the operator approvals listed at the end |

### Gate 1: ordering and compatibility

- **Schema.** The current schema (preview branch copied from production) has 0 user tables and 0 functions in `public`. `netlify db status` shows 0 applied and 0 pending migrations, and the only extension is `plpgsql`. Nothing collides with the six tables or the two functions.
- **Dependencies.** `gen_random_uuid()` is built in, and `GRANT … WITH INHERIT/SET` and the `MAINTAIN` privilege need PostgreSQL 16 or later and 17 or later. Production runs 18.6.
- **Ordering.** Netlify sorts migration names lexicographically. `002` depends on `001`'s tables. Run the other way round, `002` aborts and rolls back completely, including the role it creates (tested).
- **Transactions.** Netlify's local tooling applies each file in its own transaction and records it in `netlify.migrations`. The production runner isn't visible to us, so V1 confirms it there. To keep each file safe on its own, `001` now removes read-only access by itself. If `002` fails, the empty tables exist but nobody except the owner can read them, and auth stays at 503.

### Gate 2: `netlifydb_readonly` exposure (was failing)

Live catalog finding: `pg_default_acl` contains `netlifydb_owner / public / tables → {netlifydb_readonly=r}`. Every table a migration creates is therefore readable by the read-only credential, which includes members' emails, session token hashes, invitations, rate-limit buckets and audit records. The previous `002` revoked access only from `PUBLIC` and from the runtime role.

**Fix:** `001` and `002` both revoke all privileges on the six tables and the audit sequence from `PUBLIC` and from `netlifydb_readonly`. Trigger functions are no longer executable by `PUBLIC`.

**Effective privileges, checked live on the branch:**
- `netlifydb_readonly` has no role memberships and isn't in `pg_read_all_data`, so it inherits no privileges.
- `netlifydb_owner` holds `netlifydb_readonly` only with ADMIN (no SET, no INHERIT).
- `pg_read_all_data` belongs only to `neon_superuser` (whose members are `netlifydb_owner` and `neon_service`).

**Migration self-check.** `002` now ends with a check that **aborts the migration**, and therefore the deploy, if any of these is true:
- `PUBLIC` or `netlifydb_readonly` has *any* effective table or column privilege on an auth table, as seen by `has_table_privilege` / `has_any_column_privilege`, which follow inherited memberships such as `pg_read_all_data`
- any role other than the owner and `hourvia_auth_runtime` appears in a table, column or sequence ACL
- the runtime role holds DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN or CREATE, can read audit, can write assignments, or can update the identity or approval columns

The default ACL itself is **left in place**, because changing it would affect every future table. See risk R11.

### Gate 3: the real migration role (was failing)

Netlify's database roles are: `netlifydb_owner` (CREATEROLE, CREATEDB, BYPASSRLS, LOGIN, a member of `neon_superuser`, **not a superuser**), `netlifydb_readonly`, `neon_superuser`, `cloud_admin` (superuser, the platform's) and `neon_service`. The database is owned by `netlifydb_owner`.

The new test harness recreates this catalog in PGlite and runs **both migrations and all 104 tests as the non-superuser `netlifydb_owner`**, so passing locally as a superuser no longer counts as evidence.

Result:
- **The previous `002` failed** with `permission denied to alter role`. In PostgreSQL 16 and later, only a superuser may name `SUPERUSER` or `REPLICATION` in `ALTER ROLE`, even just to clear them. That would have blocked the production deploy.
- **The revised `002` applies cleanly.** It creates the role using only attributes a CREATEROLE role may set. If the role already exists, it is **verified, not altered**, and the migration aborts if the role can log in, inherits, holds an elevated attribute, or belongs to any role. The grant to `netlifydb_owner` gives SET but not INHERIT.
- **The grant to the runtime user is now required.** If `netlifydb_owner` doesn't exist, the migration aborts instead of silently skipping the grant.

Still unproven: Neon may patch role checks, and the identity of the production migration runner isn't documented. The emulation is evidence, not proof. **P4 and V1–V6 on the promotion PR's preview branch are the real test.**

### Gate 4: restricted role on every auth query

- **Single database entry point.** `server/auth/runtime.ts` is the only `getDatabase()` call in `src/`, `server/` and `netlify/`. It wraps the pool in `roleScopedSqlClient`, so every statement and every transaction starts with `SET LOCAL ROLE hourvia_auth_runtime`. The role name is a constant, not an env var. A test asserts this wiring.
- **No role leakage.** `SET LOCAL` reverts at commit, and the tests check that the pooled connection isn't left as the runtime role.
- **Fail-closed cases (tested):**
  - the role is missing
  - the grant to `netlifydb_owner` is revoked
  - the function connects as `netlifydb_readonly`

  In each case `SET ROLE` or the query raises, and `handleAuthRequest` returns 503 `auth_unavailable` with no detail.

### Gate 5: constraints

These constraints are new in `001`. Each one is consistent with every write path in `store-postgres.ts` and with the bootstrap example.

| Table | Added |
| --- | --- |
| `workspace_members` | `active` requires `activated_at`; `disabled` requires `disabled_at`; a member can't disable themselves (`disabled_by <> id`) |
| `workspace_invitations` | email length 3–320; `accepted_at` is set **if and only if** status is `accepted` |
| `auth_sessions` | `absolute_expires_at > created_at`; `last_seen_at >= created_at`; `revoked_reason` (1–64 characters) only together with `revoked_at` |
| `auth_audit_events` | `event_type` matches `^[a-z_]{1,64}$`; `email_hmac` and `ip_hmac` must be 64-character hex (a raw email or IP is rejected); `details` must be a JSON object of at most 4 KB |
| `auth_rate_limits` | `bucket` must match `name:<64-hex HMAC>` (a raw email or IP is rejected) |

These existing constraints were re-tested:
- workspace pinning
- lower-case emails
- the approval flag only for Managers
- one pending invitation per member
- `expires_at > created_at`
- the token-hash format and uniqueness
- `idle_expires_at <= absolute_expires_at`
- audit IDs are `GENERATED ALWAYS`
- `hits > 0`
- foreign keys

Not enforced by the database (accepted, documented):
- that an assignment's manager and contractor actually hold those roles (the query filters on role)
- that an invitation's email and role match its member (the store writes both from the same row)

## Migration promotion checklist

**Preparation**
- [ ] **P1.** The security and database owners review the revised `001` and `002` and accept risks F1–F6 (in `auth-preflight.md`) and R11–R13 (below).
- [ ] **P2.** Create a branch (not `main`) containing exactly two new files, byte-for-byte copies:
  - `netlify/database/migrations/<YYYYMMDDHHMMSS>_create-auth-foundation.sql` ← `001`
  - `netlify/database/migrations/<later timestamp>_restrict-auth-runtime-role.sql` ← `002`

  Check with `diff`. The `002` name must sort after the `001` name.
- [ ] **P3.** No code or environment changes in the same PR. The auth function refuses every non-production context, so the preview validates only the migrations.

**Preview validation** (on the PR's Deploy Preview database branch only)
- [ ] **P4.** The deploy log shows both migrations applied. A failure here, including any `privilege check failed` or `refusing to continue` message from `002`, **fails the preview and is the expected safety behaviour**. Fix forward with a new file in the same PR. Never edit an applied file.
- [ ] **P5.** Run V1–V7 below with `netlify db connect --query "…"` against **that preview branch**. They are read-only catalog queries, and V6 reads zero rows.

**Production**
- [ ] **P6.** The database owner approves in writing, then the PR is merged. The production deploy applies both migrations before publishing, and a failure blocks publishing. Confirm the deploy is `ready`, then repeat V1–V7 against production (read-only).
- [ ] **P7.** At Gate 3 of the activation plan (environment variables set, production redeployed), send `POST /api/auth/login` for an address **not** in the smoke list:
  - **401** means the role works
  - **503** means the deployed database user can't `SET ROLE`; stop and investigate. **Never** grant the owner's privileges as a workaround.
- [ ] **P8.** Never edit or delete these files after merge.

### Verification queries (V1–V7)

Expected results are taken from the local platform emulation.

- **V1. Applied and in order.** `netlify db status` lists both names under Applied.
- **V2. Tables exist.**
  ```sql
  select count(*) from pg_class where relnamespace='public'::regnamespace and relkind='r' and relname in ('workspace_members','manager_assignments','workspace_invitations','auth_sessions','auth_audit_events','auth_rate_limits')
  ```
  Expect **6**.
- **V3. Runtime role attributes.**
  ```sql
  select rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls from pg_roles where rolname='hourvia_auth_runtime'
  ```
  Expect all **false**.
- **V4. Memberships.**
  ```sql
  select m.rolname, am.admin_option, am.inherit_option, am.set_option, pg_get_userbyid(am.grantor) from pg_auth_members am join pg_roles m on m.oid=am.member where am.roleid='hourvia_auth_runtime'::regrole
  ```
  Expect two `netlifydb_owner` rows: (admin `true`, inherit `false`, set `false`, granted by the platform superuser) and (admin `false`, inherit `false`, set `true`, granted by `netlifydb_owner`). Also:
  ```sql
  select count(*) from pg_auth_members where member='hourvia_auth_runtime'::regrole
  ```
  Expect **0**.
- **V5. Read-only and PUBLIC have no effective access.**
  ```sql
  select t, has_table_privilege('netlifydb_readonly', t, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') ro_t, has_any_column_privilege('netlifydb_readonly', t, 'SELECT,INSERT,UPDATE,REFERENCES') ro_c, has_table_privilege('public', t, 'SELECT') pub from unnest(array['workspace_members','manager_assignments','workspace_invitations','auth_sessions','auth_audit_events','auth_rate_limits']) t
  ```
  Expect every column **false**. Also:
  ```sql
  select has_sequence_privilege('netlifydb_readonly','auth_audit_events_id_seq','SELECT,USAGE,UPDATE')
  ```
  Expect **false**.
- **V6. A real denial.**
  ```sql
  select 1 from auth_sessions limit 0
  ```
  Through the read-only CLI connection, expect `permission denied for table auth_sessions`.
- **V7. Triggers and schema fingerprint.**
  ```sql
  select tgname from pg_trigger where not tgisinternal order by 1
  ```
  Expect `auth_audit_events_no_truncate`, `auth_audit_events_no_update_delete` and `workspace_members_guard`. Also:
  ```sql
  select conrelid::regclass::text t, count(*) from pg_constraint where connamespace='public'::regnamespace group by 1 order by 1
  ```
  Expect `auth_audit_events` 15, `auth_rate_limits` 6, `auth_sessions` 16, `manager_assignments` 10, `workspace_invitations` 17 and `workspace_members` 21 (these counts include NOT NULL constraints, which PostgreSQL 18 stores here).

## Rollback procedures

The migrations are additive and forward-only. "Rollback" means returning to a safe state, never editing applied files.

| Situation | Action | Effect |
| --- | --- | --- |
| A migration fails on the preview | Fix forward with a new file in the same PR, or close the PR | Production untouched; the preview branch is disposable |
| A migration fails during the production deploy | Publishing is blocked automatically, and the previous deploy stays live. Fix forward in a new PR. | No change to the live site. If the runner doesn't wrap files in transactions (V1/R6), inspect with V2–V7 before writing the fix. |
| Migrations applied but a V-check fails in production | Keep auth disabled (no Gate 3 env vars). Fix forward with a new reviewed migration. | Auth stays 503; the tables are empty and owner-only |
| Need to undo entirely before activation | A new reviewed migration that drops the six tables, both functions and `hourvia_auth_runtime` (after `REVOKE hourvia_auth_runtime FROM netlifydb_owner`). Safe only while the tables hold no data. | Returns the schema to its pre-Sprint 1.7 state |
| Bad code deploy after activation | Netlify Deploys → publish the previous production deploy | Instant; older code doesn't use the tables |
| Auth must stop immediately | Unset `HOURVIA_AUTH_ALLOW_PRODUCTION` and redeploy | All auth returns 503 |
| Restricted role broken | Keep auth at 503 and fix forward. Never grant table privileges to the owner path or run auth without `SET ROLE`. | Fail closed |

## Remaining risks

| ID | Risk | Severity | Closure |
| --- | --- | --- | --- |
| R4 | `SET ROLE` is defence in depth: the session user is still `netlifydb_owner`, which can `RESET ROLE` | Medium | Dedicated LOGIN role before general availability |
| R5 | The deployed function's database user isn't verified (fails closed) | Medium | P7 |
| R6 | The production runner's per-file transaction behaviour isn't verified (local tooling uses one transaction per file) | Low | P4/V1; `001` is safe on its own |
| R11 | The default ACL still gives `netlifydb_readonly` SELECT on **every future table** | Medium | Every future migration with sensitive data must revoke likewise. Alternatively, the operator approves a separate migration to `ALTER DEFAULT PRIVILEGES … REVOKE SELECT ON TABLES FROM netlifydb_readonly` (this affects dashboard visibility of all future tables). |
| R12 | Neon may not match vanilla PostgreSQL role checks exactly; the emulation isn't the platform | Medium | P4 preview deploy; the `002` self-check aborts on any mismatch |
| R13 | The dashboard and CLI can no longer see auth tables (row counts, debugging). Platform roles (`netlifydb_owner`, `neon_superuser` members via `pg_read_all_data`, `cloud_admin`) can still read them | Low / accepted | Use owner-side reviewed queries for support |
| R2 | Preview branches copy production data | Medium | Operator decision (unchanged) |

## Operator approvals needed before promotion

1. **Database owner and security owner:** written approval of the revised `001`/`002` (P1), including acceptance of R4, R11, R12 and R13, and of forward-only risks F1–F6.
2. **Approval to open the promotion PR** (P2/P3) whose Deploy Preview **will apply the migrations to that preview's database branch**. This is the first time any Netlify database is touched.
3. **Approval to merge** after P4/P5 pass, knowing the production deploy applies the migrations to the production database (P6).
4. **Decision on R11:** keep the default ACL and revoke per table, or approve a separate default-privileges migration.
5. **Confirmation** of the operator-reported state: Supabase secret rotated, old key revoked, and Supabase variables scoped to Production only. These weren't independently verified in this review, and no environment values were read.
6. Activation (Gate 3+), smoke users, the first-admin bootstrap and any email sending stay **separately** gated, as described in [production-activation-plan.md](production-activation-plan.md).
