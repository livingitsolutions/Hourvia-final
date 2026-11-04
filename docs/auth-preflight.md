> Superseded operational guidance: use [Sprint 2.0B.2 production pre-launch controls](production-prelaunch.md). Earlier activation, general-stage, dev/provider, invitation and preview-promotion steps below are historical and must not be executed as current instructions.

# Hourvia authentication: production preflight (2026-11-03)

This audit was done before approving database migrations or production activation. Nothing was applied, deployed, merged, emailed or created, and production authentication stays disabled.

**Evidence sources:**
- the repository at `60b8943` plus this change
- Netlify environment variable **metadata** (names, secret flag, scopes and contexts; values were never read)
- site build settings
- read-only HTTP requests to production
- read-only catalog queries against this session's isolated Netlify Database **preview branch**, which is a copy of production
- the local test suite

The Supabase and Resend dashboards were **not** accessed.

## Gate summary

| # | Security gate | Result |
| --- | --- | --- |
| 1 | Supabase env var names and scopes; server-only, no secrets in previews | **BLOCKED** (operator rescoping needed; code side PASS) |
| 2 | `/accept-invite` and `/reset-password` routes and redirect/verify flows | **PASS** (code); Supabase URL settings unverified |
| 3 | Staged SQL vs existing production schema | **PASS** (no conflicts); forward-only risks listed |
| 4 | Restricted runtime role instead of `netlifydb_owner` | **PASS locally**; **BLOCKED** until validated on Netlify Database |
| 5 | Deploy previews cannot write to or expose production data | Writes **PASS**; exposure **BLOCKED** (see R2 and R3) |
| 6 | Supabase invitation, recovery, disabled signup and templates | **PASS** (code and mocked tests); live settings **BLOCKED** (unverified) |
| 7 | Launch gate, allowlist, revocation, CSRF and rate limits (local disposable tests) | **PASS**: 82 passed, 0 failed, 5 skipped (live) |
| 8 | Promotion checklist, operator steps and rollback | **PASS** (below) |
| — | **Production smoke testing** | **BLOCKED** until the minimum changes below are done |

## 1. Environment variables

This is the current Netlify metadata. No values were read.

| Name | Secret | Scopes | Contexts | Verdict |
| --- | --- | --- | --- | --- |
| `SUPABASE_SECRET_KEY` | yes | functions | **all** (production, deploy-preview, branch-deploy, dev) | ✗ Must be **Production only**. As it stands, code in any Deploy Preview of this **public** repo can use the production service credential. |
| `VITE_SUPABASE_URL` | no | builds, functions, post_processing, runtime | all | ✗ Not used by any code. The `VITE_` prefix makes it eligible for inlining into browser bundles. Delete it. |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | no | builds, functions, post_processing, runtime | all | ✗ Same as above. Delete it. |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | — | — | — | ✗ Missing. Create them as Production only, functions scope only. |
| `HOURVIA_*` (hash key, origin, stage, smoke list, email flag, production flag) | — | — | — | Missing. This is intended: auth stays fail-closed until Gate 3. |

**Code evidence:**
- `server/auth/config.ts` reads only `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_ANON_KEY` and `SUPABASE_SECRET_KEY` / `SUPABASE_SERVICE_ROLE_KEY`. It never reads a `VITE_` name.
- `src/` contains no `import.meta.env` or `VITE_` references.
- The live production bundle (`/assets/index-BsSSQ4J3.js`, 379 KB) has 0 matches for `supabase`, `sb_publishable`, `sb_secret`, `service_role`, `SUPABASE`, `VITE_`, `resend` and `eyJhbGci`.

**New in this change:** `readServerEnv` returns `context_not_enabled` for every context except `production` and `dev`. This covers deploy previews, branch deploys, unknown contexts and a missing context (test: `config.test.ts`, "never runs in deploy previews…"). So even if a secret is mis-scoped, a preview's copy of the auth function never contacts Supabase or the database. This is defence in depth only. It doesn't stop *other* code in a preview from reading a mis-scoped secret, so the rescoping in R1 is still required.

## 2. Routes and Supabase flows

**Routes** (`src/presentation/App.tsx`): `/accept-invite` → `AcceptInvitation` and `/reset-password` → `ResetPasswordLink`. Both return 200 on production. Each page reads `token_hash` from the URL **fragment**, then immediately replaces the URL without it (`AccountPages.tsx` lines 17–18).

**Redirect values the server sends** (`service.ts`): `redirectTo = HOURVIA_APP_ORIGIN + '/accept-invite'` for invitations and `HOURVIA_APP_ORIGIN + '/reset-password'` for recovery.

**Template links** (`docs/auth-email-templates/`): `{{ .SiteURL }}/accept-invite#token_hash={{ .TokenHash }}` and `{{ .SiteURL }}/reset-password#token_hash={{ .TokenHash }}`, plus `{{ .Token }}` (the 6-digit code) in the recovery email.

The links deliberately **do not** go through Supabase's `/auth/v1/verify` redirect endpoint, so `{{ .ConfirmationURL }}` and `{{ .RedirectTo }}` are unused. Supabase therefore never puts tokens into a redirect, and the token is spent only by a server-side POST. The link origin is the Supabase **Site URL**, so Site URL must equal `HOURVIA_APP_ORIGIN` exactly. The Redirect URL allow-list is still required, because Supabase validates `redirectTo` and would otherwise fall back to the Site URL.

**Invitation flow:**
1. An Admin calls `POST /api/admin/invitations`.
2. The server calls `auth.admin.inviteUserByEmail(email, { redirectTo })` with the secret key and no metadata.
3. Supabase sends the Invite template through Resend SMTP.
4. The invitee opens `/accept-invite#token_hash=…` and submits a password.
5. The page calls `POST /api/auth/invitations/accept {tokenHash, password}`.
6. The server calls `auth.verifyOtp({ token_hash, type: 'invite' })` with the publishable key and gets a user ID and a Supabase session.
7. The server checks for a pending, unexpired Hourvia invitation bound to that same user ID.
8. The server calls `auth.admin.updateUserById(id, { password })`.
9. The member is set to `active` and the server calls `auth.admin.signOut(jwt, 'global')`. The invitee then signs in normally.

**Recovery flow:**
1. The user calls `POST /api/auth/recovery/request {email}`. This is rate-limited, always returns a generic 202 padded to at least 750 ms, and only active (and, during smoke, allowlisted) members trigger an email.
2. For those members, the server calls `auth.resetPasswordForEmail(email, { redirectTo })` and Supabase sends the Recovery template.
3. The user calls `POST /api/auth/recovery/complete` with either `{email, code, password}` or `{tokenHash, password}`.
4. The server calls `verifyOtp({ email, token, type: 'recovery' })` or `verifyOtp({ token_hash, type: 'recovery' })`.
5. Membership is checked, then `updateUserById(password)` runs, then all Hourvia sessions for the member are revoked, then `signOut(jwt, 'global')` runs.

## 3. Staged SQL vs production

Read-only catalog queries on this session's preview branch (a copy of production; PostgreSQL 18.6):
- `information_schema.tables` (excluding the system schemas) returns **0 tables**.
- `netlify db status` reports **0 applied migrations** and 0 pending, and `netlify/database/migrations/` doesn't exist in the repo.
- Extensions: `plpgsql` only.

| Check | Result |
| --- | --- |
| Duplicate tables or functions (`workspace_members`, `manager_assignments`, `workspace_invitations`, `auth_sessions`, `auth_audit_events`, `auth_rate_limits`, `hourvia_reject_audit_mutation`, `hourvia_guard_member_update`) | none exist |
| Missing dependencies | none. `gen_random_uuid()` is built into PostgreSQL 13 and later (production runs 18.6), so `pgcrypto` isn't needed. `GRANT … WITH INHERIT FALSE, SET TRUE` needs PostgreSQL 16 or later, which production meets. |
| Applied locally | both files run verbatim in PGlite 0.5.14 (PostgreSQL 18.6) at the start of every test |

**Forward-only risks.** Once merged, the migrations can't be edited, so review these before Gate 2:
- **F1 — single workspace.** `CHECK (workspace_id = 'thrivesource')` is hard-coded on every table. Supporting a second workspace needs a constraint-dropping migration. This is accepted, because the product is scoped to ThriveSource.
- **F2 — generic table names.** `workspace_members` and `manager_assignments` are generic names that the Sprint 2 domain schema will build on. Confirm these names and columns are the long-term ones, because renaming later is a migration plus a code change.
- **F3 — permanent audit trail.** Audit rows can never be deleted: triggers block DELETE and TRUNCATE for every role. Retention or erasure (for example GDPR) will need a reviewed migration that adds a controlled purge path. Audit rows hold only HMACs plus member UUIDs.
- **F4 — no deletes.** No table uses `ON DELETE`, and the runtime role has no DELETE privilege. Members can only be disabled, never removed. Pruning expired `auth_sessions` and `auth_rate_limits` rows will need a later migration that grants DELETE to a separate scheduled-job role.
- **F5 — partial failure.** Whether Netlify's migration runner wraps each file in a transaction isn't documented here. If it doesn't, a failure partway through could leave a partially applied schema. Confirm this on the promotion PR's preview branch. If a file fails, fix forward with a new file; never edit it.
- **F6 — preview role leftovers.** `002` creates a database role. On Netlify Database, roles live on each branch, and preview branches start as copies of production. A preview branch created *before* production applies `002` creates its own copy of the role, which is harmless. `002` uses `IF NOT EXISTS` and also enforces the role's attributes, so it doesn't fail if the role already exists.

## 4. Restricted role (replacement for the missing Sprint 1.6 proposal)

**Can auth run safely with the current `netlifydb_owner` privileges? No.**

From `pg_roles` and `pg_auth_members`, `netlifydb_owner` has:
- `rolcreaterole=true`
- `rolcreatedb=true`
- `rolbypassrls=true`
- membership of `neon_superuser`

It also owns every table it creates. With those privileges, any SQL bug can:
- read and change every table
- `DISABLE TRIGGER` or drop the append-only audit triggers
- delete audit rows after disabling the triggers
- create roles

RLS gives no protection: there are no policies, and this role bypasses RLS anyway. **RLS was not relied on anywhere.** Tenant isolation comes from the `CHECK (workspace_id = 'thrivesource')` constraints plus `workspace_id = $1` in every query in `store-postgres.ts`.

**What changed:**
- **Staged role:** `db/proposals/sprint-1.7-auth/002_restricted_auth_runtime_role.sql` creates `hourvia_auth_runtime` as `NOLOGIN NOINHERIT NOBYPASSRLS NOCREATEROLE NOCREATEDB`. Its grants are exactly what the store's SQL needs, at column level:
  - audit: INSERT only (no SELECT)
  - members: no UPDATE on `approval_authorized`, `auth_user_id`, `email` or `workspace_id`
  - nothing has DELETE, TRUNCATE or DDL
- **Grant to the runtime user:** it grants the role to `netlifydb_owner` `WITH INHERIT FALSE, SET TRUE`.
- **Member guard trigger** (applies to every role, the owner included):
  - workspace, email and the bound Supabase user ID can't change
  - role can change only while the member is `invited`
  - `disabled` is terminal
- **Code:** `server/auth/sql-role.ts` with `runtime.ts` runs **every** auth statement as `BEGIN; SET LOCAL ROLE hourvia_auth_runtime; …; COMMIT`. The role name is a constant, not an env var. If the role is missing or not granted, auth returns 503.

**Tests** (real PostgreSQL 18 privilege checks):
- The whole mocked suite now runs under the restricted role.
- `current_user` is `hourvia_auth_runtime` with `rolbypassrls=false`.
- Without `002`, login returns 503.
- The runtime is denied: SELECT, UPDATE, DELETE and TRUNCATE on audit; `DISABLE TRIGGER`; UPDATE of `approval_authorized` and `auth_user_id`; role escalation on an active member; writes to assignments; DELETE on sessions and members; `CREATE TABLE`; `DROP TABLE`; `CREATE ROLE`.
- Re-enabling a disabled member is blocked even for the owner.

**Limits, stated precisely:**
- The connection still authenticates as `netlifydb_owner`, so SQL that can run arbitrary statements could `RESET ROLE`. That makes this **defence in depth**, not a hard boundary. All Hourvia SQL is parameterized, single-statement and fixed-text: the only interpolations are compile-time constants (`MEMBER_COLUMNS` and the internal `where` fragments in `store-postgres.ts`).
- A **hard boundary** would need a dedicated LOGIN role whose credential is stored as a Production-only Netlify secret, with the function connecting with that credential instead of the platform URL. That isn't required for a smoke test limited to test accounts, but it is **recommended before general availability**. Whether Netlify Database supports SQL-created LOGIN roles with passwords needs confirming with Netlify.
- **Unverified:** which database user deployed functions actually connect as. This agent session's runtime URL uses `netlifydb_readonly`, while the operator reports `netlifydb_owner`. If the deployed user isn't `netlifydb_owner`, the grant in `002` won't cover it and auth stays 503 (fail closed). Checklist item P7 catches this.
- `netlifydb_readonly` (used by the CLI and dashboard) can probably SELECT the auth tables, which include member emails and session token **hashes**. The hashes can't be turned back into the 256-bit tokens. Treat read-only credentials as sensitive.

## 5. Deploy previews and production data

- **Writes:** Netlify Database gives every Deploy Preview an **isolated branch** of the database, and production deploys use only the main branch, so preview code can't write to production. On top of that, the auth function now refuses every non-production context.
- **Exposure (R2):** a preview branch is a **copy of production data**. Any code that runs in a Deploy Preview can read that copy, whether through a new function or a changed one. Who can get code into a preview:
  - repo collaborators
  - fork PRs, but only after manual approval (`untrusted_flow: review` ✓)
- **Exposure (R3):** previews are public (no site password or SSO). Branch deploys are limited to `main` ✓.
- **Exposure (R1):** while `SUPABASE_SECRET_KEY` is in all contexts, preview code can also read and change **real Supabase users**: ban them, change passwords, send invites. This is the most serious open issue.

## 6. Supabase behaviour and template compatibility

| Behaviour | Expectation | Evidence or status |
| --- | --- | --- |
| Signup disabled | `disable_signup=true` blocks `/signup`, but admin invites still work. Hourvia has no signup route (`/api/auth/signup` returns 404 in production). | Live check in `supabase.live.test.ts`, not run |
| Confirm email on, other providers off | asserted by the live test (`mailer_autoconfirm` not true; only `email` in `external`) | not run |
| Invite of an unconfirmed user | Supabase resends; a confirmed user gets 422 `email_exists`, which Hourvia maps to 409 `identity_exists` | mocked |
| Invite token lifetime (**mismatch M11**) | Supabase's invite token expires after the **Email OTP expiry (3600 s)**, but Hourvia records a **7-day** invitation | Effective validity is 1 hour. An admin resends by inviting the same email again (still `invited`). Either accept this and say "1 hour" in the email, or set Hourvia's TTL to match. Raising the OTP expiry also lengthens recovery codes, which weakens the 6-digit code. |
| Recovery code | `{{ .Token }}` length follows the OTP length setting; Hourvia requires exactly `^\d{6}$` | Setting must be 6 (M8) |
| Per-user email cooldown (~60 s) and email rate limit | Supabase returns 429. Hourvia's recovery still returns the generic 202 (audited `provider_error`); invites return 502. | mocked |
| Banned user | `ban_duration` set on disable blocks sign-in and OTP use at Supabase. Hourvia also checks `status`. | mocked |
| Password policy | Hourvia requires 12–72 characters (72 is bcrypt's limit). The Supabase minimum must be at most 12, ideally exactly 12. | config |
| CAPTCHA | must stay **off**. Server-side `signInWithPassword` sends no captcha token, so turning it on breaks login (it fails closed as 401). | operator |
| Magic link / Confirm signup / Change email templates | anyone with the public key can call Supabase `/otp` for an existing email | make them inert (M9) |
| New-style keys | `sb_secret_…` works for the admin API server-side; swapped key types fail closed | `config.test.ts` |

## 7. Local disposable test evidence

`npx vitest run`: **82 passed, 0 failed, 5 skipped** (the live Supabase tests, which need authorization). `npx tsc --noEmit` is clean. Everything runs in-process against PGlite (a disposable embedded PostgreSQL 18.6 running both staged SQL files verbatim) and `FakeSupabase`. No network, email or Netlify Database is involved.

| Control | Tests (file: `describe`) |
| --- | --- |
| Launch-stage gate | `config.test.ts`: production disabled without the flag, missing or invalid stage, `smoke` without a valid list, missing origin, non-production contexts |
| Smoke allowlist | `auth.mocked.test.ts`: "production smoke-test stage": non-listed users denied before Supabase is contacted; no invite, email, disable or revoke for non-listed users; a session ends when its account is removed from the list |
| Session revocation | logout, admin "End sessions", disable, password reset, idle (30 min) and absolute (12 h) expiry |
| CSRF | foreign `Origin`, `Sec-Fetch-Site: cross-site`, non-JSON content type all return 403; `SameSite=Strict` `__Host-` cookie; **new:** non-canonical host returns 421 with no cookie |
| Rate limits | login 10 per email and 20 per IP per 15 min; recovery request 3 per email and 10 per IP per hour; code verification 5 per email per hour; invite acceptance 10 per IP per hour; admin invites 30 per hour |
| RBAC and tenancy | Manager and Contractor get 403 on admin routes; client-sent role or workspace rejected; principals built from the database only |
| Restricted role | "restricted database role" (section 4) |
| Fail-closed | unconfigured, missing tables, missing role, provider outage all return 503 with no detail |

## 8. Minimum changes required before production smoke testing

**Code (done in this change; review it):**
1. Context gate: auth refuses everything except `production` and `dev`.
2. Restricted runtime role: `002` is staged, and all queries run under `SET LOCAL ROLE`.
3. Canonical-origin pinning: auth answers only on `HOURVIA_APP_ORIGIN`, which closes M6 for auth.

**Operator** (each needs the named approval):
1. Rescope `SUPABASE_SECRET_KEY` to **Production only**. Create `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (Production, functions only). Delete `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY`. Because the secret key was available to previews of a public repo, **rotate it** in Supabase before smoke testing, and look for unexpected admin activity in the Supabase auth logs.
2. In Supabase, set and confirm:
   - Site URL `https://hourvia.livingitsolutions.com`
   - Redirect URLs `…/accept-invite` and `…/reset-password` only
   - signup disabled, Confirm email on, other providers and anonymous sign-ins off, CAPTCHA off
   - OTP length 6, expiry 3600 s; password minimum 12
   - Invite and Recovery templates installed; Magic link, Confirm signup and Change email templates inert
   - Resend SMTP with a verified domain and a sending-only key
3. Decide on M11 (invite lifetime of 1 hour vs 7 days).
4. Approve and complete migration promotion (checklist below). That includes confirming the deployed function's database user and the role grant (P7).
5. Decide on R2 (production data copied into previews): keep fork-PR approval on, limit collaborators, and decide whether public previews are acceptable once real member data exists.

## Migration promotion checklist (Gate 2)

> **Superseded (Sprint 1.7 readiness, 2026-11-03):** use [migration-promotion-checklist.md](migration-promotion-checklist.md). The revised `002` fixes a failure under the non-superuser `netlifydb_owner` and removes `netlifydb_readonly` access to all auth tables. The P5 membership query below now returns two rows.

- [ ] **P1.** Security and database owners have reviewed `001` and `002` and accepted risks F1–F6.
- [ ] **P2.** Create a branch (not `main`) with exactly two new files and nothing else:
  - `netlify/database/migrations/<YYYYMMDDHHMMSS>_create-auth-foundation.sql`, a byte-for-byte copy of `001`
  - `<later timestamp>_restrict-auth-runtime-role.sql`, a byte-for-byte copy of `002`

  Verify with `diff`.
- [ ] **P3.** No code changes in the same PR. With the context gate, the preview's auth function stays 503, so the preview only validates the migration.
- [ ] **P4.** Open the PR. On its Deploy Preview, confirm the deploy log shows both migrations applied with no error. A failure fails the preview; if so, fix forward with a new file.
- [ ] **P5.** On the **preview** branch (Netlify dashboard, Database, or `netlify db connect` with that branch), run read-only checks:
  - all six tables exist
  - `select tgname from pg_trigger where not tgisinternal` returns the 3 triggers
  - `select rolname, rolbypassrls, rolcanlogin from pg_roles where rolname='hourvia_auth_runtime'` returns `false`, `false`
  - `select r.rolname, m.set_option, m.inherit_option from pg_auth_members m join pg_roles r on r.oid=m.member where m.roleid='hourvia_auth_runtime'::regrole` returns `netlifydb_owner`, `true`, `false`
  - `select table_name, privilege_type from information_schema.role_table_grants where grantee='hourvia_auth_runtime'` returns SELECT only, with no DELETE or TRUNCATE (column-level grants are in `role_column_grants`)
- [ ] **P6.** The DB owner approves in writing, then the PR is merged. The production deploy applies both migrations before publishing. Confirm the deploy is `ready`, then repeat the P5 queries against production (read-only).
- [ ] **P7.** At Gate 3, after the env vars are set and the site redeployed, send `POST /api/auth/login` for an address that is **not** in the smoke list:
  - **401** means the configuration and the restricted role work, and Supabase wasn't contacted
  - **503** means the role isn't usable by the deployed database user; stop and investigate
- [ ] **P8.** Never edit or delete these migration files after merge. Every correction goes in a new migration.

## Operator configuration steps (in order)

1. **Netlify, Project configuration → Environment variables (Gate 0):**
   - Edit `SUPABASE_SECRET_KEY`: scopes Functions only; value set for **Production** only; remove the values for other contexts.
   - Add `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`, Production only, functions scope.
   - Delete both `VITE_SUPABASE_*` variables.
   - Rotate the Supabase secret key and update the Netlify value.
2. **Supabase:** apply operator item 2 above. Run `HOURVIA_LIVE_SUPABASE_TESTS=production-smoke npx vitest run server/auth/supabase.live.test.ts` from a trusted shell **only after authorization**. This run is read-only and sends no email.
3. **Gate 2:** run the migration checklist.
4. **Gate 3:** in Netlify, Production context only, set:
   - `HOURVIA_AUTH_HASH_KEY` (secret, 48+ random characters)
   - `HOURVIA_APP_ORIGIN=https://hourvia.livingitsolutions.com`
   - `HOURVIA_AUTH_SMOKE_TEST_EMAILS` (secret)
   - `HOURVIA_AUTH_LAUNCH_STAGE=smoke`
   - `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false`
   - `HOURVIA_AUTH_ALLOW_PRODUCTION=true`

   Then redeploy the production commit and run P7.
5. **Gates 4–6:** follow [production-activation-plan.md](production-activation-plan.md).

## Rollback procedure

| Situation | Action | Effect |
| --- | --- | --- |
| Any smoke-test abort criterion | Unset `HOURVIA_AUTH_ALLOW_PRODUCTION` (or `HOURVIA_AUTH_LAUNCH_STAGE`) and redeploy | All auth returns 503; no email |
| Email problem only | `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false` and redeploy | Login keeps working; invites and recovery stop |
| Bad code deploy | Netlify Deploys → publish the previous production deploy | Instant. The tables stay in place; they're additive, and older code doesn't use them. |
| Bad migration (preview) | Fix forward with a new file in the same PR | Production is untouched |
| Bad migration (production publish) | The deploy is blocked automatically, so the previous deploy stays live. Fix forward. | — |
| Live sessions must end | A reviewed one-off statement as owner: `UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'incident' WHERE revoked_at IS NULL` | Everyone is signed out on their next request |
| Restricted role suspected broken | Don't grant the owner as a workaround. Keep auth at 503 and fix forward with a migration. | Fail closed |
| Credential exposure | Rotate the Supabase secret key (and the Resend key in Supabase SMTP; and `HOURVIA_AUTH_HASH_KEY` if exposed, which resets rate-limit buckets). Update Netlify and redeploy. | — |

## Unresolved risks

| ID | Risk | Severity | Owner / closure |
| --- | --- | --- | --- |
| R1 | `SUPABASE_SECRET_KEY` is readable by Deploy Preview code of a public repo | **High** | Operator: rescope and rotate (Gate 0) |
| R2 | Preview database branches are copies of production data, readable by any preview code | Medium (High once real members exist) | Operator decision; keep fork approval on |
| R3 | Previews are publicly reachable | Low (auth refuses previews) | Optional: protect previews with a password |
| R4 | Restricted role is a `SET ROLE` layer, not a separate login | Medium | Accept for smoke; plan a dedicated LOGIN role before general availability |
| R5 | Deployed function's database user unverified | Medium (fails closed) | P7 |
| R6 | Migration runner transaction semantics unverified | Low | P4 and P5 |
| R7 | Invite link valid 1 hour vs Hourvia's 7-day record (M11) | Low (usability) | Product decision |
| R8 | A user with a valid Supabase recovery token could reset directly through Supabase's API, and Hourvia sessions wouldn't be revoked (they still expire within 12 hours) | Low | Later: Supabase auth hook |
| R9 | No pruning of `auth_sessions` and `auth_rate_limits` yet | Low | Later migration with a separate job role |
| R10 | Supabase and Resend settings are not verified by anyone yet | **High** | Operator (step 2) |
