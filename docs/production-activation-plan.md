> Superseded operational guidance: use [Sprint 2.0B.2 production pre-launch controls](production-prelaunch.md). Earlier activation, general-stage, dev/provider, invitation and preview-promotion steps below are historical and must not be executed as current instructions.

# Hourvia authentication: production activation plan

**Decision (2026-11-03):** the Supabase project **Hourvia_Authentication** is the production authentication provider. No separate nonproduction Supabase project will be created. Correctness and security are proven locally against disposable databases and mocked providers. Production then gets a limited, explicitly authorized smoke test that uses designated test accounts only.

Supabase Auth, Resend (as Supabase's custom SMTP), Netlify Functions and Netlify Database stay as designed in [authentication.md](authentication.md). Public signup stays disabled and onboarding remains admin-invitation only.

Nothing in this plan is done without the approval named in its gate. That covers deploying, merging, applying migrations, sending email and creating production accounts.

## Current state (verified 2026-11-03)

| Item | State |
| --- | --- |
| Production deploy | `main` @ `83830e3` is published and includes the `auth-api` function. |
| Production auth | **Disabled (fail-closed).** `GET /api/auth/session` returns 503 on both `hourvia.livingitsolutions.com` and `hourvia-tracker.netlify.app`, and `/api/auth/signup` returns 404. |
| Auth schema | Staged at `db/proposals/sprint-1.7-auth/`, outside `netlify/database/migrations/`. It has not been applied anywhere. |
| Netlify env vars present | `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY` (both non-secret, all contexts, build scope included) and `SUPABASE_SECRET_KEY` (secret, functions scope, **all contexts**). |
| Supabase / Resend dashboards | **Not inspected.** This plan never uses production credentials. Every Supabase/Resend setting below must be confirmed by an operator. |

## Configuration mismatches

| # | Mismatch | Effect | Resolution |
| --- | --- | --- | --- |
| M1 | `SUPABASE_SECRET_KEY` is available in **all** deploy contexts, including Deploy Previews and branch deploys of a **public** repository. | A preview build could reach a production service credential. | Re-scope it to the **Production** context only (keep it secret, functions scope). |
| M2 | The server needs `SUPABASE_URL` and a server-side publishable key. Only `VITE_`-prefixed versions exist. | The function reports `not_configured` (fail-closed). `VITE_` variables can be inlined into the browser bundle, and the design never lets the browser talk to Supabase. | Create `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (Production, functions scope). Then delete `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY`; no code references them. The server deliberately never reads `VITE_` names. |
| M3 | The code expected the legacy names `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY`. | The existing `SUPABASE_SECRET_KEY` would have been ignored. | **Fixed in code.** `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_SECRET_KEY` are read first and the legacy names are kept as fallback. Swapped key types (`sb_secret_…` as publishable or `sb_publishable_…` as secret) fail closed. |
| M4 | `HOURVIA_AUTH_HASH_KEY`, `HOURVIA_APP_ORIGIN`, `HOURVIA_AUTH_LAUNCH_STAGE`, `HOURVIA_AUTH_SMOKE_TEST_EMAILS`, `HOURVIA_EMAIL_DELIVERY_AUTHORIZED` and `HOURVIA_AUTH_ALLOW_PRODUCTION` are not set. | Auth stays disabled. This is the intended state until Gate 3. | Set them at Gate 3 (see the table in "Netlify environment"). |
| M5 | The email templates build links from `{{ .SiteURL }}`, but the server passes `redirectTo = HOURVIA_APP_ORIGIN + /accept-invite` or `/reset-password`. | If the Supabase **Site URL** differs from `HOURVIA_APP_ORIGIN`, invitation and recovery links open the wrong origin, where the `__Host-` cookie and same-origin checks don't apply. | Set the Supabase Site URL to **exactly** `https://hourvia.livingitsolutions.com` (no trailing slash) and set `HOURVIA_APP_ORIGIN` to the same value. The templates keep using `{{ .SiteURL }}` on purpose so links are pinned to the production origin. |
| M6 | The site answers on two origins: the custom domain and `hourvia-tracker.netlify.app` (plus `main--…`). | A session on one origin is invisible on the other, which confuses users. It is not a security hole, because the cookie and Origin checks are per-origin. | Treat the custom domain as canonical and test there only. Optionally add a domain-level redirect from the `netlify.app` hostnames. |
| M7 | Supabase **Redirect URLs** must contain the actual routes. | If they don't, Supabase falls back to the Site URL root. | Allow-list exactly `https://hourvia.livingitsolutions.com/accept-invite` and `https://hourvia.livingitsolutions.com/reset-password`. Remove `localhost`, wildcard and preview entries. |
| M8 | Recovery codes are validated as exactly 6 digits (`^\d{6}$`). | If the project's Email OTP length isn't 6, recovery-by-code always fails. | Set Email OTP length to 6 and expiry to 3600 s. |
| M9 | The default Supabase templates for **Magic link**, **Confirm signup** and **Change email** link to `{{ .ConfirmationURL }}`. Anyone holding the public publishable key can call Supabase directly (`/otp`, `/recover`) for an existing email. | A user can receive a magic link that drops a Supabase token into the Hourvia origin's URL fragment. Hourvia ignores it (cookie-only), but it's unwanted email and token exposure. | Replace those three templates with inert text that contains no link or token, for example "Hourvia does not use this sign-in method. Contact your workspace admin.". Keep Supabase's email rate limit low. |
| M10 | Bootstrap instructions referred to a nonproduction project. | — | **Updated.** The first admin for the smoke test is a designated test admin (see Gate 4). |

## Code changes made for this decision

- **Production launch-stage gate** (`server/auth/config.ts`). In production, auth now needs all of the following, otherwise it returns 503:
  - `HOURVIA_AUTH_ALLOW_PRODUCTION=true`
  - a valid `HOURVIA_APP_ORIGIN`
  - `HOURVIA_AUTH_LAUNCH_STAGE` set to `smoke` or `general`
- **Smoke-test allowlist** (`server/auth/service.ts`). With `HOURVIA_AUTH_LAUNCH_STAGE=smoke`, only the emails in `HOURVIA_AUTH_SMOKE_TEST_EMAILS` (1–20; any malformed entry fails closed) can:
  - sign in
  - be invited
  - receive or complete recovery
  - accept an invitation
  - keep a session
  - be disabled or have sessions ended

  Anyone else gets the same generic responses, and sign-in is refused **before Supabase is contacted**. Real users' Supabase records (sessions, last sign-in, bans, passwords) are therefore never touched during the smoke window.
- **Supabase key names.** The code reads the key names that already exist in Netlify (M3).
- **Live provider tests** (`server/auth/supabase.live.test.ts`). These accept `HOURVIA_LIVE_SUPABASE_TESTS=production-smoke`. They assert:
  - signup is disabled
  - email confirmation is on
  - every non-email provider is off

  The optional sign-in check runs only for an email in the smoke list. They still never send email or change users.

## Netlify environment

All variables are **Production context only**, **functions scope only**, and marked **secret** where noted. Never use a `VITE_` prefix and never print values in build logs.

| Variable | Secret | Value / rule | Set at |
| --- | --- | --- | --- |
| `SUPABASE_URL` | no | `https://<ref>.supabase.co` of Hourvia_Authentication | Gate 3 |
| `SUPABASE_PUBLISHABLE_KEY` | no (server-only by policy) | the project's `sb_publishable_…` key (or legacy anon key) | Gate 3 |
| `SUPABASE_SECRET_KEY` | **yes** | already exists; re-scope to Production only (M1) | Gate 0 |
| `HOURVIA_AUTH_HASH_KEY` | **yes** | 48+ random characters, generated once and never reused | Gate 3 |
| `HOURVIA_APP_ORIGIN` | no | `https://hourvia.livingitsolutions.com` | Gate 3 |
| `HOURVIA_AUTH_LAUNCH_STAGE` | no | `smoke` during the smoke window; `general` only at Gate 6 | Gate 3 / 6 |
| `HOURVIA_AUTH_SMOKE_TEST_EMAILS` | **yes** | comma-separated designated test mailboxes | Gate 3 |
| `HOURVIA_EMAIL_DELIVERY_AUTHORIZED` | no | `false` until Gate 5, then `true` | Gate 5 |
| `HOURVIA_AUTH_ALLOW_PRODUCTION` | no | unset until Gate 3; this is the kill switch | Gate 3 |

The Resend API key lives **only** in Supabase's SMTP settings. Netlify never needs it.

## Supabase (Hourvia_Authentication) settings to confirm

1. **Sign In / Providers:**
   - Allow new users to sign up: **off**
   - Email: on
   - Confirm email: **on**
   - Anonymous sign-ins and every OAuth and phone provider: **off**
2. **Email OTP:** length **6**, expiry **3600 s**. **Password:** minimum length 12, plus leaked-password protection if the plan allows it.
3. **URL Configuration:** Site URL and Redirect URLs as in M5 and M7.
4. **Email templates:**
   - **Invite user:** `docs/auth-email-templates/invite.html`
   - **Reset password:** `docs/auth-email-templates/recovery.html`
   - **Magic link, Confirm signup, Change email:** inert text (M9)
5. **SMTP:**
   - host `smtp.resend.com`, port 465, user `resend`
   - password: a Resend **sending-only** key restricted to the verified domain
   - sender `no-reply@<verified domain>`, name `Hourvia`
   - the Resend domain must have SPF, DKIM and DMARC passing
6. **Rate limits:**
   - Keep the email-sending limit low (for example 30/h).
   - Raise the per-IP sign-in and verify limits enough that Netlify's shared egress IPs aren't throttled. Hourvia's per-email and per-IP limits are the primary control.
7. **Keys:** confirm which key types are enabled (new `sb_…` keys or legacy JWT keys) and that the secret key is only stored in Netlify's secret variable.
8. **Users:** inventory existing users without changing them. Hourvia only ever modifies Supabase users it invited and bound to a workspace member.

## Database plan

- **Staging.** The SQL stays in `db/proposals/sprint-1.7-auth/` until approved at Gate 2. Netlify only auto-applies files in `netlify/database/migrations/`.
- **Promotion (Gate 2).** In a dedicated PR, copy **both** `001_create_auth_foundation.sql` and `002_restricted_auth_runtime_role.sql`, unchanged, to `netlify/database/migrations/` as two consecutive files (for example `<ts>_create-auth-foundation.sql` and `<ts+1>_restrict-auth-runtime-role.sql`). Follow the full checklist in [auth-preflight.md](auth-preflight.md).
  - The PR's Deploy Preview applies it to an isolated **preview branch** of the database (a copy of production data), which validates the migration without touching production.
  - Merging applies it to production before that deploy publishes. A failed migration blocks publishing.
- **Restricted runtime role.** The missing Sprint 1.6 proposal is replaced, for the auth tables, by `002_restricted_auth_runtime_role.sql`. Every auth statement runs under `SET LOCAL ROLE hourvia_auth_runtime`, and auth returns 503 until that role exists and is granted. See [auth-preflight.md](auth-preflight.md) for what this role does and doesn't protect against.
- **Bootstrap.** `bootstrap-first-admin.sql.example` is run once, by hand and reviewed, against production for the designated **test** admin (Gate 4). It is never a migration.

## Test strategy

| Layer | Where | Provider | Email | Status |
| --- | --- | --- | --- | --- |
| Unit and config (`config.test.ts`) | local | none | none | **pass** |
| Integration and destructive security (`auth.mocked.test.ts`) | local disposable PGlite running the staged SQL | `FakeSupabase` | none | **pass** |
| Supabase adapter (`provider-supabase.mocked.test.ts`) | local | real supabase-js, fake `fetch` | none | **pass** |
| Browser, UI and secret-boundary scan | local jsdom | mocked | none | **pass** |
| Live read-only provider checks (`supabase.live.test.ts`, `production-smoke`) | trusted operator shell | Hourvia_Authentication | none | **skipped** until Gate 3 |
| Production smoke test (below) | production | Hourvia_Authentication + Resend | **yes**, to test mailboxes only | **not started** until Gate 5 |

The mocked suites cover:
- invitation-only access
- login and logout
- idle and absolute expiry
- recovery by code and by link
- disabled members
- RBAC for Admin, Manager and Contractor
- ThriveSource tenant isolation and rejection of client-supplied workspace IDs and roles
- forged, duplicated and bearer credentials
- cross-user session binding
- CSRF and Origin checks
- per-email and per-IP rate limits
- append-only audit with HMAC'd PII
- fail-closed 503 for missing configuration, missing tables and provider outages
- the smoke allowlist

Destructive tests (dropping tables, forging rows, outages) run only against disposable local databases.

## Production smoke test (Gate 5, explicit authorization required)

**Designated test accounts.** Dedicated mailboxes the team controls, for example `hourvia-smoke-admin@`, `hourvia-smoke-manager@` and `hourvia-smoke-contractor@` on livingitsolutions.com. They are listed in `HOURVIA_AUTH_SMOKE_TEST_EMAILS`. No real person's email is used and no existing Supabase user is modified.

Run everything on `https://hourvia.livingitsolutions.com`. Record the time, the result and the matching `auth_audit_events` row (event and outcome only) for each step.

1. **Read-only checks:**
   - `GET /api/auth/session` returns 401.
   - `POST /api/auth/signup` returns 404.
   - The live provider tests pass (`production-smoke` mode).
2. **Invitation delivery.** The test admin invites the test manager and the test contractor.
   - Each email arrives from the Resend domain with SPF, DKIM and DMARC passing.
   - The link points to `https://hourvia.livingitsolutions.com/accept-invite#token_hash=…`.
3. **Allowlist enforcement.** Inviting a non-listed address returns 403 and sends no email.
4. **Account activation.**
   - Each invitee sets a 12+ character password and the member becomes `active`.
   - Reusing the same link fails with the generic message.
5. **Login and logout.**
   - Login sets the `__Host-hourvia_session` cookie with HttpOnly, Secure and SameSite=Strict.
   - Logout clears the cookie, and reusing the old cookie returns 401.
6. **Role enforcement.**
   - Manager and Contractor get 403 on `/api/admin/*`.
   - Admin gets 200.
   - A forged role or workspace field in a request body returns 400 and has no effect.
7. **Six-digit password recovery.** For the contractor:
   - The email shows the code and the link.
   - A wrong code is rejected, and the 6th attempt within an hour returns 429.
   - The correct code resets the password and ends the contractor's other open sessions.
   - The old password fails and the new one works.
8. **Session revocation.**
   - Admin "End sessions" for the manager returns 401 on the manager's next request.
   - Admin "Disable" for the contractor returns 401 immediately, login is denied, and the Supabase user is banned.
9. **Rate limits.**
   - The 11th failed login for one test email within 15 minutes returns 429.
   - The 4th recovery request per hour returns 429, and the generic 202 body is identical for listed and non-listed emails.
10. **Fail-closed check.** Remove `HOURVIA_AUTH_LAUNCH_STAGE` and redeploy. Every `/api/auth/*` call returns 503. Restore it and redeploy.

**Abort criteria:** any of the following stops the smoke test and triggers rollback:
- an email sent to a non-test address
- a token or secret visible in a browser, URL, log or response
- a cross-role or cross-tenant success
- a non-generic recovery or login response
- missing audit rows

## Gates and exact deployment steps

| Gate | Approval needed | Steps |
| --- | --- | --- |
| **0: Config hygiene** | operator | Re-scope `SUPABASE_SECRET_KEY` to Production. Create `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (Production, functions). Delete the two `VITE_SUPABASE_*` variables. Changing variables doesn't redeploy anything, so auth stays 503. |
| **1: Review** | security reviewer | Review this branch: code, staged SQL, templates and this plan. Confirm the Supabase and Resend settings above. Confirm all local suites pass (`npm test`, `npm run typecheck`). Merge only after approval. With the launch-stage gate unset, auth stays 503. |
| **2: Migration** | DB owner, explicit | Promotion PR (see "Database plan"). Check the Deploy Preview's migration log and preview-branch schema. Merge and confirm production publishes with the migration applied. Auth is still 503. |
| **3: Enable smoke stage** | security owner, explicit | Validate the restricted role on the production branch (read-only catalog queries in [auth-preflight.md](auth-preflight.md)). Set `HOURVIA_AUTH_HASH_KEY`, `HOURVIA_APP_ORIGIN`, `HOURVIA_AUTH_SMOKE_TEST_EMAILS`, `HOURVIA_AUTH_LAUNCH_STAGE=smoke` and `HOURVIA_AUTH_ALLOW_PRODUCTION=true`, keeping `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false`. Trigger a production redeploy of the same commit. Run step 1 of the smoke test (read-only), plus the database probe: `POST /api/auth/login` for a non-listed address must return 401, not 503. That proves the role works without contacting Supabase. |
| **4: Test admin bootstrap** | security owner, explicit (sends 1 email) | In Supabase, invite the test-admin mailbox. Run the reviewed bootstrap SQL with that user's UUID. The test admin accepts the invitation and signs in. |
| **5: Smoke test** | product + security owners, explicit | Set `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=true` and redeploy. Run steps 2–10. Archive the evidence. |
| **6: General availability** | product + security owners, explicit | Bootstrap the real first Admin (same reviewed procedure). Disable the test accounts. Set `HOURVIA_AUTH_LAUNCH_STAGE=general` and redeploy. Retire the Netlify Identity instance in a separate approved change. |

## Rollback strategy

- **Kill switch (seconds to minutes).** Unset `HOURVIA_AUTH_ALLOW_PRODUCTION`, or `HOURVIA_AUTH_LAUNCH_STAGE`, and redeploy. Every auth endpoint returns 503 and no email can be sent. Set `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false` on its own to stop email but keep login.
- **Instant rollback.** In Netlify Deploys, publish the previous known-good production deploy. Netlify Database migrations are forward-only. The auth tables are additive and unused by earlier code, so leaving them in place is safe.
- **Session purge.** Ending all Hourvia sessions takes a reviewed, one-off `UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'incident' WHERE revoked_at IS NULL`, or Admin "End sessions" for each member.
- **Credential compromise.** Rotate the Supabase secret key (and `HOURVIA_AUTH_HASH_KEY` if exposed, which invalidates rate-limit buckets but not sessions), update the Netlify secret, then redeploy. Rotate the Resend key in Supabase SMTP.
- **Test accounts.** After the smoke test, disable them in Hourvia, which also bans them in Supabase. Delete them in Supabase only with approval. Audit rows are kept.
- **Schema rollback.** If a schema defect is found, roll forward with a new reviewed migration. Never edit an applied migration.

## Residual risks (accepted or tracked)

- A user who already holds a valid Supabase recovery code could change their password directly through Supabase's API. Hourvia wouldn't then revoke their existing Hourvia sessions automatically, though those still expire within 12 hours. This could be mitigated later with a Supabase Auth hook or webhook.
- Supabase's own `/recover` and `/otp` endpoints can be called with the public key. Their email rate limit applies and M9 makes those emails inert.
- Scheduled pruning of expired sessions and rate-limit rows is still to do (not required for the smoke test).

## Readiness

| Area | Status |
| --- | --- |
| Code: Supabase adapter, server sessions, invitations, 6-digit recovery, RBAC, tenant isolation, rate limits, audit, fail-closed, smoke allowlist | **PASS** (local and mocked) |
| Production auth currently disabled | **PASS** (503 verified) |
| Netlify env scoping and naming (M1–M4) | **BLOCKED**: operator action at Gate 0 / 3 |
| Supabase URL configuration, templates, OTP length, SMTP (M5–M9) | **BLOCKED**: unverified, operator must confirm |
| Migration promotion and restricted-role validation | **BLOCKED**: Gate 2 approval; the role proposal is staged (`002`) and tested locally, but not yet validated on Netlify Database |
| Live provider and production smoke tests | **BLOCKED**: Gates 3–5 authorization |
| **Overall production activation** | **BLOCKED** |
