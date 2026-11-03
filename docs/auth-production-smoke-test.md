# Hourvia production authentication smoke test: runbook (Sprint 1.9B)

**Status: PREPARED, NOT EXECUTED.** Production authentication is disabled. Nothing in this runbook has been run.

Each stage needs the named approval before it starts. The same approval does not carry over to the next stage.

Context:
- [production-activation-plan.md](production-activation-plan.md) is the gate model.
- [migration-promotion-checklist.md](migration-promotion-checklist.md) holds V1–V7.
- [authentication.md](authentication.md) describes the architecture.

Every value, threshold and response in this runbook is taken from the source at the commit that added it:
- `server/auth/config.ts`
- `service.ts`
- `http.ts`
- `sql-role.ts`
- `runtime.ts`
- `store-postgres.ts`
- the two applied migrations

If the code changes, re-check this document.

## Conventions

- **Canonical origin:** `https://hourvia.livingitsolutions.com`. Run every test there. With auth enabled, `hourvia-tracker.netlify.app` answers **421** `wrong_origin` by design.
- **Owner SQL** means the Netlify Database SQL editor for the **production** branch. It connects as `netlifydb_owner`, which can read the auth tables and also bypasses the restricted role.
  - Use it read-only unless a step says it writes.
  - Only Stage D and the incident steps in Stage F write.
- **No step prints secrets.** Don't paste cookies, token hashes, recovery codes or keys into tickets, chat or logs. Record status codes, event types and outcomes only.
- **Environment-variable changes only take effect after a production redeploy.** Netlify bakes Function environment variables into each deploy. To redeploy, go to Deploys → Trigger deploy → "Deploy project" on `main`, using the same commit and no new migrations. Every redeploy is a production deploy and needs the stage's approval.
- **Same 503 for every failure.** The auth function returns the same `503 auth_unavailable` body for every configuration failure, and it has no server-side logging. A wrong value looks exactly like "disabled". If you get a 503 you didn't expect, re-check each value against the rules in Stage C.

---

## Stage A: Preconditions (read-only)

**Approval:** operator. **Writes:** none.

| # | Check | How | Expected | Evidence on record |
| --- | --- | --- | --- | --- |
| A1 | Production deploy healthy | Netlify Deploys: the published deploy is `ready`, context `production`, branch `main`. Then `curl -s -o /dev/null -w '%{http_code}' https://hourvia.livingitsolutions.com/` | `ready`; 200 | Stage 0: commit `3a17064`, 200 |
| A2 | Auth disabled | `curl -s https://hourvia.livingitsolutions.com/api/auth/session` | 503 `{"error":"auth_unavailable",…}`, no `Set-Cookie` | Stage 0: PASS |
| A3 | No signup route | `curl -s -o /dev/null -w '%{http_code}' https://hourvia.livingitsolutions.com/api/auth/signup` | 404 (the router has no such route; this doesn't depend on configuration) | Stage 0: PASS |
| A4 | Supabase settings S1–S20 | Operator-reviewed record (Stage 0 checklist) | All recorded. In particular: OTP length 6, Site URL exact, Hourvia invite and recovery templates, CAPTCHA off, signup off. | Operator-reviewed (accepted) |
| A5 | Production-only environment | Netlify dashboard → Environment variables → Edit, for each of `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` and `SUPABASE_SECRET_KEY` | Functions scope; different value per context; Production set; every other context empty | Operator dashboard evidence (accepted). **See the unresolved gate U1 below.** |
| A6 | Secret key rotation and revocation | Supabase → Settings → API Keys | Record: the date the current secret key was created, and whether any earlier secret or `service_role` key is revoked | **Record before Stage C** |
| A7 | No unexpected members or invitations | Owner SQL: `SELECT count(*) FROM workspace_members;` `SELECT count(*) FROM workspace_invitations;` `SELECT count(*) FROM auth_sessions;` | `0`, `0`, `0` | **Not yet recorded** (the read-only credential is denied by design) |
| A8 | Migration history complete | Netlify Database → production → migrations (or `netlify db status` against production) | Exactly `20261103170000_create-auth-foundation` and `20261103170100_restrict-auth-runtime-role` applied; 0 pending, 0 missing, 0 out of order | Sprint 1.8 operator evidence; Stage 0 preview branch PASS |
| A9 | Supabase user inventory | Supabase → Authentication → Users | Record the count. None of the designated smoke mailboxes exist yet, unless that was planned. | Record |
| A10 | Live read-only provider check (optional, separately approved) | Trusted operator shell, never CI: `HOURVIA_LIVE_SUPABASE_TESTS=production-smoke SUPABASE_URL=… SUPABASE_PUBLISHABLE_KEY=… SUPABASE_SECRET_KEY=… npx vitest run server/auth/supabase.live.test.ts`, with **no** `HOURVIA_LIVE_TEST_*` variables | 4 passed, 1 skipped. It sends no email and changes no user. It does make one failed sign-in and some forged-token calls, which count towards Supabase rate limits and logs. | Not run |

### Unresolved security gates (must be accepted or closed in writing before Stage C)

- **U1: Runtime isolation of the Supabase variables. Unresolved; documented.**
  - The operator's dashboard Edit screens show Production-only values.
  - The Netlify API (`getEnvVars`) and the CLI (`env:list --context deploy-preview|branch-deploy|dev`) still report one `context: "all"` entry per variable, and they list the keys in every context.
  - Neither source can confirm the effective runtime values from here.
  - **Mitigation in code:** the auth function refuses every context except `production` and `dev` before it reads any key (`config.ts`).
  - **Residual risk:** other function code in a preview or branch deploy, and a linked `netlify dev` session, could read the variables if the `all` entry is what's actually in effect.
  - **To close:** raise a Netlify support query on why the API and the dashboard disagree, or have the security owner sign an explicit acceptance.
- **U2: Secret key rotation record (A6).**
- **U3: Production row counts (A7).**
- **U4: V6 on production.** Direct `netlifydb_readonly` denial passed on a preview branch derived from production (accepted evidence). It has not been run on the production branch itself.

**Stop if:** A1–A3 or A8 fails; A7 is non-zero and the rows can't be explained; or U1–U3 are neither closed nor accepted.

---

## Stage B: Restricted runtime verification

**When:** immediately after the Stage C redeploy, before Stage D. **Approval:** security owner (part of the Stage C approval). **Writes:** B4 inserts one rate-limit row and one audit row. Nothing else writes.

### What the code guarantees (static, with local tests)

- **Single database entry point.** `server/auth/runtime.ts` is the only `getDatabase()` call. It uses the Netlify-injected connection for the production database branch. No connection string is read from user or configurable input.
- **Every statement runs under the restricted role.** `roleScopedSqlClient` (`sql-role.ts`) runs every statement inside `BEGIN; SET LOCAL ROLE hourvia_auth_runtime; …; COMMIT`.
  - The role name is a constant; no environment variable can change it.
  - `SET LOCAL` reverts at COMMIT or ROLLBACK, so the role can't leak to other requests sharing a pooled connection (tested).
- **No fallback to owner privileges.** No code path issues a query without first entering the role.
  - If `SET LOCAL ROLE` fails, the transaction rolls back and the request returns **503**. Causes include a missing role, a revoked grant, or connecting as `netlifydb_readonly`. All three are tested.
- **Least privilege in the catalog** (Stage 0, preview branch): the role can't read `auth_audit_events`, can't delete anywhere, and can only update the listed state columns.

### Runtime probes (no diagnostic endpoint)

| # | Request | Expected | Proves | Stop if |
| --- | --- | --- | --- | --- |
| B1 | `curl -s -o /dev/null -w '%{http_code}\n' https://hourvia.livingitsolutions.com/api/auth/session` (no cookie) | **401** | The configuration gate passed and the origin matched. This path doesn't touch the database (no token means no query). | 503: configuration wrong. Check every Stage C rule. |
| B2 | The same request on `https://hourvia-tracker.netlify.app` | **421** `wrong_origin` | The canonical-origin pin is live | anything else |
| B3 | `curl -s -i https://hourvia.livingitsolutions.com/api/auth/session -H "Cookie: __Host-hourvia_session=$(openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '=')"` | **401** and `Set-Cookie: __Host-hourvia_session=; …Max-Age=0` | A well-formed but unknown 43-character token reaches `resolveSession`. Its SELECT on `auth_sessions` and `workspace_members` ran in a transaction **after** `SET LOCAL ROLE` succeeded on the production pool. Read-only. | **503: the role switch or database failed. Go to Stage F now.** |
| B4 | One login for an address that is **not** in `HOURVIA_AUTH_SMOKE_TEST_EMAILS` and isn't a real user: `curl -s -i -X POST https://hourvia.livingitsolutions.com/api/auth/login -H 'Origin: https://hourvia.livingitsolutions.com' -H 'Content-Type: application/json' --data '{"email":"stage-b-probe@example.com","password":"not-a-password"}'` | **401** `login_failed` | The rate-limit upsert (`auth_rate_limits`) and the audit insert (`auth_audit_events`) succeed under the role's column grants. The request is denied **before Supabase is contacted**, so no provider call and no email. | 503 |
| B5 | Owner SQL, read-only: `SELECT event_type, outcome, details->>'reason' AS reason FROM auth_audit_events ORDER BY id DESC LIMIT 1;` | `login`, `denied`, `smoke_allowlist` | The write path is audited | row missing |

**Limitation.** B3–B5 show that every auth query runs only after a successful `SET LOCAL ROLE`, because the code has no other path. They don't show the **effective** `current_user` directly: the owner could also run these statements. The only way to prove the effective role directly would be a separately approved, forward-only migration that adds an audit column defaulting to `current_user`, where new rows must show `hourvia_auth_runtime`. That migration is **not** part of this sprint. `pg_stat_statements` isn't installed (only `plpgsql` is present), so that route isn't available.

---

## Stage C: Controlled activation (smoke stage)

**Approval:** security owner, explicit and in writing, after Stage A. **Changes:** production environment variables plus one production redeploy.

### Variables and valid values (from `server/auth/config.ts`)

Set every variable in the **Production context only**, with **Functions scope only**. Never use a `VITE_` prefix.

| Variable | Secret | Valid value (exact rule in code) | Smoke value | Effect if wrong |
| --- | --- | --- | --- | --- |
| `HOURVIA_AUTH_ALLOW_PRODUCTION` | no | Exactly the string `true`. Any other value or unset gives `production_not_enabled`. This is checked **first**. | `true` (set **last**) | 503 (this is the kill switch) |
| `HOURVIA_AUTH_HASH_KEY` | **yes** | Required. Length ≥ 32 characters. Generate 48+ random characters once. | random | unset: `not_configured`; too short: `misconfigured` (503) |
| `HOURVIA_APP_ORIGIN` | no | Required in production. Must match `^https://[a-z0-9.-]+(:\d+)?$`: no path and no trailing slash. It must equal the Supabase Site URL. | `https://hourvia.livingitsolutions.com` | 503 `misconfigured` |
| `HOURVIA_AUTH_LAUNCH_STAGE` | no | Exactly `smoke` or `general`. In production, anything else or unset gives `launch_stage_not_set`. | `smoke` | 503 |
| `HOURVIA_AUTH_SMOKE_TEST_EMAILS` | **yes** | Required when the stage is `smoke`. 1–20 comma-separated addresses, case-insensitive, each matching `^[^\s@,]+@[^\s@,]+\.[^\s@,]+$`. **One malformed entry invalidates the whole list.** | the designated test mailboxes (see Stage E) | 503 `misconfigured` |
| `HOURVIA_EMAIL_DELIVERY_AUTHORIZED` | no | Exactly `true` enables Hourvia-initiated email (invitations and recovery). It also needs a valid `HOURVIA_APP_ORIGIN`. Any other value disables it. | `false` until Stage E step E2 | Invites return 503 `email_delivery_not_authorized`. Recovery returns the generic 202 and sends nothing (audited as `delivery_not_authorized`). |

These must already exist and pass the same checks. `config.ts` rejects them if `SUPABASE_URL` doesn't start with `https://`, if the two keys are equal, or if the key types are swapped (`sb_secret_…` as the publishable key, or `sb_publishable_…` as the secret key).
- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY`
- `SUPABASE_SECRET_KEY`

Optional (code defaults apply when unset or out of range):
- `HOURVIA_SESSION_IDLE_SECONDS`: 300–7200, default 1800.
- `HOURVIA_SESSION_ABSOLUTE_SECONDS`: 3600–86400, default 43200, and never less than the idle timeout.

Leave both unset for the smoke test.

### Ordering

1. Confirm Stage A, and that U1–U4 are closed or accepted in writing.
2. Add `HOURVIA_AUTH_HASH_KEY`, `HOURVIA_APP_ORIGIN`, `HOURVIA_AUTH_LAUNCH_STAGE=smoke`, `HOURVIA_AUTH_SMOKE_TEST_EMAILS` and `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false`. These have no effect until a redeploy, and they have no effect without the kill switch.
3. Add `HOURVIA_AUTH_ALLOW_PRODUCTION=true` **last**.
4. Re-open each variable's Edit screen. Confirm Production-only values and Functions scope.
5. Trigger **one** production redeploy of the current `main` commit.
6. Run Stage B immediately. If B1 or B3 fails, go to Stage F.

---

## Stage D: First administrator (one-time bootstrap)

**Approval:** security owner, explicit and in writing, naming the designated admin mailbox and the approval reference. **Sends:** one email (the Supabase invitation). **Writes:** one member, one invitation and one audit row.

**Rules:**
- No public signup: the route doesn't exist, and Supabase signup is off (S2).
- No default credentials: the admin sets their own password through the invite link.
- Never automatic: this SQL is not a migration and must never be placed in `netlify/database/migrations/`.
- During the smoke stage, the admin mailbox **must** be a designated test mailbox listed in `HOURVIA_AUTH_SMOKE_TEST_EMAILS`. Otherwise the acceptance is denied.
- Admins can't create other admins through the API: `adminInviteSchema` only allows `workspace_manager` and `contractor`. This is the only way an admin can exist.

**Preconditions:**
- Stage B passed.
- A7 counts were 0.
- The admin mailbox is in the smoke list.

### Steps (in this order, all within the Supabase Email OTP expiry, S8, for example 1 hour)

1. **Supabase → Authentication → Users → Invite user** for the admin mailbox. Supabase sends its "Invite user" template (the Hourvia template, S11, linking to `/accept-invite#token_hash=…`). This email is sent by Supabase directly. `HOURVIA_EMAIL_DELIVERY_AUTHORIZED` doesn't control it.
   **Don't open the link yet.** Opening it before step 2 consumes the token and the acceptance is denied (`no_invitation`).
2. Copy the new user's UUID from Supabase.
3. In owner SQL (write), run this once. It is guarded: it does nothing if any member or invitation already exists. It also records an audit event.

```sql
WITH guard AS (
  SELECT 1 AS ok
  WHERE NOT EXISTS (SELECT 1 FROM workspace_members)
    AND NOT EXISTS (SELECT 1 FROM workspace_invitations)
), member AS (
  INSERT INTO workspace_members (workspace_id, auth_user_id, email, display_name, role, status)
  SELECT 'thrivesource', '<SUPABASE_USER_UUID>'::uuid, lower('<admin-test-mailbox>'), '<Display Name>', 'workspace_admin', 'invited'
  FROM guard
  ON CONFLICT DO NOTHING
  RETURNING id, email
), invitation AS (
  INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, expires_at)
  SELECT 'thrivesource', id, email, 'workspace_admin', 'pending', NULL, now() + interval '7 days' FROM member
  RETURNING member_id
)
INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, subject_member_id, details)
SELECT 'thrivesource', now(), 'admin_bootstrap', 'success', member_id,
       jsonb_build_object('method', 'operator_sql', 'approval_ref', '<approval reference>')
FROM invitation
RETURNING id, event_type, subject_member_id;
```

   - **One row returned:** bootstrapped.
   - **Zero rows:** nothing was written, because something already exists. Stop and investigate. Never delete rows to retry.
   - `invited_by_member_id IS NULL` is allowed only for this bootstrap, which the column comment documents.
4. The admin opens the email link on the canonical origin and sets a password of 12–72 characters.
   - Expected: `200` "Your password is set".
   - The member becomes `active`, and an `invitation_accepted / success` audit row is written.
5. The admin signs in (see Stage E, E4). From here on, all administration goes through the role-scoped API. Owner SQL isn't used for administration.

**Verify (owner SQL, read-only):**

```sql
SELECT role, status, activated_at IS NOT NULL AS activated FROM workspace_members;
SELECT event_type, outcome FROM auth_audit_events ORDER BY id;
```

**If the link expired or was consumed early:** re-send the invitation from Supabase to the same user, which keeps the same UUID. The pending Hourvia invitation is valid for 7 days. Don't re-run the SQL.

---

## Stage E: Authentication smoke tests

**Approval:**
- Product owner and security owner, explicit.
- E2 onwards needs `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=true` plus a redeploy, which is a separate approval.

**Accounts:** designated test mailboxes only, all listed in `HOURVIA_AUTH_SMOKE_TEST_EMAILS`. For example:
- `hourvia-smoke-admin@…`
- `hourvia-smoke-manager@…`
- `hourvia-smoke-contractor@…`
- a second contractor mailbox, for cross-user checks

Record the time, the status code and the matching audit row (`event_type` and `outcome` only) for each step. Leave at least 15 minutes between E16 and any other login step, because the limits are shared by IP.

| # | Test | Procedure | Expected (from code) |
| --- | --- | --- | --- |
| E1 | Invitation creation | Admin: `POST /api/admin/invitations` `{"email":"<manager mailbox>","role":"workspace_manager"}` (UI: Workspace settings). With delivery still `false`: | **503** `email_delivery_not_authorized`, and no email. Then enable delivery and redeploy. |
| E1b | Allowlist | Admin invites a **non-listed** address | **403** `smoke_allowlist`, no provider call, audit `invitation_created / denied` |
| E2 | Invitation email delivery | Admin invites the manager and both contractors | **201**. Each email comes from the Resend domain with SPF, DKIM and DMARC passing. The link is `https://hourvia.livingitsolutions.com/accept-invite#token_hash=…` and is not rewritten by click tracking (S15). Audit `invitation_created / success`. |
| E3 | Invitation acceptance | Each invitee opens their link and sets a password | **200**; the member becomes `active`; audit `invitation_accepted / success` |
| E4 | Email/password login | Sign in as each account | **200** `{principal}` with the correct role; audit `login / success` |
| E5 | Session creation | Inspect the response headers (browser devtools; don't copy the value) | `Set-Cookie: __Host-hourvia_session=…; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`. Not visible to `document.cookie`. |
| E6 | Session persistence | Reload, wait more than 60 s, then `GET /api/auth/session` | **200**, same principal. `last_seen_at` advances at most once a minute. Idle timeout 30 min; absolute 12 h. |
| E7 | Logout and revocation | `POST /api/auth/logout`, then replay the old cookie (in the same browser profile, from saved devtools state; never shared) | **204** with a clearing cookie, then **401**; audit `logout / success` |
| E8 | Six-digit recovery | Contractor: request recovery, then complete with `{email, code, password}` | Request: **202** generic message (identical for unknown and non-listed emails, with ≥ 750 ms minimum latency). The email has a 6-digit code and a `/reset-password#token_hash=` link. Completion: **200**. The contractor's other sessions are revoked (`details.sessions_revoked`). Old password fails, new one works. Audit `recovery_requested / success`, then `recovery_completed / success`. |
| E9 | Expired and replayed tokens | Reuse the E3 invite link; reuse the E8 code; use an invite link older than the Supabase OTP expiry (S8) | **400** `invitation_failed` / `recovery_failed`, with the generic message; audit `… / denied` with reason `verification` |
| E10 | Unauthorized access | No cookie, a random cookie, and two duplicate session cookies, against `/api/auth/session` and `/api/admin/members`. A cross-origin POST (wrong `Origin`), and a `text/plain` POST. | **401**. A single cookie gets a clearing `Set-Cookie`; duplicate cookies are treated as no session, so they get no clearing cookie. **403** `origin_rejected` for the bad Origin or content type; a bearer `Authorization` header is ignored |
| E11 | Admin authorization | Admin: `GET /api/admin/members`, then `POST /api/admin/members/<contractor-2 id>/revoke-sessions` | **200**; then **200** `{sessionsRevoked:n}` and contractor 2's next request returns **401**. Self-disable returns **409** `self_disable`. |
| E12 | Manager authorization | Manager: `GET /api/admin/members`, `POST /api/admin/invitations` | **403** `forbidden`; audit `admin_access / denied` |
| E13 | Contractor authorization | Contractor: the same admin endpoints | **403** `forbidden` |
| E14 | Cross-user denial and escalation | Contractor posts `/api/admin/members/<other id>/disable`. Any user sends `role`, `workspaceId` or extra fields in bodies (`{"email":…,"role":"workspace_admin"}`). The admin invites with `role:"workspace_admin"`. | **403**; **400** `invalid_request` (strict schemas); **400** (admins can't mint admins). No state change. |
| E15 | Audit generation | Owner SQL, read-only: `SELECT event_type, outcome, count(*) FROM auth_audit_events GROUP BY 1,2 ORDER BY 1,2;` | One row per step above. `email_hmac` and `ip_hmac` are 64-character hex. No raw emails or IPs in `details`. |
| E16 | Rate limiting | (a) 11 wrong-password logins for one test email within 15 min. (b) 4 recovery requests for one email within 1 h. (c) 6 wrong codes for one email within 1 h. | (a) the 11th returns **429** (`login_email` 10/15 min; `login_ip` 20/15 min). (b) the 4th returns **429** (`recovery_request_email` 3/h). (c) the 6th returns **429** (`recovery_verify_email` 5/h). Each gives audit `rate_limited / denied`. Other limits: invite acceptance 10/h per IP, admin invites 30/h per admin. |
| E17 | Disable | Admin disables contractor 2 | **200**; immediate **401** for contractor 2; login denied (`member_disabled`); Supabase user banned (`providerBanned:true`) |

**Not testable yet:**
- Manager scope over assigned contractors. There's no API to create `manager_assignments` (the runtime role has SELECT only), and the time-tracking endpoints aren't implemented.
- Cross-user access to time records. Testing either would need separately approved owner SQL or later features.

**Abort and go to Stage F if any of these happen:**
- an email reaches a non-listed address
- a token, code, cookie or secret appears in a URL query, log, response body or browser storage
- a cross-role success
- a non-generic login or recovery response
- an unexpected 503
- a missing audit row

---

## Stage F: Emergency disable

**Who:** any approved operator can start it. A disable doesn't wait for approval.

### Procedure

1. **Kill switch.** Netlify → Environment variables → `HOURVIA_AUTH_ALLOW_PRODUCTION`:
   - Delete the Production value, or set it to anything other than `true`.
   - Then **trigger a production redeploy**. An environment change alone doesn't affect the running deploy.
2. **Optional, faster.** In Deploys, publish the last production deploy built **before** activation. The probe below must confirm 503; don't assume it.
3. **Email only.** To stop Hourvia-initiated email but keep login, set `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false` and redeploy.

### Expected responses after disable

| Request | Expected |
| --- | --- |
| `GET /api/auth/session` (with or without cookie) | **503** `auth_unavailable`, with no `Set-Cookie` |
| `GET /api/admin/members` | **503** |
| `POST /api/auth/login` with same-origin JSON | **503**. Bad Origin or content type: **403**. Wrong method: **405**. |
| `GET /api/auth/signup` | **404** |
| `GET /` | 200 |

### Sessions

- Disabling doesn't revoke session rows. They're unusable while auth is disabled. If auth is re-enabled, any unrevoked, unexpired session (absolute ≤ 12 h) works again.
- For an incident, revoke all sessions before re-enabling. This is owner SQL (write), separately approved:

  ```sql
  UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'incident' WHERE revoked_at IS NULL;
  ```

- Supabase-side sessions are already revoked at login, so no provider refresh token survives. If a provider credential or user is suspect, ban it in Supabase, or disable it through Hourvia before disabling auth.

### Verify that no unauthorized users remain active (owner SQL, read-only)

```sql
SELECT email, role, status, activated_at FROM workspace_members WHERE status <> 'disabled' ORDER BY created_at;
SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL AND absolute_expires_at > now();
SELECT email, status, expires_at FROM workspace_invitations WHERE status = 'pending';
```

Every non-disabled member and every pending invitation must be a designated test mailbox. In Supabase → Users, every user created during the window must be a test mailbox. These queries show email addresses, so keep the results inside the incident record.

### Preserve audit evidence

- `auth_audit_events` is append-only: UPDATE, DELETE and TRUNCATE are rejected by triggers.
- Never disable those triggers, drop tables, or "clean up" rows.
- Export the window for the incident record:

  ```sql
  SELECT id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, details FROM auth_audit_events WHERE occurred_at >= '<window start>' ORDER BY id;
  ```

- Keep the Netlify deploy IDs and timestamps for every redeploy.

### Stop and escalate to the security owner when

- any Stage B probe returns 503 after activation
- an unexpected member, invitation, session or Supabase user appears
- any secret or token may have been exposed (also rotate `SUPABASE_SECRET_KEY` in Supabase, update Netlify, redeploy, and rotate the Resend key)
- the kill-switch probe doesn't return 503
- a fix would need SQL against applied migrations: only roll forward with a new reviewed migration, and never edit applied files
