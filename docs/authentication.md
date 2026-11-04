# Hourvia authentication (Sprint 1.7)

Supabase Auth verifies credentials. Hourvia's Netlify Functions own sessions, workspace membership, roles, assignments, rate limits, and audit. Resend delivers Supabase's transactional email through custom SMTP. Browser code never handles a provider token, refresh token, or service credential.

## Netlify Identity audit (before migration)

| Item | Finding | Action |
| --- | --- | --- |
| `@netlify/identity`, `netlify-identity-widget`, `gotrue-js` | Not installed and not imported anywhere | None |
| Browser auth adapter | `unconfiguredAuth` (always signed out, sign-in always fails) | Replaced in the entry point by `serverSessionAuth`; kept for tests |
| Domain contracts | `Authentication`, `Principal`, `authorization.can`, and `canNavigate` have no provider coupling | Unchanged; recovery/invitation contracts added alongside |
| Functions and database | None existed; no migrations applied | New auth function; schema staged as a proposal |
| Docs | `architecture.md` planned `@netlify/identity` for Sprint 1 | Updated to point here |
| Site configuration | A Netlify Identity instance exists on the site | **Left untouched**, as instructed. No Identity users or passwords were read or migrated. |

## Architecture

```
Browser (React)                 Netlify Function auth-api               Supabase Auth          Netlify Database
 fetch /api/auth/* ───cookie──▶  origin + JSON checks, Zod (strict)  ──▶ signInWithPassword      workspace_members
 (credentials: same-origin)      rate limits (HMAC buckets)              verifyOtp (invite/recovery) manager_assignments
 no tokens in JS or storage      membership + role from DB only          admin.inviteUserByEmail   workspace_invitations
                                 opaque session (SHA-256 at rest)        admin.updateUserById      auth_sessions
                                 audit (append-only)                     admin.signOut ◀─ revoke   auth_audit_events
                                                                          SMTP ──▶ Resend           auth_rate_limits
```

- **Sign-in:** the function calls `signInWithPassword` server-side, revokes the resulting Supabase session immediately (`admin.signOut`, scope `local`), then requires an `active` ThriveSource `workspace_members` row linked by `auth_user_id`. It issues a 256-bit random token as `__Host-hourvia_session` (`HttpOnly; Secure; SameSite=Strict; Path=/`). Only its SHA-256 is stored. No Supabase refresh token is kept anywhere.
- **Every request:** the cookie hash is looked up together with the member's status in one query. Requests fail if the session is revoked, idle for more than 30 minutes, more than 12 hours old, or the member is not `active`. The `Principal` (role, assignments, approval authority) is rebuilt from the database and checked with the shared `authorization.can` policy. Client-supplied roles, workspace IDs, `Authorization` headers, and Supabase metadata are never trusted.
- **CSRF:** `SameSite=Strict`, an exact same-origin `Origin` check, `Sec-Fetch-Site` validation, and `application/json` are required on every POST.
- **Contexts and origin:** the function runs only in `production` (behind its gates) and local `dev`. Deploy previews and branch deploys always return 503. In production it answers only on `HOURVIA_APP_ORIGIN`; other hostnames get 421.
- **Fail closed:** missing configuration, missing tables, database errors, or provider outages return `503` without details. Production is disabled unless `HOURVIA_AUTH_ALLOW_PRODUCTION=true`.

### Endpoints

| Method and path | Who | Purpose |
| --- | --- | --- |
| GET `/api/auth/session` | anyone | Current principal, or 401 (clears cookie) |
| POST `/api/auth/login` | anyone | Generic failure message; 10 per email and 20 per IP per 15 min |
| POST `/api/auth/logout` | anyone | Revokes the session row and clears the cookie |
| POST `/api/auth/recovery/request` | anyone | Always the same 202 response, padded to at least 750 ms; emails only active members; 3 per email and 10 per IP per hour |
| POST `/api/auth/recovery/complete` | anyone | `{email, code, password}` or `{tokenHash, password}`; 5 per email and 20 per IP per hour; revokes all sessions |
| POST `/api/auth/invitations/accept` | invitee | `{tokenHash, password}`; must match a pending, unexpired invitation bound to the same Supabase user |
| GET `/api/admin/members` | Administrator | Members list (no provider IDs) |
| POST `/api/admin/invitations` | Administrator | Invites `workspace_manager` or `contractor`; `workspace_admin` also requires the caller's **Platform Super Admin** privilege. Platform privileges are never accepted. Requires `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=true` |
| POST `/api/admin/members/:id/role` | Administrator | `{role}`; changes an active member's organization role within the caller's authority (see [auth-platform-super-admin.md](auth-platform-super-admin.md)) |
| POST `/api/admin/members/:id/disable` | Administrator | Disables the member, revokes all sessions (attributed to the caller), bans the Supabase user; nobody can disable themselves; disabling an Administrator requires the Platform Super Admin privilege |
| POST `/api/admin/members/:id/revoke-sessions` | Administrator | Ends all sessions for a member within the caller's authority (anyone with access may end their own); every revocation records the acting member |

There is no signup endpoint.

### Invitation flow

1. The admin submits an email and role. The function checks admin RBAC, calls `admin.inviteUserByEmail` with no user metadata, and records the member (`invited`, bound to the returned Supabase user ID) and a 7-day invitation.
2. The email link points to `/accept-invite#token_hash=…`. The fragment never reaches servers or logs. The page strips it from the URL immediately, and link scanners can't consume it because the token is only spent by a POST.
3. The invitee sets a password. The server verifies the OTP (`type: invite`) and checks that the Supabase user ID matches the pending invitation. Supabase stores the password via `admin.updateUserById`; Hourvia never hashes passwords. The server then activates the member, revokes the provider session, and redirects the invitee to sign in.

### Recovery flow

Supabase's recovery email (sent via Resend) contains both the 6-digit `{{ .Token }}` and a `{{ .TokenHash }}` link. The 6-digit code is acceptable because Hourvia limits verification to 5 attempts per email per hour (about 5 in 10⁶ per hour against a code that expires and works once), as well as limiting by IP. After a reset, every Hourvia session and every Supabase session for the user is revoked.

## Required Supabase settings (production project Hourvia_Authentication)

The environment decision, configuration mismatches, gates, smoke test and rollback are in [production-activation-plan.md](production-activation-plan.md).

- **Authentication → Sign In / Providers:** turn off **Allow new users to sign up**, keep Email enabled, turn on **Confirm email**, and turn off all other providers and anonymous sign-ins.
- **Email OTP:** expiration of 3600 s (applies to invitation links and recovery codes) and length of 6.
- **Passwords:** minimum length 12; turn on leaked-password protection if the plan allows.
- **URL configuration:** set **Site URL** to exactly `https://hourvia.livingitsolutions.com` (the same value as `HOURVIA_APP_ORIGIN`; the templates build links from `{{ .SiteURL }}`) and allow-list only `https://hourvia.livingitsolutions.com/accept-invite` and `https://hourvia.livingitsolutions.com/reset-password` as Redirect URLs.
- **Email templates:** use [invite.html](auth-email-templates/invite.html) for Invite user and [recovery.html](auth-email-templates/recovery.html) for Reset password. Replace the Magic link, Confirm signup and Change email templates with inert text that contains no link or token.
- **Rate limits:** all traffic reaches Supabase from Netlify Functions IPs, so raise Supabase's per-IP sign-in and verify limits enough to avoid shared throttling. Hourvia's per-email and per-IP limits are the primary control. Keep the email-sending limit low.
- **API keys:** only the server uses the anon (publishable) and service-role (secret) keys. Neither is shipped to the browser. RLS is irrelevant here because Hourvia data lives in Netlify Database, not Supabase.

## Required Resend settings

- Verify a sending domain (for example `mail.livingitsolutions.com`) with SPF, DKIM, and DMARC.
- Create a **sending-only** API key restricted to that domain.
- In Supabase **Authentication → Emails → SMTP Settings**, use host `smtp.resend.com`, port `465` (or 587), username `resend`, password set to the Resend API key, sender `no-reply@<verified domain>`, and sender name `Hourvia`.
- The Resend key lives only in Supabase's SMTP settings. Hourvia's Netlify environment never needs it.

## Netlify environment

See `.env.example` and the variable table in [production-activation-plan.md](production-activation-plan.md). Scope every value to the **Production** context and functions only, and mark credentials as secret. Never use a `VITE_` prefix. In production the function also requires `HOURVIA_AUTH_ALLOW_PRODUCTION=true`, `HOURVIA_APP_ORIGIN` and `HOURVIA_AUTH_LAUNCH_STAGE` (`smoke` with `HOURVIA_AUTH_SMOKE_TEST_EMAILS`, or `general`). During `smoke`, only designated test accounts can sign in, be invited, recover or be administered, and everyone else is refused before Supabase is contacted. Keep `HOURVIA_EMAIL_DELIVERY_AUTHORIZED` unset or `false` until live email is authorized.

## Database

The schema is staged at `db/proposals/sprint-1.7-auth/001_create_auth_foundation.sql`, outside `netlify/database/migrations`, so Netlify applies it nowhere. `002_restricted_auth_runtime_role.sql` (replacing the missing Sprint 1.6 proposal for these tables) creates `hourvia_auth_runtime`. Every auth statement runs under `SET LOCAL ROLE hourvia_auth_runtime` (`server/auth/sql-role.ts`), and auth returns 503 until the role exists. Promote both files together, following [auth-preflight.md](auth-preflight.md). The grants are column-level:

- `auth_audit_events`: INSERT only.
- `auth_rate_limits`: INSERT, UPDATE, and SELECT.
- `auth_sessions`: INSERT, UPDATE, and SELECT.
- Members and invitations: INSERT, UPDATE, and SELECT.
- No DELETE or DDL is needed. Triggers also block UPDATE, DELETE, and TRUNCATE on audit events.

The first Admin is bootstrapped with the reviewed `bootstrap-first-admin.sql.example`. The platform-scoped Platform Super Admin privilege, its database guards and its operator procedures are described in [auth-platform-super-admin.md](auth-platform-super-admin.md). Future multi-tenant, seat and PWA design is in [saas-pwa-architecture.md](saas-pwa-architecture.md). Expired session and rate-limit rows can be pruned by a later scheduled job.

## Tests

- **Mocked:** `server/auth/auth.mocked.test.ts` runs the real HTTP handler, service, and Postgres store against embedded Postgres (PGlite) running the proposal SQL, with a fake Supabase. `provider-supabase.mocked.test.ts` runs real supabase-js against a fake `fetch`. `src/infrastructure/server-session-auth.test.tsx` covers the browser adapter, the UI flows, and a static scan of the secret boundary.
- **Live (opt-in, skipped by default):** `server/auth/supabase.live.test.ts` needs `HOURVIA_LIVE_SUPABASE_TESTS=production-smoke` (or `nonproduction` for a disposable project) and project keys. Run it only from a trusted operator shell. It never sends email or changes users, and the optional sign-in check runs only for an email in `HOURVIA_AUTH_SMOKE_TEST_EMAILS`.
