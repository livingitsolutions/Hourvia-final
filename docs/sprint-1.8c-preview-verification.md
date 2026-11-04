> Superseded operational guidance: use [Sprint 2.0B.2 production pre-launch controls](production-prelaunch.md). Earlier activation, general-stage, dev/provider, invitation and preview-promotion steps below are historical and must not be executed as current instructions.

# Sprint 1.8C — Controlled preview verification of `20261104160000`

This runbook verifies Sprint 1.8B (H-1 `pg_temp` hardening and M-1 platform rate limits) on a real Netlify Database
branch. It contains **no shadowing attack**. Every database check is a catalog read in a `READ ONLY` transaction.

> Treat every preview branch as holding copied production data. Do not create temp tables, `SET ROLE`, create LOGIN
> roles, change credentials or run exploit probes against it. Shadowing regressions run only in
> `server/auth/platform-security.test.ts` (throwaway PGlite).

## 1. Database checks (read-only)

```sh
netlify database connect --query "$(cat db/verification/sprint-1.8b-preview-readonly.sql)"
netlify database status        # must list six applied migrations and zero pending
```

| Check | Expected |
|---|---|
| V1 | exactly the 15 reviewed `hourvia_*` functions |
| V2 | every `proconfig` is exactly `search_path=pg_catalog, public, pg_temp` |
| V3 | all owned by `netlifydb_owner` |
| V4 | `SECURITY DEFINER` only on `hourvia_platform_overview` and `hourvia_platform_audit_page` |
| V5 | no EXECUTE for `PUBLIC`/`netlifydb_readonly`; `hourvia_auth_runtime` only on `hourvia_member_authority`, `hourvia_platform_overview`, `hourvia_platform_audit_page` |
| V6 | `hourvia_auth_runtime` has no CREATE on `public` or the database, keeps USAGE |
| V7 | no `hourvia_*` role can log in |
| status | applied: `20261103170000`, `20261103170100`, `20261104120000`, `20261104130000`, `20261104150000`, `20261104160000` |

## 2. Application checks

**These checks cannot run on a deploy preview as configured.** `readServerEnv` (`server/auth/config.ts`) returns
`context_not_enabled` for every context except `production` and `dev`, so every `/api/*` route on a deploy preview
answers `503 auth_unavailable`. This is deliberate: deploy previews share the production Supabase project and
secrets, and there is no non-production identity provider. A deploy preview can only confirm that check A0 returns
`503` and leaks nothing.

The checks below run only where the auth function is enabled:
- local `netlify dev` (context `dev`) bound to an agent or preview database branch, with operator approval because
  it signs in against the production identity provider. The `dev` context carries the production
  `HOURVIA_APP_ORIGIN`, so `localhost` requests get `421 wrong_origin` unless that variable is overridden for the
  local process only (never in the Netlify UI). The production launch stage also applies, so in `smoke` stage only
  the designated smoke-test accounts can sign in; or
- production, as a post-deploy smoke test with separate approval.

`$PREVIEW` is the origin under test (`http://localhost:8889` for `netlify dev`). Send no `Origin` header, or the preview's own origin; foreign origins are
refused before authorization. Session cookies come from signing in through the preview UI. Never paste them into
tickets or logs.

| # | Who | Request | Expected | Database side effect on the branch |
|---|---|---|---|---|
| A0 | none, on a deploy preview | `curl -si $PREVIEW/api/platform/overview` | `503 auth_unavailable`, no data | none |
| A1 | none | `curl -si $PREVIEW/api/platform/overview` | `401`, no body data | none |
| A2 | none | `curl -si "$PREVIEW/api/platform/audit?limit=10"` | `401` | none |
| A3 | Platform Super Admin holder | sign in, open the Platform console | overview and first audit page render | one `platform_audit_read` row per audit page |
| A4 | holder | `curl -si -H "Cookie: __Host-hourvia_session=…" $PREVIEW/api/platform/overview` | `200`, no UID/email/session hash | none |
| A5 | signed-in Manager/Administrator without the grant | `GET /api/platform/overview` | `403` | one `auth_audit_events` denial row |
| A6 | same non-holder | repeat A5 until 11 total requests (10/member/hour) | requests 1–10 → `403`; request 11 → `429` with no platform data | 10 denial rows + 1 `rate_limited` row |
| A7 | holder, after A6 | `GET /api/platform/overview` | still `200` (holder unaffected) | none |

Optional, because it adds 60 append-only rows to the branch: 61 holder audit reads (`GET /api/platform/audit`) →
reads 1–60 `200`, read 61 `429`. The PGlite suite already covers it.

Thresholds are `PLATFORM_LIMITS` in `server/auth/service.ts`: 10 denials per member, 30 per IP, 60 audit reads per
holder, in fixed one-hour windows.

## 3. Record

Record the pass/fail per check, the deploy ID, the database branch name and the operator. Don't record cookies,
UIDs or emails.
