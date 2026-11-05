# Hourvia operations status

Last reconciled: Sprint 2.0C.2, 2026-11-05. This document records what is known about the production deployment, database and configuration, and how each fact is known. It authorizes no operation. Update it whenever a status changes, and keep the evidence class accurate.

## Evidence classes

| Class | Meaning |
|---|---|
| **Verified** | Observed directly from read-only Netlify metadata, unauthenticated HTTP checks or the repository. |
| **Owner-confirmed** | Reported by the account owner. Not independently verified. |
| **Historical** | True of an earlier state. Kept for traceability; it does not describe the current state. |
| **Access limitation** | Could not be checked because the access path returned 401. This is not evidence of a fault. |
| **Unverified** | No direct evidence either way. |

## Production identity (verified 2026-11-05)

| Item | Value |
|---|---|
| Site | `hourvia-tracker` (`48d7a24b-6072-40bc-866f-0d6e43a921ea`) |
| Canonical URL | https://hourvia.livingitsolutions.com (200) |
| Production branch | `main` (auto-publish, not locked) |
| Published deploy | `6aebe50abd9ac16c02942a31`, commit `6c22106d4e97eff0860c77b9f14b468e25209f67`, context `production`, database branch `production`, published 2026-11-05 02:08:34 UTC (re-verified 2026-11-05, Sprint 3.0 preflight) |
| Known-good rollback deploy | `6aeb5cd4c8797713f23cc5b8` (same commit) |
| Authentication | Fail-closed. `/api/auth/session`, `/api/admin/members` and `/api/platform/overview` return 503 `auth_unavailable` |
| Deploy secret scan | 94 files scanned, 0 matches |

## Migrations (verified in the repository)

| # | Migration | SHA-256 |
|---|---|---|
| M1 | `20261103170000_create-auth-foundation` | `fa614b04e8caf8faf4ee82ff211c5fb78c2853f16cba765775919452bd39fe2a` |
| M2 | `20261103170100_restrict-auth-runtime-role` | `58be1ffd2ca6bc247ebbee88662aa3035d1a183492746004a4de413f7525f037` |
| M3 | `20261104120000_super-admin-role` | `8476f1a8ba50cacd083d53d67bdda01b4903494bf3cb982f93cb39e38bef132f` |
| M4 | `20261104130000_platform-privileges-correction` | `1c275a67a062e76c51cfc16558ab30fac4f0ee4193ef2c0ef333928693c1591e` |
| M5 | `20261104150000_platform-administration-read-access` | `b1f199ea303d7e1c437c5a56d6060a9f33bd746392c7e8a6bca8c659c255aea0` |
| M6 | `20261104160000_pin-function-search-path-pg-temp` | `a1ff5af790a69ff9b83c6a8ff49f4718707cb8db8be71a79a1e94df0c6544d44` |
| M7 | `20261104170000_organizations-expand` | `9f483233ba7dc2e762ae50890e029478b2d57a4c618e7cc4e3f76e7bfc502576` |

These digests are pinned in `server/auth/production-database.ts` (`MIGRATION_DIGESTS`) and checked by the offline tests. M1–M7 must never be edited, renamed or removed; schema corrections go forward in a new, separately approved migration.

### Production ledger

- **Verified (deploy metadata):** production deploys recorded applying M1–M2 (`6aea1369`, 11-03 17:01 UTC), M3–M4 (`6aea8aec`, 11-04 01:31 UTC) and M5–M6 (`6aeaa310`, 11-04 03:14 UTC). Production deploys since 15:24 UTC on 11-04 report no pending migrations and no errors.
- **Owner-confirmed:** the current production deploy completed database provisioning and discovered M1–M7.
- **Historical finding (provenance discrepancy):** the production ledger contained M7 before 15:20:40 UTC on 11-04. At that time the production deploy `6aeabf28` (commit `799f042`, no M7) was re-published three times (15:20:40, 15:20:54, 15:23:14 UTC) and recorded "migration 20261104170000_organizations-expand has been removed after being applied". No deploy on any Hourvia site records applying M7 to production, and M7 reached `main` only at 15:24:43 UTC (PR #15). What wrote M7 to the production ledger is **unverified**.
- **Access limitation:** `netlify db status --branch production`, the database metadata API, build logs and the account audit log return 401 from Agent Runner.
- **Unverified:** the production ledger's exact contents and order, whether production's M7 content matches the repository digest, and the production catalog (tables, constraints, grants, functions, search paths, organization schema).

## Configuration

| Item | Owner-confirmed | Netlify metadata (verified) | Status |
|---|---|---|---|
| Nine variables (`HOURVIA_APP_ORIGIN`, `HOURVIA_AUTH_ALLOW_PRODUCTION`, `HOURVIA_AUTH_HASH_KEY`, `HOURVIA_AUTH_LAUNCH_STAGE`, `HOURVIA_AUTH_SMOKE_TEST_EMAILS`, `HOURVIA_EMAIL_DELIVERY_AUTHORIZED`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `SUPABASE_URL`) | Production-only, Functions-scoped | Recreated 2026-11-05 02:06–02:07 UTC. Each has exactly one value in context `production`. Deploy Preview, branch deploy and dev resolve none of them. A newly built Deploy Preview (`6aebe84ee08c78e7856b04a8`) reported all nine absent at runtime. | Resolved for new deploys. Deploys built before 2026-11-05 02:06 UTC kept the earlier values. |
| `SUPABASE_SECRET_KEY` rotated, previous key revoked | Yes | Last updated 2026-11-04 17:14 UTC | Owner-confirmed |
| `HOURVIA_SYNTHETIC_IDENTITY_POLICY`, `HOURVIA_PRODUCTION_DATABASE_EVIDENCE` | n/a | Not set | Correct for the current fail-closed state; both are required before any smoke activation |
| Branch deploys | n/a | All branches build | Not yet aligned with the main-only policy |
| Deploy Previews | n/a | Enabled; untrusted contributors require approval | Not yet aligned with the main-only policy |
| Non-Git production deploys | n/a | Allowed | Owner decision pending |
| Deploy notifications | n/a | GitHub status/checks only; no succeeded/failed/locked email or Slack | Owner decision pending |
| Old deploy permalinks | n/a | Public; no password or SSO protection | Exposure remains until restricted or expired (90-day retention) |
| Legacy staging hostname | n/a | Not attached to any site; resolves only through `*.hourvia.livingitsolutions.com` and returns a Netlify 404 | Not serving content; DNS cleanup pending |

The code refuses authentication outside a published production deploy on this site whose stamped identity matches. Previews and branch deploys built after the 2026-11-05 rescoping receive none of the nine variables. Older preview and branch deploys still hold the values they were built with, so the previous Supabase secret key must stay revoked. The temporary diagnostic deploy `6aebe84ee08c78e7856b04a8` should be deleted by the owner.

## Release rules

- Every merge to `main` is a production release. Netlify auto-publishes it and applies any new migration file to the production database.
- Do not republish any deploy built before commit `e33fefc` (PR #15). Pre-M7 deploys conflict with the production ledger.
- **Before any M8 or later migration reaches `main`:**
  1. `netlify db status --branch production --json`, run by the owner, shows exactly M1–M7 in order, with nothing pending, missing or out of order.
  2. M7's provenance in production is explained (audit log or Netlify Support), and its applied content is confirmed to match the digest above, or a reviewed read-only catalog check matches the M1–M7 schema.
  3. The new migration has been rehearsed offline and on an isolated preview database branch, and its preconditions refuse to run on any unexpected state.
- Authentication activation additionally requires everything in [production pre-launch safeguards](production-prelaunch.md).
