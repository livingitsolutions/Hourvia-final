# Hourvia operations status

Last reconciled: Sprint 3.0.6, 2026-11-08. This document records what is known about the production deployment, database and configuration, and how each fact is known. It authorizes no operation. Update it whenever a status changes, and keep the evidence class accurate.

## Evidence classes

| Class | Meaning |
|---|---|
| **Verified** | Observed directly from read-only Netlify metadata, unauthenticated HTTP checks or the repository. |
| **Owner-confirmed** | Reported by the account owner. Not independently verified. |
| **Historical** | True of an earlier state. Kept for traceability; it does not describe the current state. |
| **Access limitation** | Could not be checked because the access path returned 401. This is not evidence of a fault. |
| **Unverified** | No direct evidence either way. |

## Production identity (verified 2026-11-06)

| Item | Value |
|---|---|
| Site | `hourvia-tracker` (`48d7a24b-6072-40bc-866f-0d6e43a921ea`) |
| Canonical URL | https://hourvia.livingitsolutions.com (200) |
| Production branch | `main`. Production publishing is **locked** on the published deploy below (verified 2026-11-06): a merge to `main` still builds a production deploy, but it is not published until the owner publishes it manually |
| Published deploy | `6aebf26c137be0d868ccff2e`, commit `3fd11656743b799b8527dead246468e4cda20203` (PR #19, Sprint 3.0), context `production`, database branch `production`, published 2026-11-05 03:05:42 UTC, locked (re-verified 2026-11-07 from live site metadata, Sprint 3.0.2) |
| Previous published deploy | `6aebe50abd9ac16c02942a31`, commit `6c22106d4e97eff0860c77b9f14b468e25209f67` (Historical) |
| GitHub `main` protection | Ruleset `26699501` "Hourvia - Protect Main Production", enforcement `active`, target default branch: pull request with 1 approval (last-push approval, stale reviews dismissed, threads resolved), no deletion, no force push (verified 2026-11-06 through the public API). Bypass actors: **Unverified** (visible to admins only) |
| Known-good rollback deploy | `6aeb5cd4c8797713f23cc5b8` (same commit). Valid **only while the production database is M1–M7**. After M8 it is not a rollback target (see release rules) |
| Post-M8 recovery target | **Not designated.** Must be designated by the owner before any M8 release window (see release rules) |
| Authentication | Fail-closed. `/api/auth/session`, `/api/admin/members` and `/api/platform/overview` return 503 `auth_unavailable` (re-verified 2026-11-06) |
| Multi-organization | Not available. No HTTP route; no runtime capability; M8 is a proposal outside the migrations directory (re-verified 2026-11-07: `netlify/database/migrations/` holds exactly M1–M7, digests below unchanged) |
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
- **Verified (full deploy history, Sprint 3.0.4 audit, 2026-11-08):** M1–M6 were each applied by an identifiable production deploy. **No production deploy on this site has ever recorded applying M7.** M7 was applied only to preview branches (from 13:37 UTC on 11-04), and the production ledger already contained it when `6aeabf28` was re-published at 15:20:40 UTC. The out-of-band write therefore happened between about 13:37 and 15:20:40 UTC on 2026-11-04 (inferred window). Every later production build, including the locked, unpublished builds for PR #20–#22, reports no pending migrations.
- **Verified (secondary, Sprint 3.0.4):** a preview branch copied from production (it holds production rows) shows exactly M1–M7 applied, and its catalog matches a replay of the repository's M1–M7 on 325 of 327 fingerprint items; the two differences are platform artefacts (`cloud_admin` default ACLs, grantor name). This is evidence against schema drift, **not** production evidence.
- **Access limitation:** `netlify db status --branch production`, the database metadata API, build logs and the account audit log return 401 from Agent Runner. The platform ledger tables `netlify.migrations` and `netlify.migration_checksums` (which holds a per-migration `sha256`) are not readable by `netlifydb_readonly`.
- **Unverified:** the production ledger's exact contents and order, whether production's M7 content matches the repository digest, and the production catalog (tables, constraints, grants, functions, search paths, organization schema).

### Database targeting and preview isolation (Sprint 3.0.6, 2026-11-08)

Full evidence is in section 1 of the [M8 preview rehearsal runbook](m8-preview-rehearsal-runbook.md). `netlify-cli` 27.16.2 was inspected; no SQL was run on any Netlify database.

- **Verified (CLI source):** `netlify db connect` has no branch selection and ignores the Git branch. It connects to `NETLIFY_DB_URL` if set, otherwise to a local embedded database **with no migrations applied**. The Sprint 3.0.5 error `relation "public.workspace_invitations" does not exist` (a table created by M1) therefore came from a database without M1, almost certainly that empty local database. It says nothing about M8.
- **Verified (CLI source):** `netlify db status --branch <b>` reads the ledger by branch name through the API. To do so it silently fetches a **`netlifydb_owner`** connection string for that branch. The owner's production ledger gate below can use the credential-free `netlify api listSiteDatabaseMigrations --data '{"site_id":"48d7a24b-6072-40bc-866f-0d6e43a921ea","branch":"production"}'` instead.
- **Verified (CLI source):** `netlify db migrations apply` and `netlify db reset` honour `NETLIFY_DB_URL`. `reset` drops the schema. A remote credential must never be exported in a shell that could run them.
- **Verified (OpenAPI, observed on preview branches only):** `getSiteDatabaseBranch` with `role: "netlifydb_readonly"` returns a read-only credential for an explicitly named branch. It also returns `metadata.deploy` (`id`, `branch`, `context`). Branches have distinct hosts and the same database name.
- **Verified (120 deploys):** every non-`main` deploy with a database branch uses `database_branch_id` equal to its Git branch; production deploys of `main` use `production`. Database branches persist after use (branches from 2026-11-03 still exist).
- **Access limitation:** Agent Runner gets 401 from `listSiteDatabaseBranches`. It can read the ledger and mint read-only credentials for preview branches.
- **Open (blocks the M8 preview rehearsal):** the out-of-band M7 production-ledger write above happened while only preview deploys recorded applying M7. Until it is explained, preview-to-production isolation is supported by documentation and metadata, but not established. The rehearsal verdict is **NO-GO** (runbook gates G1–G6).

## Configuration

| Item | Owner-confirmed | Netlify metadata (verified) | Status |
|---|---|---|---|
| Nine variables (scopes re-check 2026-11-06: **Access limitation**, the environment-variable API returns no entries to Agent Runner; none of the nine is present in the Agent Runner environment) (`HOURVIA_APP_ORIGIN`, `HOURVIA_AUTH_ALLOW_PRODUCTION`, `HOURVIA_AUTH_HASH_KEY`, `HOURVIA_AUTH_LAUNCH_STAGE`, `HOURVIA_AUTH_SMOKE_TEST_EMAILS`, `HOURVIA_EMAIL_DELIVERY_AUTHORIZED`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `SUPABASE_URL`) | Production-only, Functions-scoped | Recreated 2026-11-05 02:06–02:07 UTC. Each has exactly one value in context `production`. Deploy Preview, branch deploy and dev resolve none of them. A newly built Deploy Preview (`6aebe84ee08c78e7856b04a8`) reported all nine absent at runtime. | Resolved for new deploys. Deploys built before 2026-11-05 02:06 UTC kept the earlier values. |
| `SUPABASE_SECRET_KEY` rotated, previous key revoked | Yes | Last updated 2026-11-04 17:14 UTC | Owner-confirmed |
| `HOURVIA_SYNTHETIC_IDENTITY_POLICY`, `HOURVIA_PRODUCTION_DATABASE_EVIDENCE` | n/a | Not set | Correct for the current fail-closed state; both are required before any smoke activation |
| Branch deploys | n/a | All branches build | Not yet aligned with the main-only policy |
| Deploy Previews | n/a | Enabled; untrusted contributors require approval | Not yet aligned with the main-only policy |
| Non-Git production deploys | n/a | Allowed | Owner decision pending |
| Deploy notifications | n/a | GitHub status/checks only; no succeeded/failed/locked email or Slack | Owner decision pending |
| Preview database branches | n/a | About 30 agent and preview database branches persist, each created as a copy of production data (verified 2026-11-08: branches from 2026-11-03 still exist) | Privacy exposure grows once production holds real users; owner decision on deleting stale branches pending |
| Old deploy permalinks | n/a | Public; no password or SSO protection | Exposure remains until restricted or expired (90-day retention) |
| Legacy staging hostname | n/a | Not attached to any site; resolves only through `*.hourvia.livingitsolutions.com` and returns a Netlify 404 | Not serving content; DNS cleanup pending |

The code refuses authentication outside a published production deploy on this site whose stamped identity matches. Previews and branch deploys built after the 2026-11-05 rescoping receive none of the nine variables. Older preview and branch deploys still hold the values they were built with, so the previous Supabase secret key must stay revoked. The temporary diagnostic deploy `6aebe84ee08c78e7856b04a8` should be deleted by the owner.

## Release rules

- **Merging a migration file into `main` applies it to the production database, even while publishing is locked.** The lock gates only which deploy is served. Every production build still runs the migration step against database branch `production`: the locked, unpublished builds `6aee7c60` (PR #20), `6aefca2c` (PR #21) and `6aefd8e1` (PR #22) each carry a `database_migrations` result for `production` (verified from deploy metadata, Sprint 3.0.4). Treat the merge itself as the production database change.
- **M8 promotion needs an explicit owner-approved release window:** a named owner present, a written time window, every M8 evidence gate below closed beforehand, the post-M8 recovery target plan agreed, and nothing else in the same merge. No agent may merge a migration PR.
- **Existing pre-M8 deploys are not valid post-M8 rollback targets.** Once M8 is applied, republishing any deploy built without M8 (including the published `6aebf26c` and the known-good `6aeb5cd4`) produces a migration-history error, as happened with M7 on 2026-11-04. Before the window the owner designates a **post-M8 compatible recovery target**: the deploy built from the promotion merge commit once it is `ready`. Record its ID in the table above. Until then the only recovery is a reviewed forward fix, with authentication staying at 503.
- **Operator SQL on organizations suspends, closes or reactivates one organization per transaction.** Taking two organizations' session locks in one transaction can deadlock with an in-flight organization switch.
- **PostgreSQL deadlock (`40P01`) or serialization (`40001`) errors mean the whole transaction was rolled back.** Re-read the state, confirm nothing changed, retry once, then verify the intended end state (status and session revocation) with a read-only query before reporting success. Never retry blindly in a loop, and never work around the error by changing isolation level (M8 refuses anything other than READ COMMITTED).
- Agent PRs (opened by `netlify-coding[bot]`) need an approving review under the `main` ruleset. Do not merge an agent PR before its independent review.
- Do not republish any deploy built before commit `e33fefc` (PR #15). Pre-M7 deploys conflict with the production ledger.
- **Before any M8 or later migration reaches `main`:**
  1. `netlify db status --branch production --json`, run by the owner, shows exactly M1–M7 in order, with nothing pending, missing or out of order. (That command fetches a production owner credential internally. The credential-free `netlify api listSiteDatabaseMigrations` call above gives the same ledger.)
  2. M7's provenance in production is explained (audit log or Netlify Support), and its applied content is confirmed to match the digest above, or a reviewed read-only catalog check matches the M1–M7 schema.
  3. The new migration has been rehearsed offline and on an isolated preview database branch, and its preconditions refuse to run on any unexpected state. For M8, follow [the M8 preview rehearsal runbook](m8-preview-rehearsal-runbook.md) with the pinned final digest.
  4. The owner-approved release window and post-M8 recovery target above are agreed in writing.
- Authentication activation additionally requires everything in [production pre-launch safeguards](production-prelaunch.md).
