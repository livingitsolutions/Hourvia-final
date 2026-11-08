# M8 Netlify preview rehearsal runbook (Sprint 3.0.6 revision)

**Status: prepared, not executed. Current verdict: NO-GO.** The rehearsal must not start until every gate in [section 4](#4-open-gates-the-rehearsal-may-not-start-until-all-are-closed) is closed. This runbook authorizes nothing by itself.

Running it applies the M8 proposal to two **disposable Netlify preview database branches**, each first created by a no-M8 preflight push. It must never touch the `production` database branch, never fetch a production credential and never use production as a connection test. The account owner runs it, or an operator the owner names in writing, inside an approved window. Agents may prepare evidence, but they must not push rehearsal branches.

| Item | Value |
|---|---|
| Proposal file | `db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql` |
| **Pinned final digest** | `f401b7a3af458749a6078037d67cd284aac1672f0653c4b0540031f9a4e0b532` |
| Baseline | `main` with M1–M7 exactly (digests in `docs/operations-status.md`), reviewed commit recorded at Step 0 |
| M8 verification script | `db/verification/sprint-3.0.5-m8-preview-readonly.sql` (catalog-only, one SELECT in a READ ONLY transaction; tested offline as `netlifydb_readonly`) |
| M7 compatibility checks | Only statements M7-4, M7-5, M7-6, M7-7 and M7-8 of `db/verification/sprint-2.0b-preview-readonly.sql`, run one at a time (see section 1, row V10) |
| Site | `hourvia-tracker` (`48d7a24b-6072-40bc-866f-0d6e43a921ea`) |
| CLI behaviour verified against | `netlify-cli` 27.16.2. Any other version: STOP and re-verify section 1 |

## 1. Verified Netlify CLI and API behaviour (Sprint 3.0.6, 2026-11-08)

"Source" means the installed CLI implementation (`netlify-cli/dist/commands/database/`) or the bundled OpenAPI spec (`@netlify/open-api`). "Observed" means a read-only metadata call or a harmless probe in Agent Runner. No SQL was executed on any Netlify database in this sprint.

| # | Behaviour | Evidence |
|---|---|---|
| V1 | `netlify db connect` has no `--branch` option and never calls the Netlify API. Its target is resolved in this order: (1) the `NETLIFY_DB_URL` environment variable, used verbatim; (2) a connection string persisted by a running local `netlify dev`; (3) otherwise it **starts a local embedded database** in `.netlify/db`. | Source (`db-connect.js`, `util/db-connection.js`); `--help` |
| V2 | The local embedded database started by V1(3) has **no migrations applied**. `netlify dev` starts it without running migrations. | Source (`@netlify/dev` start path) |
| V3 | The checked-out Git branch has **no effect** on `db connect`. `NETLIFY_DB_BRANCH` is also ignored by `db connect`. | Source |
| V4 | An explicit `NETLIFY_DB_URL` fails closed. If it is unreachable, `db connect` errors and does **not** fall back to a local database. | Source; observed (loopback probe: `ECONNREFUSED`, no `.netlify/db` created) |
| V5 | `netlify db status` resolves its target as `--branch`, else `NETLIFY_DB_BRANCH`, else `local`. With a branch, it calls `GET /sites/{site}/database/branch/{branch}` **without a role, which returns a `netlifydb_owner` credential** (redacted in output unless `--show-credentials`). It then reads the ledger from `GET /sites/{site}/database/migrations?branch=…`. A missing branch gives HTTP 404, "No database branch found". | Source; OpenAPI (`role` defaults to `netlifydb_owner`) |
| V6 | `db status --branch` and `db connect` therefore resolve targets **differently**: by branch name through the API, versus environment or local. A `db status` result never proves what `db connect` reached. | Source |
| V7 | The API issues a **read-only credential for an explicitly named branch**: `netlify api getSiteDatabaseBranch` with `branch_id` and `role: "netlifydb_readonly"` (the enum is `netlifydb_owner` \| `netlifydb_readonly`). The response also carries `metadata.deploy` (`id`, `branch`, `context`) naming the deploy bound to that database branch. | OpenAPI; observed on two existing preview branches (credential kept in memory, only booleans printed) |
| V8 | Different database branches have **different hosts but the same database name**. `current_database()` cannot distinguish branches; host and API binding can. | Observed |
| V9 | `netlify api listSiteDatabaseMigrations` with a `branch` returns that branch's ledger (`name`, `applied`) **without fetching any credential**. | OpenAPI; observed on `agent-pins-index-self-checks-d2fe`: M1–M7 applied, nothing else |
| V10 | `db connect --json --query` prints only the **last** row set. `--json` **without** `--query` prints the full connection string, including the password. | Source (`psql-formatter.js`, `db-connect.js`) |
| V11 | `netlify db migrations apply` and `netlify db reset` also honour `NETLIFY_DB_URL`. With a remote owner URL exported, "local" apply would migrate that remote database, and `reset` runs `DROP SCHEMA … CASCADE` on it. | Source |
| V12 | `netlify db migrations pull --branch` with no value uses the current Git branch. It is the only `db` subcommand that reads the Git branch. | Source |
| V13 | In Agent Runner, `NETLIFY_DB_URL` is pre-set to a **read-only credential for the agent session's own preview branch**, byte-identical to the V7 credential for that branch. `NETLIFY_DB_BRANCH` is pre-set to that session branch, which is not `production` and not any rehearsal branch. | Observed (comparison only, no values printed) |
| V14 | The Agent Runner token gets **401** from `listSiteDatabaseBranches`. It can read V7 and V9 for preview branches. | Observed |

### What the earlier `relation "public.workspace_invitations" does not exist` error means

`workspace_invitations` is created by **M1** (`20261103170000_create-auth-foundation.sql`). The database that answered had **no M1**, so it was not an M1–M7 preview branch and not production.

The same session's `db status --json` reported `local` (V5 with no branch variable set). By V1–V2, the unqualified `db connect` almost certainly opened an **empty local embedded database**. This is an inference, not a measurement. It is **not** evidence about M8, and no M8 verification was performed.

**Rule: unqualified `netlify db connect` is never used in this runbook.** The only supported way to run a query against a named preview branch is a V7 read-only credential, passed through `NETLIFY_DB_URL` to a single `netlify db connect` process (section 7).

## 2. Branch and isolation facts

**Verified (deploy metadata, 120 deploys, 2026-10-31 to 2026-11-08):**
- Every deploy of a non-`main` Git branch that has a database branch has `database_branch_id` exactly equal to the Git branch name. That is 69 Deploy Previews and 10 branch deploys, with no exceptions.
- Every production deploy of `main` with a database branch uses `production`.
- Branch deploys run for all branches. Pushing a branch is enough to create its database branch and apply its migrations; no PR is needed.
- Branch deploys and Deploy Previews of the same Git branch share one database branch.
- A new Git branch's first deploy gets its own branch (V8: a distinct host).
- `database_migrations.files` lists only the migrations applied **by that deploy**, as `{name, applied}`. A deploy with nothing new shows `files: []`. A failed migration appears as `database_migrations.error`.
- Five deploys have `database_branch_id: null`: failed or pre-database builds, and one CLI-style diagnostic deploy of `main`. None of them recorded migrations.
- Database branches **persist** after use. Branches from 2026-11-03 still exist. No Git branch has ever been deleted on this repository, so there is no evidence whether deleting a Git branch removes its database branch.

**Verified (Sprint 3.0.4) and documented:** preview branches start as a copy of production, data included. The API's `createSiteDatabaseBranch` also defaults `parent_branch_id` to production. Treat every rehearsal branch as holding **production personal data**.

**Unverified:**
- The exact moment of the copy (first deploy is inferred).
- Whether a name other than `[a-z0-9-]` is normalised.
- What a Git branch literally named `production` would map to.
- Whether a failed database-branch creation could fall back to another branch.
- Whether a GET on a deleted branch returns 404. The CLI source handles 404 as "no branch", so a GET is not expected to create one.

**Unexplained (blocks the rehearsal, gate G1):** M7 entered the **production** ledger between about 13:37 and 15:20 UTC on 2026-11-04. In that window the only deploys that recorded applying M7 were **preview** deploys (`6aeb3529`, `6aeb3681`), and no production deploy has ever recorded applying M7 ([operations status](operations-status.md)). Until this is explained, it cannot be ruled out that migrations from a non-production deploy, or some other out-of-band path, reached production. The no-M8 preflight below can prove the branch-to-database binding, but it cannot exclude this failure mode, because the preflight applies no migration.

## 3. Hard rules (stop immediately if any is violated)

1. **No production.** Never pass `production` to any command, never fetch a credential without `role: netlifydb_readonly`, and never run `netlify db status` or `db connect` against production as a positive or negative test. Never run anything from a checkout of `main` except the Step 0 digest check.
2. **Never run:**
   - `netlify db migrations apply`, `netlify db reset`, `netlify db migrations new`, `netlify db migrations pull` or `netlify db migrations reset`;
   - `netlify db status --show-credentials`, or `netlify db connect --json` without `--query`;
   - `netlify api runSiteDatabaseMigrations`, `createSiteDatabaseBranch`, `resetSiteDatabaseBranch`, `restoreSiteDatabaseSnapshot` or `deleteSiteDatabase`;
   - any hand-written DDL or DML;
   - anything that changes environment variables, publishing, locks or security settings.

   The only deletion is the owner's Step 6 cleanup of the two named rehearsal branches.
3. **Never export `NETLIFY_DB_URL`** or write a credential to a file, `.env`, shell history or evidence. A rehearsal credential lives only in an unexported shell variable and is passed to one `netlify db connect` process at a time (V11). Never run `set -x`.
4. **Only read-only SQL:** the identity query, the M8 script and the five M7 catalog statements, through the section 7 helpers, as `netlifydb_readonly`.
5. **Branch names** match `^rehearsal-m8-[0-9]{8}-(ok|fail)-[a-z0-9]{4}$`, for example `rehearsal-m8-20261110-ok-7f3a`. They are unique, never reused, and never equal to `main`, `production` or any existing Git or database branch name. The success branch `$B` and the rollback branch `$F` are different database branches.
6. **The proposal must equal the pinned digest.** If it doesn't, stop. A new digest needs a new review, and the rehearsal starts again.
7. **No PR, ever,** from a rehearsal branch, and no push of rehearsal commits to any other ref. The deliberately failing copy exists only on `$F`.
8. If any output is unexpected, stop, record it, and escalate. Never fix forward on a rehearsal branch.

## 4. Open gates (the rehearsal may not start until all are closed)

| Gate | Requirement | Owner of the action | Status 2026-11-08 |
|---|---|---|---|
| **G1** | The out-of-band M7 production-ledger write is explained, by the account audit log or Netlify Support, and the explanation rules out a preview or branch deploy writing to `production`. | Account owner | **Open: STOP** |
| **G2** | A reviewed offline test proves that the identity query and the five M7 catalog statements run as `netlifydb_readonly` and give the section 9 values on M7, on M8 and on rolled-back M8. Today only the M8 script is tested under that role. M7-1 and M7-3 read rows the role is denied, and M7-2 uses `information_schema`, which hides those tables from it. | Engineering, next sprint | **Open** |
| **G3** | The owner confirms that neither chosen name exists as a Git branch or database branch (dashboard Project → Database → Branches, or `branch_absent` in section 7). Agent Runner cannot list database branches (V14). | Account owner | Open |
| **G4** | Written approval naming the operator, the window, both branch names, the reviewed `main` commit and who performs cleanup. | Account owner | Open |
| **G5** | The owner confirms they can delete database branches and deploys (dashboard or `deleteSiteDatabaseBranch` / `deleteSiteDeploy`), since rehearsal branches hold production data and do not expire on their own (section 2). | Account owner | Open |
| **G6** | An independent review of this revision. | Reviewer other than its author | Open |

## 5. Production-data protection

- **What is copied.** Each rehearsal database branch is a full copy of production, including member, invitation, session and audit rows. Supabase Auth users are not copied, because they live in Supabase.
- **Preview APIs expose nothing.**
  - The only function, `auth-api`, refuses every context except a published production deploy of this site with a matching build identity. `readServerEnv` returns `context_not_enabled` before any database pool or Supabase client is created. A branch deploy therefore answers 503 on `/api/auth/*`, `/api/admin/*` and `/api/platform/*`, and opens no database connection. Step 3 re-checks this.
  - The nine production variables, including Supabase keys and email authorization, are scoped to production only. Branch deploys built after 2026-11-05 resolve none of them ([operations status](operations-status.md)).
  - The frontend is static.
- **No email or invitation is sent.** Invitations are sent only by `AuthService.invite` through Supabase, which is unreachable outside production (above). M8 contains no notification, network or extension calls. Deploy notifications are GitHub statuses only.
- **No background writer.** There are no scheduled, background or edge functions. The only writes to a rehearsal branch are M8's own: the reviewed ThriveSource entitlement row and its trigger functions, inside the migration.
- **Read paths for people.** Any team member with API access can mint credentials for a preview branch. The owner role can read every copied row. This runbook uses only `netlifydb_readonly`, which M2 and M7 deny on the auth and organization tables. Its queries read the catalog only and return no personal data.
- **Evidence and logs** never contain:
  - credentials, connection strings or database hosts;
  - row contents, email addresses or user IDs;
  - the output of `netlify api getSiteDatabaseBranch` or `listSiteDatabaseBranches`.

  The helpers mask the host and drop connection strings. M8's exception messages contain no row values.
- **Cleanup is part of the rehearsal.** Deleting the two database branches is the only way to remove the copied production data. The rehearsal is not complete until Step 6 confirms both are gone.
- **Residual risks, outside this rehearsal:**
  - About 30 earlier agent and preview database branches already hold production copies and persist.
  - Old deploy permalinks are public. They hold no data, but the failing rehearsal deploy carries a modified migration.
  - Rehearsal branches inherit production data whenever production gains real users. Running the rehearsal before real user data exists minimises exposure.

  These are owner decisions.

## 6. Why the rehearsal is split into preflight and migration pushes

The database branch for a Git branch is created by that branch's first deploy. The rehearsal therefore creates both branches with a **no-M8 preflight push**: an empty commit on the reviewed `main` commit, which applies nothing because M1–M7 are already in the copy. It then proves each binding, read-only role and isolation from the other branch. **Only then** is the migration-triggering commit pushed to the same Git branch. A wrong or missing binding is caught before M8 can run anywhere.

**Limitation:** the preflight proves the binding the platform reports. It cannot prove that a migration push cannot reach production through the unexplained path in section 2. That is why G1 is a STOP gate and not a checklist item.

## 7. Helper functions

Paste the block below into a fresh `bash` shell at the root of a clean checkout. The helpers:
- print booleans and metadata only;
- refuse any branch that is not a rehearsal name;
- fetch only `netlifydb_readonly` credentials;
- never export a credential.

```bash
# --- M8 rehearsal helpers (bash, netlify-cli 27.16.2). Never run `set -x` in this shell. ---
set -o pipefail
SITE=48d7a24b-6072-40bc-866f-0d6e43a921ea
unset NETLIFY_DB_URL NETLIFY_DB_BRANCH   # no inherited database target, ever

# rehearsal_name_ok NAME: refuses anything that is not a rehearsal branch name.
rehearsal_name_ok() {
  [[ "$1" =~ ^rehearsal-m8-[0-9]{8}-(ok|fail)-[a-z0-9]{4}$ ]] || { echo "STOP: '$1' is not a rehearsal branch name" >&2; return 1; }
}

# deploys_of BRANCH: the site's recent deploys of one Git branch, newest first, metadata only.
deploys_of() {
  rehearsal_name_ok "$1" || return 1
  netlify api listSiteDeploys --data "{\"site_id\":\"$SITE\",\"per_page\":50}" | B="$1" node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      for (const d of JSON.parse(s)) if (d.branch === process.env.B)
        console.log(JSON.stringify({ id: d.id, created_at: d.created_at, context: d.context, commit: d.commit_ref, state: d.state,
          database_branch_id: d.database_branch_id, database_migrations: d.database_migrations }));
    });'
}

# ledger_of BRANCH: the platform migration ledger of one database branch (credential-free, V9).
ledger_of() {
  rehearsal_name_ok "$1" || return 1
  netlify api listSiteDatabaseMigrations --data "{\"site_id\":\"$SITE\",\"branch\":\"$1\"}" | node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      for (const m of JSON.parse(s).migrations) console.log((m.applied ? "applied     " : "NOT-APPLIED ") + m.name);
    });'
}

# branch_absent BRANCH: succeeds only if the API answers "Not Found" for the database branch. Any other error is a STOP.
branch_absent() {
  rehearsal_name_ok "$1" || return 1
  # The CLI exits non-zero on 404; `|| true` lets the parser below, not the exit code, decide.
  { netlify api getSiteDatabaseBranch --data "{\"site_id\":\"$SITE\",\"branch_id\":\"$1\",\"role\":\"netlifydb_readonly\"}" 2>&1 || true; } | B="$1" node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      try { JSON.parse(s); console.error("STOP: database branch " + process.env.B + " exists"); process.exit(1); } catch {}
      if (/Not Found/i.test(s)) { console.log("absent: " + process.env.B); process.exit(0); }
      console.error("STOP: unexpected API answer: " + s.replace(/postgres(ql)?:\/\/\S+/g, "<redacted>").trim().split("\n")[0]); process.exit(1);
    });'
}

# ro_url BRANCH DEPLOY_ID[,DEPLOY_ID]: writes the branch's netlifydb_readonly connection string to stdout. Capture it with
# VAR="$(ro_url ...)"; never let it reach the terminal. The identity checks (booleans) go to stderr. Fails unless the API
# binds the database branch to this Git branch and to one of the expected deploys, in a non-production context.
ro_url() {
  rehearsal_name_ok "$1" || return 1
  [[ "$2" =~ ^[0-9a-f]{24}(,[0-9a-f]{24})*$ ]] || { echo "STOP: expected deploy id(s) missing" >&2; return 1; }
  netlify api getSiteDatabaseBranch --data "{\"site_id\":\"$SITE\",\"branch_id\":\"$1\",\"role\":\"netlifydb_readonly\"}" 2>&1 | B="$1" D="$2" node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      let j; try { j = JSON.parse(s); } catch {
        console.error("STOP: API refused: " + s.replace(/postgres(ql)?:\/\/\S+/g, "<redacted>").trim().split("\n")[0]); process.exit(1); }
      const u = new URL(j.connection_string), m = (j.metadata || {}).deploy || {};
      const c = { branch_bound: m.branch === process.env.B, deploy_bound: process.env.D.split(",").includes(m.id),
        context_not_production: m.context === "branch-deploy" || m.context === "deploy-preview",
        readonly_user: decodeURIComponent(u.username) === "netlifydb_readonly" };
      console.error("identity checks for " + process.env.B + ": " + JSON.stringify({ ...c, bound_deploy: m.id || null, context: m.context || null }));
      if (!Object.values(c).every(Boolean)) { console.error("STOP: identity check failed"); process.exit(1); }
      process.stdout.write(j.connection_string);
    });'
}

# same_host URL_A URL_B: prints whether two captured credentials point at the same database host (boolean only).
same_host() {
  URL_A="$1" URL_B="$2" node -e 'const a = new URL(process.env.URL_A).hostname, b = new URL(process.env.URL_B).hostname;
    console.log("same_host: " + (a === b)); process.exit(a === b ? 0 : 1);'
}

# ro_sql URL SQL: one read-only query through `netlify db connect`, its target pinned by NETLIFY_DB_URL for this one
# process only (V1, V4). Masks the host and any connection string in the output.
ro_sql() {
  NETLIFY_DB_URL="$1" netlify db connect --json --query "$2" 2>&1 | U="$1" node -e '
    const h = new URL(process.env.U).hostname; let s = "";
    process.stdin.on("data", d => s += d).on("end", () => {
      for (const l of s.split("\n")) if (!l.startsWith("Connected to "))
        console.log(l.split(h).join("<host>").replace(/postgres(ql)?:\/\/\S+/g, "<redacted-url>"));
    });'
}

# m7_stmt LABEL: one catalog-only statement (M7-4 ... M7-8) from the M7 script, wrapped in a READ ONLY transaction.
m7_stmt() {
  [[ "$1" =~ ^M7-[45678]$ ]] || { echo "STOP: only M7-4 ... M7-8 are catalog-only" >&2; return 1; }
  node -e '
    const s = require("fs").readFileSync("db/verification/sprint-2.0b-preview-readonly.sql", "utf8").split("\n")
      .filter(l => !l.trim().startsWith("--")).join("\n").split(";").map(x => x.trim())
      .filter(x => x.startsWith("SELECT \x27" + process.argv[1] + " "));
    if (s.length !== 1) { console.error("STOP: statement " + process.argv[1] + " not found exactly once"); process.exit(1); }
    console.log("BEGIN TRANSACTION READ ONLY;\n" + s[0] + ";\nROLLBACK;");' "$1"
}

# Identity query: role, read-only transaction, and an M1/M7 Hourvia schema, without reading any row.
IDENTITY_SQL="BEGIN TRANSACTION READ ONLY;
SELECT current_user = 'netlifydb_readonly' AS readonly_user,
       session_user = 'netlifydb_readonly' AS readonly_session,
       current_setting('transaction_read_only') = 'on' AS readonly_transaction,
       NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = 'netlifydb_owner' AND pg_has_role(current_user, r.oid, 'MEMBER')) AS not_owner,
       to_regclass('public.workspace_invitations') IS NOT NULL AS has_m1_schema,
       to_regclass('public.organizations') IS NOT NULL AS has_m7_schema,
       NOT has_table_privilege('public.organizations', 'SELECT') AS readonly_denied_organizations;
ROLLBACK;"

# verify_branch URL: identity query, M8 script and the five M7 catalog statements against one captured credential.
verify_branch() {
  echo "== identity";  ro_sql "$1" "$IDENTITY_SQL" || return 1
  echo "== M8 script"; ro_sql "$1" "$(cat db/verification/sprint-3.0.5-m8-preview-readonly.sql)" || return 1
  for c in M7-4 M7-5 M7-6 M7-7 M7-8; do echo "== $c"; ro_sql "$1" "$(m7_stmt "$c")" || return 1; done
}
```

Expected identity result on every rehearsal branch: every column `true`. Any `false`, or any error, is a STOP.

## 8. Procedure

### Step 0: preconditions (owner)

- [ ] Gates G1–G6 are closed and recorded.
- [ ] Production publishing is still locked on the approved baseline (owner, dashboard). Authentication returns 503 on the canonical domain for `/api/auth/session`, `/api/admin/members` and `/api/platform/overview`.
- [ ] `netlify --version` reports `netlify-cli/27.16.2`. Otherwise STOP and re-verify section 1.
- [ ] A clean checkout of the reviewed `main` commit:
  ```
  git switch main && git pull --ff-only
  git rev-parse HEAD                           # record it as $BASE; must equal the approved commit
  sha256sum db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql   # must equal the pinned digest
  ls netlify/database/migrations/              # exactly the seven M1–M7 files
  git status --short                           # empty
  ```
- [ ] Offline suite and disposable-PostgreSQL rehearsals pass on `$BASE`:
  - `npm run typecheck && npm test`
  - `scripts/rehearsal/platform-grant-rehearsal.sh m7`, then the same script with `m8`
  - `scripts/rehearsal/multi-organization-rehearsal.sh`
  - `scripts/rehearsal/disable-lock-order-rehearsal.sh`
- [ ] Choose the names, paste the section 7 helpers, then:
  ```
  B=rehearsal-m8-<yyyymmdd>-ok-<4 lowercase hex>     # e.g. from: openssl rand -hex 2
  F=rehearsal-m8-<yyyymmdd>-fail-<4 lowercase hex>
  rehearsal_name_ok "$B" && rehearsal_name_ok "$F" && [ "$B" != "$F" ]
  branch_absent "$B" && branch_absent "$F"        # G3: both database branches must not exist yet
  ```

### Step 1: no-M8 preflight (creates and proves both database branches; applies no migration)

For each name in turn (`$B`, then `$F`):

```
git switch main && test "$(git rev-parse HEAD)" = "$BASE"
git switch -c "$B"                                     # repeat with "$F"
git commit --allow-empty -m "REHEARSAL ONLY - DO NOT MERGE: no-M8 preflight"
git push origin "refs/heads/$B:refs/heads/$B"          # explicit refspec: pushes this ref only
```

Wait for the branch deploy to finish, then:

```
deploys_of "$B"                                        # exactly one deploy for this branch
ledger_of "$B"
RO_B="$(ro_url "$B" <preflight deploy id>)" || echo STOP
# for the second preflight: deploys_of "$F"; ledger_of "$F"; RO_F="$(ro_url "$F" <its preflight deploy id>)" || echo STOP
```

All of the following must hold, or **STOP**:
- the deploy has `context` `branch-deploy`, `commit` equal to the preflight commit, `state` `ready`, `database_branch_id` exactly the branch name (not `production`, not `null`), and `database_migrations` `{"files":[]}` with no `error`;
- `ledger_of` lists exactly M1–M7 as `applied`, in repository order, and nothing else;
- `ro_url` reports all four identity checks `true`.

After both preflights:

```
same_host "$RO_B" "$RO_F"     # must print same_host: false (two distinct database branches)
verify_branch "$RO_B"
verify_branch "$RO_F"
```

Expected on both branches before M8: identity all `true`; `M8-0` `true` and `M8-1` … `M8-8` `false`; M7-4 … M7-8 all `true`. Anything else is a STOP. The branch is not in the reviewed M7 state, and M8's preconditions would refuse it.

The branch-to-database binding, read-only role and isolation between `$B` and `$F` are now established, **before** any migration is pushed.

### Step 2: success rehearsal push (`$B` only)

```
git switch "$B"
cp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/
cmp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/20261106120000_multi-organization-memberships.sql
sha256sum netlify/database/migrations/20261106120000_multi-organization-memberships.sql   # must equal the pinned digest
git status --short            # exactly: ?? netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git add netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git commit -m "REHEARSAL ONLY - DO NOT MERGE: M8 on a preview database branch"
git log --oneline "$BASE..HEAD"                        # exactly two commits: preflight and this one
git push origin "refs/heads/$B:refs/heads/$B"          # triggers the branch deploy that applies M8 to database branch $B
```

### Step 3: success verification (`$B`)

```
deploys_of "$B"
ledger_of "$B"
RO_B2="$(ro_url "$B" <M8 deploy id>)" || echo STOP
same_host "$RO_B" "$RO_B2"    # must print same_host: true (same database branch as the preflight)
same_host "$RO_B2" "$RO_F"    # must print same_host: false
verify_branch "$RO_B2"
```

Then check authentication on the M8 deploy's permalink, unauthenticated:

```
for p in /api/auth/session /api/admin/members /api/platform/overview; do curl -s -o /dev/null -w "%{http_code} $p\n" "https://<M8 deploy id>--hourvia-tracker.netlify.app$p"; done
```

The acceptance criteria are in section 9.

### Step 4: rollback rehearsal push (`$F` only, a separate database branch)

This step proves that a failure after the entire M8 body *and* its self-check rolls back everything. It also closes M-3 and risk R6, the platform runner's per-file transaction behaviour. M8 has no top-level `BEGIN`/`COMMIT`, so atomicity depends entirely on the runner.

```
git switch "$F"
git log --oneline "$BASE..HEAD"                        # exactly one commit: the preflight
cp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/
printf '\nDO $$ BEGIN RAISE EXCEPTION %s; END $$;\n' "'rehearsal: deliberate failure after the complete M8 body'" \
  >> netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git diff --no-index db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git status --short            # exactly one untracked file
git add netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git commit -m "REHEARSAL ONLY - DO NOT MERGE: deliberately failing M8 copy"
git push origin "refs/heads/$F:refs/heads/$F"
```

- The diff must show only the appended statement.
- The modified copy exists **only** on `$F`. It is never pushed to another ref, never opened as a PR, never compared against or substituted for the reviewed file, and `$F` is deleted in Step 6 in the same window.
- The repository has no CI. The protection against merging is the absence of a PR, the `main` ruleset (PR plus one approval) and the prompt deletion. The ruleset's bypass actors are unverified, so the owner must not merge or bypass.

### Step 5: rollback verification (`$F`)

```
deploys_of "$F"
ledger_of "$F"
RO_F2="$(ro_url "$F" <preflight deploy id>,<failing deploy id>)" || echo STOP
same_host "$RO_F" "$RO_F2"    # must print same_host: true
same_host "$RO_F2" "$RO_B2"   # must print same_host: false
verify_branch "$RO_F2"
```

A failed deploy may or may not update the branch's bound deploy, so both `$F` deploy IDs are accepted. Record which one was reported.

### Step 6: cleanup (owner; the rehearsal is not complete without it)

```
unset RO_B RO_B2 RO_F RO_F2
git switch main
rehearsal_name_ok "$B" && rehearsal_name_ok "$F" && git push origin --delete "$B" "$F"
git branch -D "$B" "$F"
```

Delete the Git branches first, so no new push can recreate a database branch. Then:

1. The owner deletes database branches `$B` and `$F`, by name, in the dashboard (Project → Database → Branches) or with `netlify api deleteSiteDatabaseBranch --data "{\"site_id\":\"$SITE\",\"branch_id\":\"$B\"}"` (then `$F`), after `rehearsal_name_ok`. **Never delete, reset or restore `production` or any other branch.**
2. `branch_absent "$B" && branch_absent "$F"` must both report `absent`. If deletion leaves anything (state `archived`, a 200 answer, or any other error), STOP and escalate: the copied production data still exists.
3. The owner deletes every rehearsal deploy recorded in Steps 1–5 (dashboard, or `netlify api deleteSiteDeploy` with `site_id` and `deploy_id`). Their permalinks are public, and the `$F` deploy carries a modified migration.
4. Confirm that `main` is unchanged (`git fetch origin && git rev-parse origin/main` equals `$BASE` or a reviewed later commit), that `git ls-tree --name-only origin/main netlify/database/migrations/` lists exactly M1–M7, and that production publishing is still locked.
5. Close the shell.

### Step 7: evidence record

Record the following in `docs/operations-status.md` under a new "M8 preview rehearsal" entry:
- operator, approval reference, date and window;
- `$BASE`, the proposal digest, the CLI version, and all four rehearsal commit SHAs;
- for every rehearsal deploy: ID, `context`, `commit`, `database_branch_id`, `state` and `database_migrations`;
- the `ledger_of` lists;
- the `ro_url` identity booleans and bound deploy IDs;
- the `same_host` results;
- every `verify_branch` row and its value, for both branches, in both phases;
- the three 503 checks;
- cleanup confirmation: Git branches, `branch_absent` results and deleted deploy IDs.

**Never record** credentials, connection strings, hosts, row data, email addresses or raw API output.

## 9. Acceptance criteria

**Success rehearsal (`$B`) passes only if all of these hold:**
- The M8 deploy has `context` `branch-deploy` and `database_branch_id` `$B`, and is `ready`.
- `database_migrations` is `{"files":[{"name":"20261106120000_multi-organization-memberships","applied":true}]}`, with no `error`.
- `ledger_of "$B"` lists M1–M7, then M8, all `applied`.
- `ro_url` checks are all `true`, bound to the M8 deploy. `same_host` matches the preflight and differs from `$F`.
- Identity is all `true`.
- `M8-0` is `false` and `M8-1` … `M8-8` are all `true`.
- M7 catalog statements: `M7-4` `false` (single-organization constraints removed), `M7-5` `true`, `M7-6` `false` (23 functions, not 16), `M7-7` `false` (runtime `organization_id` INSERT), `M7-8` `true`. These values were established on a disposable M1–M8 database in Sprint 3.0.5 as the owner role. G2 must confirm them under `netlifydb_readonly`.
- All three authentication endpoints return 503.

**Rollback rehearsal (`$F`) passes only if all of these hold:**
- The failing deploy fails. `database_migrations.error` names `20261106120000_multi-organization-memberships` and the deliberate message, and `files` does not list M8 as applied.
- `database_branch_id` is `$F`.
- `ledger_of "$F"` lists exactly M1–M7 as `applied`; M8 is absent or `NOT-APPLIED`.
- `ro_url` and `same_host` checks are as in Step 5. Identity is all `true`.
- `M8-0` is `true` and `M8-1` … `M8-8` are all `false`.
- `M7-4` … `M7-8` are all `true`, identical to the Step 1 preflight.

Anything else means the runner did not apply the file atomically, or the target is not what was proven. That is a **promotion blocker**.

**Cleanup passes only if** both Git branches are deleted, `branch_absent` reports both database branches absent, every rehearsal deploy is deleted, `main` still holds exactly M1–M7, and publishing is still locked.

The rehearsal **passes** only if all three pass. It satisfies only the "isolated preview rehearsal" gate. Promotion still needs every other gate in the M8 README and the operations status:
- the owner's production ledger check;
- M7 provenance closure;
- an owner-approved release window;
- a designated post-M8 recovery target.

## 10. STOP conditions

Stop, record and escalate, without retrying or fixing forward, if any of these happens:
- Any gate in section 4 is open, or the CLI version differs.
- A digest, file list, `git status` or commit count differs from what is stated.
- A deploy for a rehearsal branch shows `context` `production`, a `database_branch_id` other than the branch name (including `null` or `production`), an unexpected commit, or more deploys than pushes.
- `ledger_of` shows anything other than the stated list.
- `ro_url` fails any identity check, or `same_host` gives the wrong answer.
- The identity query returns any `false` or an error. Verification results match neither the expected M7 nor the expected M8 pattern.
- A credential, connection string or host appears on screen or in a log. Stop, end the session, and have the owner rotate as Netlify Support advises.
- Any production change is suspected: a production deploy starts, the published deploy changes, or the lock state changes.
- Cleanup cannot be confirmed for either database branch.
- Anyone proposes `db connect` without the section 7 helpers, `db status --branch production`, an owner credential, or a PR from a rehearsal branch.

## 11. Remaining unknowns

| Unknown | Effect | How it closes |
|---|---|---|
| Mechanism of the out-of-band M7 production-ledger write | Isolation cannot be fully established | G1 |
| Whether a failed deploy updates `metadata.deploy` | Step 5 accepts both `$F` deploy IDs | Observed in the rehearsal |
| Whether `listSiteDatabaseMigrations` lists an unapplied M8 after a failed migration | Step 5 accepts absent or `NOT-APPLIED` | Observed in the rehearsal |
| Whether deleting a Git branch deletes its database branch, and whether a deleted branch answers 404 | Step 6 deletes explicitly and requires `branch_absent` | Observed in the rehearsal |
| Exact moment and scope of the production copy into a new branch | Treat every branch as holding production personal data | Netlify documentation or Support |
| Read-only role behaviour of the identity query and the M7 catalog statements | Expected values could differ under `netlifydb_readonly` | G2 |
| Whether a branch host can change between deploys | `same_host` "true" checks would STOP | Observed in the rehearsal (a STOP, not a failure of M8) |
| Ruleset bypass actors on `main` | The owner could merge a rehearsal branch | Owner discipline; no PR is ever opened |

## 12. Owner-only actions and approvals

- Closing G1 (audit log or Netlify Support), G3, G4 and G5, and appointing the G6 reviewer.
- Approving the window and branch names, running or supervising Steps 0–6, deleting database branches and deploys.
- Optionally, as a detective control, comparing the production ledger before Step 2 and after Step 6 with the credential-free `netlify api listSiteDatabaseMigrations --data '{"site_id":"48d7a24b-6072-40bc-866f-0d6e43a921ea","branch":"production"}'`. This is metadata only, with no credential and no SQL. Both lists must be exactly M1–M7. Agents receive 401 for production database metadata and must not attempt it.
- Promotion of M8 is a separate, later decision (M8 README, operations status). This rehearsal never promotes anything.
