# M8 Netlify preview rehearsal runbook (Sprint 3.0.5)

**Status: prepared, not executed.** This runbook authorizes nothing by itself. Running it applies the M8 proposal to two **disposable Netlify preview database branches**. It must never touch the `production` database branch. The account owner runs it, or an operator the owner names in writing, inside an approved window. Agents may prepare evidence, but they must not push the rehearsal branches.

| Item | Value |
|---|---|
| Proposal file | `db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql` |
| **Pinned final digest** | `dc5640f445eba246eed207f18f412bc7f07c80d0066c3bdfba722ace40ba1850` |
| Baseline | `main` with M1–M7 exactly (digests in `docs/operations-status.md`) |
| Verification script | `db/verification/sprint-3.0.5-m8-preview-readonly.sql` (read-only, catalog-only, one SELECT) |
| Site | `hourvia-tracker` (`48d7a24b-6072-40bc-866f-0d6e43a921ea`) |

## How preview database branches work here (verified 2026-11-08)

- Netlify creates one database branch per **git branch**, named after the git branch. The branch deploy and the Deploy Preview of that git branch share it. For example, `agent-organization-suspension-4766` was used by both branch deploy `6aefd6d1` and Deploy Preview `6aefd6d5`.
- Branch deploys are currently enabled for **all** branches. **Pushing a branch is enough to apply its migrations to its preview database branch.** No PR is needed, and none should be opened.
- A preview branch starts as a copy of production, data included (risk R2). Treat its contents as production personal data.
- Only `main` builds against database branch `production`. **Never** push the rehearsal changes to `main`, and never open a PR from a rehearsal branch.

## Hard rules (stop immediately if any is violated)

1. The CLI never receives `--branch production`, and nothing is run from a checkout of `main`.
2. These commands are never run: `netlify db migrations apply`, `netlify db reset`, `netlify db migrations new`, `netlify db migrations pull`. Also never run a hand-written DDL or DML statement, and nothing that changes environment variables, publishing or locks.
3. The only SQL is the read-only verification scripts, through the CLI's `netlifydb_readonly` credential.
4. Rehearsal git branch names start with `rehearsal-m8-`, are unique, and are never reused. A database branch whose rehearsal has finished is never reused.
5. The proposal must equal the pinned digest. If it doesn't, stop. A new digest needs a new review, and the rehearsal starts again.
6. If any output is unexpected, stop, record it, and escalate. Never fix forward on a rehearsal branch.

## Step 0: preconditions (owner)

- [ ] Written approval for this rehearsal, recording who runs it, when, and the two branch names `rehearsal-m8-<yyyymmdd>-ok` and `rehearsal-m8-<yyyymmdd>-fail`.
- [ ] Production publishing is still locked on the approved baseline. Authentication returns 503 on the canonical domain.
- [ ] A clean checkout of the reviewed commit on `main`:
  ```
  git rev-parse HEAD                     # record it
  sha256sum db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql
  ```
  The digest must equal the pinned value above.
- [ ] Offline suite and disposable-PostgreSQL rehearsals pass on that commit:
  - `npm run typecheck && npm test`
  - `scripts/rehearsal/platform-grant-rehearsal.sh m7`, then the same script with `m8`
  - `scripts/rehearsal/multi-organization-rehearsal.sh`
  - `scripts/rehearsal/disable-lock-order-rehearsal.sh`

## Step 1: success rehearsal branch (applies M8 to its own preview database branch)

```
B=rehearsal-m8-<yyyymmdd>-ok
git switch -c "$B"            # from the reviewed main commit
cp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/
cmp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/20261106120000_multi-organization-memberships.sql
sha256sum netlify/database/migrations/20261106120000_multi-organization-memberships.sql   # must equal the pinned digest
git status --short            # exactly one new file, nothing else
git commit -m "REHEARSAL ONLY - DO NOT MERGE: M8 on a preview database branch"
git push origin "$B"          # this triggers the branch deploy, which applies M8 to database branch "$B"
```

Expected: one added file, no other change, no PR.

## Step 2: confirm preview database branch identity (before any query)

Find the branch deploy for `$B`. These commands read metadata only; print only the fields shown.

```
netlify api listSiteDeploys --data '{"site_id":"48d7a24b-6072-40bc-866f-0d6e43a921ea","per_page":20}' \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const d of JSON.parse(s))if(d.branch===process.argv[1])console.log(d.id,d.context,d.database_branch_id,d.state,JSON.stringify(d.database_migrations))})' "$B"
```

All of the following must hold. If any doesn't, **stop**:

- `context` is `branch-deploy` (or `deploy-preview`). It is **never** `production`.
- `database_branch_id` is exactly `$B`. It is **not** `production`, and not any other existing branch.
- The deploy's commit is the rehearsal commit, not a `main` commit.

Then, from the rehearsal checkout, with the branch named explicitly:

```
netlify db status --branch "$B" --json
```

- `target` is exactly `$B`.
- `applied` lists M1–M7 in repository order, then `20261106120000_multi-organization-memberships`.
- `pending`, `missingOnDisk` and `outOfOrder` are all empty.

Finally, as a positive control that production is **not** reachable from this session, run `netlify db status --branch production --json`. It should be **refused** for a non-owner CLI token. If the operator's token *can* read production, do **not** run that command; record instead that the identity check relied on `target` and `database_branch_id`.

## Step 3: deploy evidence

From the branch deploy record (`netlify api getDeploy --data '{"deploy_id":"<id>"}'`, filtered to `state`, `database_branch_id`, `database_migrations` and `summary`):

- `database_migrations.files` contains `{"name":"20261106120000_multi-organization-memberships","applied":true}`, and there is no `error`.
- `state` is `ready`.
- Authentication on the branch deploy URL still returns 503 for `/api/auth/session`, `/api/admin/members` and `/api/platform/overview`.

## Step 4: read-only catalog verification

Connect with a target confirmed in Step 2. If the CLI cannot be pinned to `$B` for `connect`, run from the rehearsal checkout. Before running the script, use `SELECT current_database(), current_user` to confirm `current_user` is `netlifydb_readonly`.

```
netlify db connect --json --query "$(cat db/verification/sprint-3.0.5-m8-preview-readonly.sql)"
```

Expected:

| Check | Expected |
|---|---|
| `M8-0 M7 state (no M8 object)` | `false` |
| `M8-1` … `M8-8` | all `true` |

Also run `db/verification/sprint-2.0b-preview-readonly.sql` and record every row. On M8, exactly the three M7 checks that M8 intentionally changes are expected to be **false**: `M7-4` (single-organization constraints removed), `M7-6` (23 functions instead of 16) and `M7-7` (runtime `organization_id` INSERT). `M7-1`, `M7-2`, `M7-3`, `M7-5` and `M7-8` must be `true`. This combination was verified on a disposable M1–M8 database in Sprint 3.0.5.

## Step 5: atomic-rollback rehearsal (separate, fresh preview database branch)

This step proves that a failure anywhere in the file, here after the entire M8 body *and* its self-check, rolls back everything. It also closes M-3 and risk R6, the production runner's per-file transaction behaviour.

```
F=rehearsal-m8-<yyyymmdd>-fail
git switch main && git switch -c "$F"
cp db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/
printf '\nDO $$ BEGIN RAISE EXCEPTION %s; END $$;\n' "'rehearsal: deliberate failure after the complete M8 body'" \
  >> netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git diff --no-index --stat db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql netlify/database/migrations/20261106120000_multi-organization-memberships.sql
git commit -am "REHEARSAL ONLY - DO NOT MERGE: deliberately failing M8 copy" && git push origin "$F"
```

The diff must show only the appended statement. This modified copy exists **only** on branch `$F`. It must never be merged, and must never be compared against or substituted for the reviewed file.

Repeat the Step 2 identity checks for `$F`. Then expect:

- The branch deploy **fails**. `database_migrations.error` names `20261106120000_multi-organization-memberships` and the deliberate message.
- `netlify db status --branch "$F" --json` lists exactly M1–M7 as applied, with M8 **pending** or not applied.
- `sprint-3.0.5-m8-preview-readonly.sql`: `M8-0` is `true`, and `M8-1` … `M8-8` are all `false`.
- `sprint-2.0b-preview-readonly.sql`: every row is `true`, meaning the M7 schema is exactly intact.

Anything else means the runner did not apply the file atomically. That is a **promotion blocker**: stop and escalate.

## Step 6: cleanup

1. Delete both remote git branches: `git push origin --delete "$B" "$F"`. Delete the local branches too.
2. In the Netlify dashboard (Project → Database → Branches), confirm the database branches `$B` and `$F` are deleted. If deleting the git branch does not remove them, the owner deletes them there. **Never delete or reset `production`.**
3. Delete the two rehearsal deploys, or let them expire. Their permalinks are public and the failing one carries a modified migration.
4. Confirm `main` is unchanged, `netlify/database/migrations/` on `main` still holds exactly M1–M7, and production publishing is still locked.

## Step 7: evidence record

Record the following in `docs/operations-status.md` under a new "M8 preview rehearsal" entry, without credentials or connection strings:

- operator, approval reference, date and window;
- reviewed `main` commit, proposal digest, and both rehearsal commit SHAs;
- for each branch: deploy ID, `context`, `database_branch_id`, `state`, and the `database_migrations` result;
- the `netlify db status --branch <b> --json` lists (names only);
- every verification row and its value for both scripts on both branches;
- cleanup confirmation: git branches, database branches and deploys.

The rehearsal **passes** only if Steps 2–6 all match their expectations. It satisfies only the "isolated preview rehearsal" gate. Promotion still needs every other gate in the M8 README and the operations status, including the owner's production ledger check, M7 provenance closure, an owner-approved release window and a designated post-M8 recovery target.
