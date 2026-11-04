#!/usr/bin/env bash
# Sprint 2.0B legacy-compatibility rehearsal (test-only; embedded PGlite; no Netlify database, no network, no credentials).
#
#   bash scripts/rehearsal/legacy-compat-m7.sh [baseline-commit]
#
# 1. Exports the deployed application at the baseline commit (default 799f042) with read-only `git show` into a new
#    temp directory outside the repository.
# 2. Adds the M7 migration from the working tree, and patches ONLY the baseline test harness so that every database it
#    builds also has M7 applied (after 20261104160000, before any test runs).
# 3. Runs the baseline's own automated test suite: the deployed store, service and HTTP code against an M7 database.
# 4. Deletes the temp directory.
# Expected: every baseline test passes, except two baseline tests that pin the PRE-M7 catalog by design: the
# migration-file list (six files) and the exact hourvia_* function count (15; M7 adds hourvia_guard_organization).
# Both are excluded explicitly, and the exclusions are printed. Their M7 equivalents live in organization-foundation.test.ts.
set -uo pipefail
BASE="${1:-799f042}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/hv-legacy-XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
cd "$REPO"
git cat-file -e "$BASE^{commit}" || { echo "baseline $BASE not found"; exit 2; }
# File list from the tracked index (git ls-tree is unavailable in some sandboxes); content always from the baseline commit.
# Files that do not exist at the baseline are skipped, so nothing from the working tree leaks into the export.
git ls-files | while read -r f; do
  if git cat-file -e "$BASE:$f" 2>/dev/null; then mkdir -p "$WORK/$(dirname "$f")"; git show "$BASE:$f" > "$WORK/$f"; fi
done
[ -f "$WORK/server/auth/store-postgres.ts" ] || { echo "baseline export failed"; exit 2; }
cp netlify/database/migrations/20261104170000_organizations-expand.sql "$WORK/netlify/database/migrations/"
ln -s "$REPO/node_modules" "$WORK/node_modules"
H="$WORK/server/auth/testing/harness.ts"
python3 -I - "$H" <<'PY' || { echo "could not patch baseline harness"; exit 2; }
import sys
p = sys.argv[1]; s = open(p).read()
anchor = "      if (options.searchPathFix !== false) await applyMigration(pg, SEARCH_PATH_SQL);"
assert s.count(anchor) == 1, 'harness anchor not found'
s = s.replace(anchor, "      if (options.searchPathFix !== false) { await applyMigration(pg, SEARCH_PATH_SQL); await applyMigration(pg, migration('20261104170000_organizations-expand.sql')); }")
open(p, 'w').write(s)
PY
cd "$WORK"
EXCLUDE='keeps the applied migrations first and in order|preserves signatures, SECURITY DEFINER flags, ownership and EXECUTE grants'
echo "baseline: $BASE; M7 sha256: $(sha256sum netlify/database/migrations/20261104170000_organizations-expand.sql | cut -d' ' -f1)"
echo "excluded baseline tests (pin the pre-M7 catalog): $EXCLUDE"
npx vitest run --testTimeout=60000 --testNamePattern="^(?!.*(${EXCLUDE})).*$"
STATUS=$?
echo "legacy-compat exit code: $STATUS"
exit $STATUS
