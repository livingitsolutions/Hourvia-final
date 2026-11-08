#!/usr/bin/env bash
# DISPOSABLE PostgreSQL 18 rehearsal for the Sprint 3.0.3 member-disable / organization-suspension lock-order fix
# (test-only; never touches Netlify preview or production databases, and applies the M8 proposal only inside the
# disposable cluster it creates).
#
#   bash scripts/rehearsal/disable-lock-order-rehearsal.sh
#
# 1. Downloads pinned PostgreSQL 18.6 server binaries (npm package @embedded-postgres/linux-x64, install scripts
#    disabled) into a new temp directory outside the repository.
# 2. initdb's a brand-new cluster in another new temp directory and starts it with NO TCP listener (Unix socket only,
#    trust auth for local socket connections). No existing database, URL or credential is read.
# 3. Runs server/auth/disable-lock-order.rehearsal.test.ts against it (an M1-M7 template and an M1-M7 + M8 template).
# 4. Always stops the server and deletes the cluster and the binaries, then verifies they are gone.
# Exit code: the test result; 3 if cleanup failed; 2 if PostgreSQL 18 could not be provisioned (BLOCKED).
set -uo pipefail
PG_PKG='@embedded-postgres/linux-x64@18.6.0-beta.19'
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="$(mktemp -d /tmp/hv-lock-pgbin-XXXXXX)"
RUN_DIR="$(mktemp -d /tmp/hv-lock-pg-XXXXXX)"
PGDATA="$RUN_DIR/data"; SOCK="$RUN_DIR/sock"; PORT=$(( 20000 + RANDOM % 20000 ))
mkdir -p "$SOCK"
# Do not inherit any libpq target from the environment.
unset PGHOST PGPORT PGUSER PGDATABASE PGPASSWORD DATABASE_URL

cleanup() {
  local status=0
  if [ -x "$PGBIN/pg_ctl" ] && [ -f "$PGDATA/postmaster.pid" ]; then
    "$PGBIN/pg_ctl" -D "$PGDATA" -m immediate -w stop >/dev/null 2>&1 || { echo "[rehearsal] CLEANUP FAILURE: pg_ctl stop"; status=3; }
  fi
  rm -rf "$RUN_DIR" "$BIN_DIR" || status=3
  if [ -e "$RUN_DIR" ] || [ -e "$BIN_DIR" ]; then echo "[rehearsal] CLEANUP FAILURE: temp directories remain"; status=3; fi
  if [ "$status" -eq 0 ]; then echo "[rehearsal] cleanup: server stopped; cluster $RUN_DIR and binaries $BIN_DIR deleted (verified absent)"; fi
  return $status
}
PGBIN=""
trap 'cleanup; exit 130' INT TERM

( cd "$BIN_DIR" && npm init -y >/dev/null && npm install --no-audit --no-fund --ignore-scripts "$PG_PKG" >/dev/null 2>&1 )
PKG_DIR="$BIN_DIR/node_modules/@embedded-postgres/linux-x64"
PGBIN="$PKG_DIR/native/bin"
# Recreate the package's shared-library symlinks from its data manifest ourselves (its install script is not run).
node -e '
const fs = require("fs"), path = require("path"); const root = path.resolve(process.argv[1]); const lib = path.join(root, "native", "lib") + path.sep;
for (const { source, target } of JSON.parse(fs.readFileSync(path.join(root, "native", "pg-symlinks.json"), "utf8"))) {
  const s = path.resolve(root, source), t = path.resolve(root, target);
  if (!s.startsWith(lib) || !t.startsWith(lib)) throw new Error("symlink outside native/lib: " + target);
  if (!fs.existsSync(t)) fs.symlinkSync(path.relative(path.dirname(t), s), t);
}' "$PKG_DIR" 2>/dev/null || true
if ! "$PGBIN/postgres" --version 2>/dev/null | grep -q 'PostgreSQL) 18\.'; then
  echo "[rehearsal] BLOCKED: PostgreSQL 18 binaries unavailable"; cleanup; exit 2
fi
echo "[rehearsal] server binary: $("$PGBIN/postgres" --version)"
if ! "$PGBIN/initdb" -D "$PGDATA" -U rehearsal_super --auth=trust -E UTF8 --no-instructions >"$RUN_DIR/initdb.log" 2>&1; then
  echo "[rehearsal] BLOCKED: initdb failed"; tail -5 "$RUN_DIR/initdb.log"; cleanup; exit 2
fi
if ! "$PGBIN/pg_ctl" -D "$PGDATA" -l "$RUN_DIR/server.log" -w -o "-c listen_addresses='' -k $SOCK -p $PORT -c fsync=off" start >/dev/null; then
  echo "[rehearsal] BLOCKED: server failed to start"; tail -5 "$RUN_DIR/server.log"; cleanup; exit 2
fi
echo "[rehearsal] disposable cluster: data=$PGDATA socket=$SOCK port=$PORT (no TCP listener)"

cd "$REPO"
HOURVIA_LOCK_ORDER_REHEARSAL=disposable-local-cluster HOURVIA_REHEARSAL_PGSOCKET="$SOCK" HOURVIA_REHEARSAL_PGPORT="$PORT" \
HOURVIA_REHEARSAL_PGDATA="$PGDATA" NETLIFY_DB_URL= NETLIFY_AGENT_RUNNER_DB_CONNECTION_STRING= \
  npx vitest run --testTimeout=60000 server/auth/disable-lock-order.rehearsal.test.ts
TEST_STATUS=$?
cleanup || exit 3
exit $TEST_STATUS
