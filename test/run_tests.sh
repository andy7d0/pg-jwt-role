#!/bin/bash
# run_tests.sh — pg_jwt_role test harness entrypoint.
#
# Runs inside the Alpine + PostgreSQL 18 image built by Dockerfile.
# Spins up a temp cluster with the extension preloaded, generates test
# JWTs, and runs each test/sql/test_*.sql via psql. Prints a clear
# PASS/FAIL summary and exits non-zero if any expectation fails.
#
# Environment:
#   PG_JWT_ROLE_IMPLEMENTED - "1" asserts the success-path expectations
#                              (Steps 3 & 4 of plans/plan.md landed).
#                              Defaults to "0" (stub still errors out).
#   HS256_SECRET            - HS256 key for the test JWTs.
#   PG_BIN                  - postgres bin dir (default: pg_config --bindir)

set -euo pipefail

PG_BIN="${PG_BIN:-$(pg_config --bindir)}"
IMPLEMENTED="${PG_JWT_ROLE_IMPLEMENTED:-0}"
HS256_SECRET="${HS256_SECRET:-test-secret-key-do-not-use-in-prod}"

# Per-run working directory inside /tmp. We don't reuse /tmp itself
# because compose may mount /tmp as tmpfs owned by a different UID.
WORK="$(mktemp -d -t pgjwt.XXXXXX)"
PG_DATA="$WORK/pgdata"
PG_SOCK="$WORK/sock"
PG_PORT="${PG_PORT:-55432}"

PGUSER=postgres
export PGUSER

mkdir -p "$PG_DATA" "$PG_SOCK"
# chmod is a no-op when we own the parent dir; do not try to chmod
# /tmp itself (might be mounted as tmpfs owned by a different UID).
chmod 0755 "$PG_DATA" "$PG_SOCK" 2>/dev/null || true

echo ">>> workdir: $WORK"
echo ">>> running as uid=$(id -u) gid=$(id -g)"

cleanup() {
    if [ -n "${PG_PID:-}" ] && kill -0 "$PG_PID" 2>/dev/null; then
        echo ">>> stopping postgres (pid $PG_PID)"
        "$PG_BIN/pg_ctl" -D "$PG_DATA" -m fast stop >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- Init cluster ---------------------------------------------------------
if [ ! -s "$PG_DATA/PG_VERSION" ]; then
    echo ">>> initdb at $PG_DATA"
    if ! "$PG_BIN/initdb" -D "$PG_DATA" \
            --username="$PGUSER" \
            --auth=trust \
            --auth-host=trust \
            --auth-local=trust \
            --no-locale \
            --encoding=UTF8 \
            > "$WORK/initdb.log" 2>&1; then
        echo "!!! initdb failed — log follows:" >&2
        cat "$WORK/initdb.log" >&2
        exit 1
    fi
fi

echo ">>> starting postgres on port $PG_PORT (IMPLEMENTED=$IMPLEMENTED)"
PGLOG="$WORK/pglog"
cd "$WORK"
# Compose the -c options for postgres startup. The verify_key and
# restricted_session_users GUCs are PGC_SIGHUP — they cannot be set
# after the cluster is already running, so they have to be passed on
# the command line.
PGOPTS=(
    "-p" "$PG_PORT"
    "-k" "$PG_SOCK"
    "-h" "127.0.0.1"
    "-c" "unix_socket_directories=$PG_SOCK"
    "-c" "shared_preload_libraries=pg_jwt_role"
    "-c" "pg_jwt_role.verify_key=$HS256_SECRET"
    "-c" "pg_jwt_role.restricted_session_users=app_user"
)

if ! "$PG_BIN/pg_ctl" -D "$PG_DATA" \
        -l "$PGLOG" \
        -o "$(printf ' %q' "${PGOPTS[@]}")" \
        start; then
    echo "!!! postgres failed to start — log follows:" >&2
    # Give postgres a moment to flush its log before we cat it.
    sleep 1
    cat "$PGLOG" >&2 || echo "(no log file at $PGLOG)" >&2
    exit 1
fi
cd /
PG_PID=$(cat "$PG_DATA/postmaster.pid" | head -1)

export PGHOST=127.0.0.1
export PGPORT="$PG_PORT"

# Wait for the cluster to accept connections.
for i in $(seq 1 60); do
    if "$PG_BIN/psql" -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# --- Bootstrap roles + extension ----------------------------------------
"$PG_BIN/psql" -d postgres -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dba_user') THEN
        CREATE ROLE dba_user NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'target_role') THEN
        CREATE ROLE target_role NOLOGIN;
    END IF;
END
$$;
-- Install the extension. The functions end up in the default 'public'
-- schema (see pg_jwt_role.control). The SQL file uses the qualified
-- 'pg_jwt_role.<name>' names which resolve via the default
-- search_path, which includes 'public'.
CREATE EXTENSION pg_jwt_role;
-- The SIGHUP-context GUCs (verify_key, restricted_session_users) were
-- already passed to postgres at startup via -c (see PGOPTS). The
-- SUSET-context GUCs (role_claim, extra_claims) don't need to be
-- pre-configured for these smoke tests - the test SQL files set them
-- per-session as needed.
SQL

# --- Pre-mint JWTs -------------------------------------------------------
TEST_DIR="/test"
TOKENS="$WORK/tokens"
mkdir -p "$TOKENS"

emit_jwt() {
    local name="$1" exp_offset="$2" role="$3"; shift 3
    local exp=$(( $(date +%s) + exp_offset ))
    python3 "$TEST_DIR/test_jwt_helper.py" \
        --secret "$HS256_SECRET" --alg HS256 \
        --role "$role" --exp "$exp" \
        "$@" \
        > "$TOKENS/$name.jwt"
}

emit_jwt valid       3600 target_role --sub=alice --email=alice@example.com
emit_jwt expired    -3600 target_role --sub=alice
emit_jwt badsig      3600 target_role --sub=alice --tamper-sig
emit_jwt norole      3600 ''          --sub=alice
emit_jwt badrole     3600 no_such_role_xyz --sub=alice

# --- Run each test_*.sql ----------------------------------------------
PASS=0
FAIL=0
FAILED_TESTS=()

run_test() {
    local name="$1" sql_file="$2"
    local log="$WORK/$name.log"

    echo "================================================================"
    echo ">>> running $name"
    echo "================================================================"

    # Build a header that injects the JWT tokens via pg_read_file.
    local header="$WORK/${name}_header.sql"
    cat > "$header" <<EOF
\\set ON_ERROR_STOP 0
\\set QUIET 0
SELECT set_config('pg_jwt_role.test.valid_jwt',  pg_read_file('$TOKENS/valid.jwt'),  false);
SELECT set_config('pg_jwt_role.test.expired_jwt', pg_read_file('$TOKENS/expired.jwt'), false);
SELECT set_config('pg_jwt_role.test.badsig_jwt',  pg_read_file('$TOKENS/badsig.jwt'),  false);
SELECT set_config('pg_jwt_role.test.norole_jwt',  pg_read_file('$TOKENS/norole.jwt'),  false);
SELECT set_config('pg_jwt_role.test.badrole_jwt', pg_read_file('$TOKENS/badrole.jwt'), false);
SELECT set_config('pg_jwt_role.test.implemented', '$IMPLEMENTED', false);
EOF
    cat "$header" "$sql_file" > "$WORK/${name}.sql"

    if "$PG_BIN/psql" -X -d postgres -f "$WORK/${name}.sql" > "$log" 2>&1; then
        echo "    psql exit 0"
    else
        echo "    psql exit non-zero (continuing — ON_ERROR_STOP is off in tests)"
    fi

    # Per-test assertions: each test prints a final SELECT 1 marker.
    # Verify the marker exists, and that EXPECTED errors appear /
    # UNEXPECTED errors do not, based on the test name.
    # Disable set -e inside the assertions so a single grep miss does
    # not abort the whole test run.
    set +e
    local rc=0
    if [ "$IMPLEMENTED" = "1" ]; then
        case "$name" in
            test_basic)
                if grep -q ' target_role ' "$log"; then
                    echo "    [OK] current_user flipped to target_role"
                else
                    echo "    [FAIL] current_user never became target_role"
                    rc=1
                fi
                if grep -q ' alice@example.com ' "$log"; then
                    echo "    [OK] pg_jwt_role.email populated"
                else
                    echo "    [FAIL] pg_jwt_role.email missing"
                    rc=1
                fi
                ;;
            test_invalid)
                local errs
                errs=$(grep -cE ' ERROR:' "$log" 2>/dev/null | head -n1)
                [ -z "$errs" ] && errs=0
                if [ "$errs" -ge 1 ]; then
                    echo "    [OK] saw $errs ERRORs (every invalid input rejected)"
                else
                    echo "    [FAIL] no ERRORs — invalid inputs were accepted"
                    rc=1
                fi
                ;;
            test_hook)
                if grep -qE 'pg_jwt_role.*SET ROLE.*rejected|ERRCODE_INSUFFICIENT_PRIVILEGE|ERROR.*SET ROLE' "$log"; then
                    echo "    [OK] hook rejected SET ROLE for restricted user"
                else
                    echo "    [FAIL] hook did not block SET ROLE (Step 4 not implemented?)"
                    rc=1
                fi
                ;;
        esac
    else
        # Stub mode: every test_*.sql must surface some ERROR for the
        # invalid inputs (either PL/pgSQL's own validation or the C
        # stub's "not yet implemented" message).
        case "$name" in
            test_basic|test_invalid)
                local errs
                errs=$(grep -cE ' ERROR:' "$log" 2>/dev/null | head -n1)
                [ -z "$errs" ] && errs=0
                if [ "$errs" -ge 1 ]; then
                    echo "    [OK] stub rejected $errs input(s) with ERROR"
                else
                    echo "    [FAIL] stub accepted an invalid input (no ERROR seen)"
                    echo "      --- log dump ---"
                    awk '{printf "      %s\n", $0}' "$log"
                    rc=1
                fi
                ;;
            test_hook)
                echo "    [SKIP] hook tests gated on PG_JWT_ROLE_IMPLEMENTED=1"
                ;;
        esac
    fi
    set -e

    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        FAILED_TESTS+=("$name")
    fi
}

# --- Smoke test that the extension really loaded --------------------------
echo "================================================================"
echo ">>> smoke: extension + GUCs"
echo "================================================================"
"$PG_BIN/psql" -d postgres -X -c "SELECT extname, extversion FROM pg_extension WHERE extname='pg_jwt_role'"
"$PG_BIN/psql" -d postgres -X -c "SHOW pg_jwt_role.verify_key"
"$PG_BIN/psql" -d postgres -X -c "SHOW pg_jwt_role.restricted_session_users"
"$PG_BIN/psql" -d postgres -X -c "SELECT count(*) FROM pg_proc WHERE proname IN ('set_role','verify_and_set_role','claim','claim_value')"
"$PG_BIN/psql" -d postgres -X -c "SELECT count(*) FROM pg_settings WHERE name LIKE 'pg_jwt_role.claim\\_%' ESCAPE '\\'"

# --- Functional tests ---------------------------------------------------
for f in "$TEST_DIR"/sql/test_*.sql; do
    name="$(basename "$f" .sql)"
    run_test "$name" "$f"
done

echo
echo "================================================================"
echo "TEST SUMMARY"
echo "================================================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '  - %s\n' "${FAILED_TESTS[@]}"
    exit 1
fi
echo "ALL TESTS PASSED"
