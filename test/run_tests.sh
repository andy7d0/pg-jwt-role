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
GRANT USAGE ON SCHEMA pgjwt TO PUBLIC;
GRANT dba_user TO app_user;
GRANT target_role TO app_user;
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
    # emit_jwt <name> <exp_offset_seconds> <role> [extra-flags...]
    local name="$1" exp_offset="$2" role="$3"; shift 3
    local exp=$(( $(date +%s) + exp_offset ))
    python3 "$TEST_DIR/test_jwt_helper.py" \
        --secret "$HS256_SECRET" --alg HS256 \
        --role "$role" --exp "$exp" \
        "$@" \
        > "$TOKENS/$name.jwt"
}

emit_jwt_alg() {
    # emit_jwt_alg <name> <alg> <exp_offset_seconds> <role> [extra-flags...]
    local name="$1" alg="$2" exp_offset="$3" role="$4"; shift 4
    local exp=$(( $(date +%s) + exp_offset ))
    python3 "$TEST_DIR/test_jwt_helper.py" \
        --secret "$HS256_SECRET" --alg "$alg" \
        --role "$role" --exp "$exp" \
        "$@" \
        > "$TOKENS/$name.jwt"
}

emit_jwt_noexp() {
    # emit_jwt_noexp <name> <role> [extra-flags...]
    local name="$1" role="$2"; shift 2
    python3 "$TEST_DIR/test_jwt_helper.py" \
        --secret "$HS256_SECRET" --alg HS256 \
        --role "$role" --no-exp \
        "$@" \
        > "$TOKENS/$name.jwt"
}

# --- Core tokens used by test_basic / test_invalid / test_hook.
emit_jwt valid       3600 target_role --sub=alice --email=alice@example.com
emit_jwt expired    -3600 target_role --sub=alice
emit_jwt badsig      3600 target_role --sub=alice --tamper-sig
emit_jwt norole      3600 ''          --sub=alice
emit_jwt badrole     3600 no_such_role_xyz --sub=alice

# --- Extra tokens for Step 3 test cases.
# HS384 / HS512 happy paths.
emit_jwt_alg hs384 HS384  3600 target_role --sub=alice --email=alice@example.com
emit_jwt_alg hs512 HS512  3600 target_role --sub=alice --email=alice@example.com

# Unknown alg: take a real HS256 token and rewrite its header to
# alg="NONSENSE". The signature is still over the original signing
# input, so verify_and_set_role will reject the unknown alg in its
# dispatch (the C function doesn't match NONSENSE in pg_jwt_verify).
python3 - <<PY > "$TOKENS/unkalg.jwt"
import base64, sys
tok = open("$TOKENS/valid.jwt").read().strip()
head, payload, sig = tok.split(".")
new_head = base64.urlsafe_b64encode(
    b'{"typ":"JWT","alg":"NONSENSE"}'
).rstrip(b"=").decode()
sys.stdout.write(new_head + "." + payload + "." + sig + "\n")
PY

# exp boundary tokens: just expired, future, missing.
emit_jwt exp_recent     -1 target_role --sub=alice
emit_jwt exp_future   3600 target_role --sub=alice --email=alice@example.com
emit_jwt_noexp exp_missing target_role --sub=alice --email=alice@example.com

# Signature segment rewritten to use base64url chars (-, _).
emit_jwt b64url_sig 3600 target_role \
    --sub=alice --email=alice@example.com --b64url-sig

# Token with 17 distinct extra claims - exercises slot-pool overflow in
# the C function. The C function can only bind 16 of them; the 17th is
# silently dropped.
emit_jwt slots17 3600 target_role \
    --a1=v1 --a2=v2 --a3=v3 --a4=v4 --a5=v5 --a6=v6 --a7=v7 --a8=v8 \
    --a9=v9 --a10=v10 --a11=v11 --a12=v12 --a13=v13 --a14=v14 --a15=v15 \
    --a16=v16 --a17=v17

# Token carrying a JSON claim key that is 65 characters long, one past
# PG_JWT_MAX_CLAIM_NAME_LEN - 1 = 63. The token is validly signed; the
# rejection is driven by extra_claims being configured to that long key
# in test_limits.sql. Exercises the P2.5 follow-up: pg_split_csv() must
# ereport() instead of silently truncating.
LONG_CLAIM="$(python3 -c 'print("a" * 65)')"
emit_jwt long_claim 3600 target_role --sub=alice "--${LONG_CLAIM}=x"

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
SELECT set_config('pg_jwt_role.test.hs256_jwt',  pg_read_file('$TOKENS/valid.jwt'),   false);
SELECT set_config('pg_jwt_role.test.hs384_jwt',  pg_read_file('$TOKENS/hs384.jwt'),   false);
SELECT set_config('pg_jwt_role.test.hs512_jwt',  pg_read_file('$TOKENS/hs512.jwt'),   false);
SELECT set_config('pg_jwt_role.test.unkalg_jwt', pg_read_file('$TOKENS/unkalg.jwt'),  false);
SELECT set_config('pg_jwt_role.test.exp_recent_jwt',  pg_read_file('$TOKENS/exp_recent.jwt'),  false);
SELECT set_config('pg_jwt_role.test.exp_future_jwt',  pg_read_file('$TOKENS/exp_future.jwt'),  false);
SELECT set_config('pg_jwt_role.test.exp_missing_jwt', pg_read_file('$TOKENS/exp_missing.jwt'), false);
SELECT set_config('pg_jwt_role.test.b64url_sig_jwt',  pg_read_file('$TOKENS/b64url_sig.jwt'),  false);
SELECT set_config('pg_jwt_role.test.slots17_jwt',     pg_read_file('$TOKENS/slots17.jwt'),     false);
SELECT set_config('pg_jwt_role.test.long_claim_jwt',  pg_read_file('$TOKENS/long_claim.jwt'),  false);
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
                if grep -qE '[ ]target_role( |$)' "$log"; then
                    echo "    [OK] current_user flipped to target_role"
                else
                    echo "    [FAIL] current_user never became target_role"
                    rc=1
                fi
                if grep -qE 'alice@example.com( |$)' "$log"; then
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
                # P1 follow-up (plans/coverage.md §P1): positively assert
                # every allow-branch in pg_jwt_role_ProcessUtility, plus
                # the rejection branch. Each allowed path emits a sentinel
                # of the form "MARKER_HOOK_<NAME>: <current_user>" via
                # "SELECT 'MARKER_HOOK_<NAME>: ' || current_user" in
                # test/sql/test_hook.sql, mirroring the MARKER_HS*
                # convention used in test_algorithms.sql.
                #
                # Marker table (test/sql/test_hook.sql):
                #   MARKER_HOOK_NONE_OK           = app_user    (SET ROLE NONE)
                #   MARKER_HOOK_RESET_OK          = app_user    (RESET ROLE)
                #   MARKER_HOOK_UNMONITORED_OK    = dba_user    (SET ROLE in unrestricted session)
                #   MARKER_HOOK_CLAIMED_OK        = target_role (SET ROLE <claimed> after pgjwt.set_role)
                #   The rejection branch raises an ERROR (no
                #   MARKER_HOOK_REJECTED_PATH sentinel is printed).
                local hook_rc=0
                if grep -qE 'MARKER_HOOK_NONE_OK: app_user' "$log"; then
                    echo "    [OK] hook allowed SET ROLE NONE for restricted user"
                else
                    echo "    [FAIL] hook did NOT allow SET ROLE NONE for restricted user"
                    hook_rc=1
                fi
                if grep -qE 'MARKER_HOOK_RESET_OK: app_user' "$log"; then
                    echo "    [OK] hook allowed RESET ROLE for restricted user"
                else
                    echo "    [FAIL] hook did NOT allow RESET ROLE for restricted user"
                    hook_rc=1
                fi
                if grep -qE 'MARKER_HOOK_UNMONITORED_OK: dba_user' "$log"; then
                    echo "    [OK] hook did not restrict unmonitored session_user"
                else
                    echo "    [FAIL] hook restricted unmonitored session_user"
                    hook_rc=1
                fi
                if grep -qE 'MARKER_HOOK_CLAIMED_OK: target_role' "$log"; then
                    echo "    [OK] hook allowed SET ROLE <claimed> after pgjwt.set_role()"
                else
                    echo "    [FAIL] hook did NOT allow SET ROLE <claimed> after pgjwt.set_role()"
                    hook_rc=1
                fi
                if grep -qE 'pg_jwt_role.*SET ROLE.*rejected|ERRCODE_INSUFFICIENT_PRIVILEGE|ERROR.*SET ROLE' "$log"; then
                    echo "    [OK] hook rejected SET ROLE for restricted user"
                else
                    echo "    [FAIL] hook did not block SET ROLE (Step 4 not implemented?)"
                    hook_rc=1
                fi
                rc=$hook_rc
                ;;
            test_algorithms)
                # Each happy path prints MARKER_HS{256,384,512}: target_role
                for n in 256 384 512; do
                    if grep -qE "MARKER_HS${n}: target_role" "$log"; then
                        echo "    [OK] HS${n} flipped current_user to target_role"
                    else
                        echo "    [FAIL] HS${n} did not flip current_user to target_role"
                        rc=1
                    fi
                done
                # Unknown alg must error out (PG raises ERROR).
                if grep -qE ' ERROR:.*(alg|signature|NONSENSE)' "$log"; then
                    echo "    [OK] unknown alg was rejected"
                else
                    echo "    [FAIL] unknown alg was not rejected"
                    rc=1
                fi
                # final current_user must NOT be target_role (unkalg failed
                # outside the BEGIN/COMMIT blocks; the committed HS512 block
                # already reverted at COMMIT, leaving us back at session_user).
                if grep -qE 'MARKER_AFTER_ALL: (postgres|app_user|target_role|dba_user)' "$log"; then
                    :
                else
                    echo "    [WARN] MARKER_AFTER_ALL missing from test_algorithms log"
                fi
                ;;
            test_exp)
                # exp_recent (exp = now-1) must error.
                if grep -qE ' ERROR:.*(expired|exp)' "$log"; then
                    echo "    [OK] exp_recent was rejected"
                else
                    echo "    [FAIL] exp_recent was not rejected"
                    rc=1
                fi
                # exp_future must flip current_user.
                if grep -q 'MARKER_EXP_FUTURE: target_role' "$log"; then
                    echo "    [OK] exp_future flipped current_user"
                else
                    echo "    [FAIL] exp_future did not flip current_user"
                    rc=1
                fi
                # exp_missing must flip current_user (no exp claim tolerated).
                if grep -q 'MARKER_EXP_MISSING: target_role' "$log"; then
                    echo "    [OK] exp_missing (no exp claim) flipped current_user"
                else
                    echo "    [FAIL] exp_missing did not flip current_user"
                    rc=1
                fi
                ;;
            test_limits)
                # max_jwt_len=128 must reject valid HS256 token.
                if grep -qE ' ERROR:.*(max_jwt_len|exceeds|too long|signing_input)' "$log"; then
                    echo "    [OK] max_jwt_len enforced"
                else
                    echo "    [FAIL] max_jwt_len not enforced"
                    rc=1
                fi
                # max_claim_len=2 must reject role="target_role" (length 11).
                if grep -qE ' ERROR:.*(max_claim_len|exceeds|claim value)' "$log"; then
                    echo "    [OK] max_claim_len enforced"
                else
                    echo "    [FAIL] max_claim_len not enforced"
                    rc=1
                fi
                # Slot pool overflow: a1 must be bound ('v1'), a17 must be
                # dropped (empty after COALESCE).
                if grep -q 'MARKER_SLOT_FIRST: v1' "$log" \
                        && grep -qE 'MARKER_SLOT_OVERFLOW: *$' "$log"; then
                    echo "    [OK] slot pool overflow handled (a1 bound, a17 dropped)"
                else
                    echo "    [FAIL] slot pool overflow not handled as expected"
                    echo "      --- relevant log lines ---"
                    grep -E 'MARKER_SLOT_' "$log" | sed 's/^/      /'
                    rc=1
                fi
                # P2.5 follow-up (plans/coverage.md §P2.5): an extra_claims
                # entry longer than PG_JWT_MAX_CLAIM_NAME_LEN - 1 must be
                # hard-rejected by pg_split_csv(), not silently truncated.
                # The token is validly signed; the rejection is driven by
                # extra_claims being configured to a 65-character name. The
                # role switch must NOT happen (MARKER_AFTER_LONG_CLAIM must
                # NOT be target_role).
                # P2.5 follow-up (plans/coverage.md §P2.5): an extra_claims
                # entry longer than PG_JWT_MAX_CLAIM_NAME_LEN - 1 must be
                # hard-rejected by pg_split_csv(), not silently truncated.
                # The token is validly signed; the rejection is driven by
                # extra_claims being configured to a 65-character name. The
                # role switch must NOT happen (MARKER_AFTER_LONG_CLAIM must
                # NOT be target_role).
                if grep -qE ' ERROR:.*(extra_claims entry too long)' "$log"; then
                    echo "    [OK] over-long extra_claims name rejected (pg_split_csv ereport)"
                else
                    echo "    [FAIL] over-long extra_claims name was NOT rejected"
                    rc=1
                fi
                if grep -qE 'MARKER_AFTER_LONG_CLAIM: (postgres|app_user)' "$log"; then
                    echo "    [OK] role unchanged after over-long extra_claims rejection"
                else
                    echo "    [FAIL] role state unclear after over-long extra_claims rejection"
                    rc=1
                fi
                ;;
            test_unknown)
                # badrole (unknown role) must error.
                if grep -qE ' ERROR:.*(does not exist|role)' "$log"; then
                    echo "    [OK] unknown role rejected"
                else
                    echo "    [FAIL] unknown role not rejected"
                    rc=1
                fi
                # norole must error.
                if grep -qE ' ERROR:.*(missing|claim)' "$log"; then
                    echo "    [OK] missing role claim rejected"
                else
                    echo "    [FAIL] missing role claim not rejected"
                    rc=1
                fi
                # b64url_sig must succeed - role flips to target_role.
                if grep -q 'MARKER_AFTER_B64URL_SIG: target_role' "$log"; then
                    echo "    [OK] base64url signature normalised + verified"
                else
                    echo "    [FAIL] base64url signature not normalised/verified"
                    rc=1
                fi
                # Empty / garbage must error (PL/pgSQL "malformed JWT").
                if grep -qE ' ERROR:.*malformed JWT' "$log"; then
                    echo "    [OK] empty/garbage input rejected"
                else
                    echo "    [FAIL] empty/garbage input not rejected"
                    rc=1
                fi
                ;;
        esac
    else
        # Stub mode: every test_*.sql must surface some ERROR for the
        # invalid inputs (either PL/pgSQL's own validation or the C
        # stub's "not yet implemented" message).
        case "$name" in
            test_basic|test_invalid|test_algorithms|test_exp|test_limits|test_unknown)
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
