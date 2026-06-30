#!/bin/bash
# run_unit_tests.sh — compile and run the C unit tests for the
# pg_jwt_role helper modules, without requiring a PostgreSQL install.
#
# Unlike the SQL integration harness (test/run_tests.sh, which needs a
# full PG 18 cluster inside Docker), these tests exercise the pure-logic
# helpers directly: pg_jwt_strlist, pg_jwt_json, pg_jwt_base64, pg_jwt_csv.
# They link the REAL production .c files unchanged, compiled against
# minimal stub headers under test/unit/stubs/ that stand in for the
# PostgreSQL headers those files #include.
#
# Usage:
#   test/unit/run_unit_tests.sh          # build + run, fail fast
#   test/unit/run_unit_tests.sh -k       # keep going across failures
#   test/unit/run_unit_tests.sh clean    # remove build artefacts
#
# Exit status: non-zero if any test binary fails (unless -k).
set -euo pipefail

cd "$(dirname "$0")/../.." # -> repo root (script lives in test/unit/)
REPO="$(pwd)"

UNIT_DIR="$REPO/test/unit"
STUBS="-I$UNIT_DIR/stubs"
INC="-I$REPO -I$UNIT_DIR/stubs"
# Match the production Makefile's flags (Makefile:18).
CFLAGS="-Wall -Wno-unused-parameter -std=c11 -O2"
CC="${CC:-gcc}"

BUILD_DIR="$UNIT_DIR/build"
KEEP_GOING=0
[ "${1:-}" = "-k" ] && { KEEP_GOING=1; shift; }

if [ "${1:-}" = "clean" ]; then
    rm -rf "$BUILD_DIR"
    echo "cleaned $BUILD_DIR"
    exit 0
fi

mkdir -p "$BUILD_DIR"

# (helper_under_test  test_file) tuples. Each test links its helper plus
# the shared stub_pg.c (which backs the ereport longjmp machinery).
SPECS=(
    "pg_jwt_strlist test_strlist"
    "pg_jwt_json    test_json"
    "pg_jwt_base64  test_base64"
    "pg_jwt_csv     test_csv"
)

PASS=0
FAIL=0
FAILED=()

for spec in "${SPECS[@]}"; do
    helper="${spec%% *}"
    test="${spec##* }"
    bin="$BUILD_DIR/$test"
    srcs="$REPO/$helper.c $UNIT_DIR/$test.c $UNIT_DIR/stub_pg.c"

    echo ">>> build $test ($helper + stubs)"
    if ! $CC $CFLAGS $INC $srcs -o "$bin" 2> "$BUILD_DIR/$test.cc.log"; then
        echo "!!! compile failed for $test:" >&2
        cat "$BUILD_DIR/$test.cc.log" >&2
        FAIL=$((FAIL+1))
        FAILED+=("$test (compile)")
        [ "$KEEP_GOING" -eq 1 ] || { echo "ABORTING (-k to continue)"; exit 1; }
        continue
    fi
    # Surface any warnings that compiled into success.
    if [ -s "$BUILD_DIR/$test.cc.log" ]; then
        cat "$BUILD_DIR/$test.cc.log" >&2
    fi

    echo ">>> run $test"
    if "$bin"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        FAILED+=("$test")
        [ "$KEEP_GOING" -eq 1 ] || { echo "ABORTING (-k to continue)"; exit 1; }
    fi
    echo
done

echo "================================================================"
echo "UNIT TEST SUMMARY"
echo "================================================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
echo "ALL UNIT TESTS PASSED"
