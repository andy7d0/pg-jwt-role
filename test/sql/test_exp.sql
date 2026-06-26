-- test_exp.sql — exp claim boundary behaviour.
--
-- Run with: psql -X -f test/sql/test_exp.sql (after run_tests.sh injected the
-- exp_* tokens).
--
-- Behaviour once Step 3 is implemented:
--   * exp_recent.jwt : exp = now-1  → ERROR (just expired)
--   * exp_future.jwt : exp = now+3600 → success
--   * exp_missing.jwt: no exp claim at all → success (exp is optional)
--
-- The C function does `time(NULL) >= exp_val`, so exp = now-1 always fails.
-- exp_missing is tolerated because missing-key returns false from
-- pg_json_extract_value and the C code falls through the check.
--
-- Output convention: each assertion prints a sentinel on a single line
-- (MARKER_*) so run_tests.sh can grep robustly.

\set ON_ERROR_STOP 0
\set ECHO all

SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';

-- 1. Just-expired token.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.exp_recent_jwt'));

-- 2. Valid future token.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.exp_future_jwt'));
SELECT 'MARKER_EXP_FUTURE: ' || current_user AS exp_future_marker;
COMMIT;

-- 3. Token with no exp claim at all.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.exp_missing_jwt'));
SELECT 'MARKER_EXP_MISSING: ' || current_user AS exp_missing_marker;
COMMIT;

SELECT 'MARKER_AFTER_ALL: ' || current_user AS after_all_marker;