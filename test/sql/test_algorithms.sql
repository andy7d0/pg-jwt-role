-- test_algorithms.sql — HS256 / HS384 / HS512 happy paths + unknown alg rejection.
--
-- Run with: psql -X -f test/sql/test_algorithms.sql (after `set_role`-friendly
-- tokens have been injected by run_tests.sh).
--
-- Behaviour once Step 3 is implemented:
--   * hs256.jwt  : valid HS256 token  → success, role flips to target_role
--   * hs384.jwt  : valid HS384 token  → success, role flips to target_role
--   * hs512.jwt  : valid HS512 token  → success, role flips to target_role
--   * unkalg.jwt : alg="NONSENSE"     → ERROR (algorithm dispatch fails)
--
-- All four tokens are HMAC-signed with the same HS256_SECRET (the key length
-- is fine for HS384/HS512 too). In stub mode every call surfaces an ERROR
-- and current_user never moves.
--
-- Output convention: each assertion prints a sentinel like
--   MARKER_HS256: target_role
-- on a single line. run_tests.sh greps for the MARKER_* prefix to keep the
-- assertions robust against psql's table-format column wrapping.

\set ON_ERROR_STOP 0
\set ECHO all

-- These GUCs are PGC_SUSET; only superuser can SET them. Briefly revert
-- session authorization to the connecting postgres superuser, set the
-- values, then re-impersonate app_user for the rest of the test.
RESET SESSION AUTHORIZATION;
SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';
SET SESSION AUTHORIZATION app_user;

-- HS256 happy path.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.hs256_jwt'));
SELECT 'MARKER_HS256: ' || current_user AS hs256_marker;
COMMIT;

-- HS384 happy path.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.hs384_jwt'));
SELECT 'MARKER_HS384: ' || current_user AS hs384_marker;
COMMIT;

-- HS512 happy path.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.hs512_jwt'));
SELECT 'MARKER_HS512: ' || current_user AS hs512_marker;
COMMIT;

-- Unknown alg: must error. The C function dispatches by exact match;
-- anything outside HS256/384/512 / RS256/384/512 / ES256/384/512 returns false.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.unkalg_jwt'));

-- Whatever happened above, current_user must still be the original role
-- when the last BEGIN/COMMIT pair finished (we committed before unkalg).
SELECT 'MARKER_AFTER_ALL: ' || current_user AS after_all_marker;