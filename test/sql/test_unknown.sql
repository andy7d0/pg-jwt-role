-- test_unknown.sql — error paths around claim extraction and signature
-- normalisation.
--
-- Run with: psql -X -f test/sql/test_unknown.sql (after run_tests.sh injected
-- the unknown_* tokens).
--
-- Behaviour once Step 3 is implemented:
--   * badrole.jwt   : role="no_such_role_xyz" → ERROR (get_role_oid fails)
--                      AFTER signature passes.
--   * norole.jwt    : payload has no "role" claim → ERROR (extract fails).
--   * b64url_sig.jwt: signature uses base64url chars (-, _) → success
--                      (the C function normalises them back to base64).
--                      The current_user must flip to target_role.
--   * empty string  : PL/pgSQL "malformed JWT" error.
--   * non-JWT garbage: PL/pgSQL "malformed JWT" error.
--
-- Output convention: each assertion prints a sentinel on a single line
-- (MARKER_*) so run_tests.sh can grep robustly.

\set ON_ERROR_STOP 0
\set ECHO all

-- These GUCs are PGC_SUSET; only superuser can SET them. Briefly revert
-- session authorization to the connecting postgres superuser, set the
-- values, then re-impersonate app_user for the rest of the test.
RESET SESSION AUTHORIZATION;
SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';
SET SESSION AUTHORIZATION app_user;

-- 1. Unknown role name.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.badrole_jwt'));

-- 2. Missing role claim.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.norole_jwt'));

-- 3. Base64url signature: must normalise and verify.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.b64url_sig_jwt'));
SELECT 'MARKER_AFTER_B64URL_SIG: ' || current_user AS after_b64url_sig_marker;
COMMIT;

-- 4. Empty input.
SELECT pgjwt.set_role('');

-- 5. Garbage input.
SELECT pgjwt.set_role('this-is-not-a-jwt');

SELECT 'MARKER_AFTER_ALL: ' || current_user AS after_all_marker;