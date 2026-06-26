-- test_hook.sql — ProcessUtility_hook behaviour (Step 4 of plans/plan.md).
--
-- Run with: psql -f test/sql/test_hook.sql
--
-- Expectation once Step 4 is implemented:
--   * app_user  (in pg_jwt_role.restricted_session_users)
--       SET ROLE NONE              allowed  (current_user -> session_user)
--       RESET ROLE                 allowed  (current_user -> session_user)
--       SET ROLE target_role       allowed  (matches JWT-claimed role, if set)
--       SET ROLE <other>           REJECTED by the hook
--   * dba_user  (not restricted)   SET ROLE anything is fine.
--
-- Today the hook is not installed, so SET ROLE for app_user is not blocked.
-- run_tests.sh asserts both the unimplemented (current) and implemented
-- (Step 4 done) outputs.
--
-- P1 follow-up (plans/coverage.md §P1): the previous version of this file
-- only exercised the rejection branch. Every "allowed" code path in
-- pg_jwt_role_ProcessUtility was silent. We now print explicit
-- 'MARKER_HOOK_*: <value>' lines after each allowed SET ROLE / RESET ROLE
-- so the harness can positively assert that the allow branches were taken.
--
-- Output convention: each assertion prints a sentinel of the form
--   MARKER_HOOK_<NAME>: <expected_current_user>
-- on a single line. run_tests.sh greps for the MARKER_HOOK_<NAME> prefix
-- to keep the assertions robust against psql's table-format column wrapping
-- (mirrors the convention used in test_algorithms.sql).

\set ON_ERROR_STOP 0
\set ECHO all

SHOW pg_jwt_role.restricted_session_users;
-- These GUCs are PGC_SUSET; only superuser can SET them. Briefly revert
-- session authorization to the connecting postgres superuser, set the
-- values, then re-impersonate app_user for the rest of the test.
RESET SESSION AUTHORIZATION;
SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';
SET SESSION AUTHORIZATION app_user;

-- ---------------------------------------------------------------------------
-- 1. Restricted user: SET ROLE NONE — always allowed by the hook
--    (hook short-circuits on strcmp(target, "none") == 0).
-- ---------------------------------------------------------------------------
SET ROLE app_user;
SELECT 'MARKER_HOOK_BEFORE_NONE: ' || current_user;
SET ROLE NONE;
SELECT 'MARKER_HOOK_NONE_OK: ' || current_user;

-- ---------------------------------------------------------------------------
-- 2. Restricted user: RESET ROLE — always allowed by the hook.
-- ---------------------------------------------------------------------------
SET ROLE app_user;
SELECT 'MARKER_HOOK_BEFORE_RESET: ' || current_user;
RESET ROLE;
SELECT 'MARKER_HOOK_RESET_OK: ' || current_user;

-- ---------------------------------------------------------------------------
-- 3. Unmonitored user: SET ROLE anything is fine. SET SESSION AUTHORIZATION
--    is superuser-only, so we bounce back to the connecting postgres
--    superuser before re-impersonating as dba_user (not in
--    pg_jwt_role.restricted_session_users). The hook's
--    is_session_user_restricted() returns false for dba_user, so the
--    SET ROLE proceeds unchallenged.
-- ---------------------------------------------------------------------------
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION dba_user;
SELECT 'MARKER_HOOK_BEFORE_UNMONITORED: ' || current_user;
SET ROLE dba_user;
SELECT 'MARKER_HOOK_UNMONITORED_OK: ' || current_user;
RESET ROLE;
SELECT 'MARKER_HOOK_AFTER_UNMONITORED_RESET: ' || current_user;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION app_user;

-- ---------------------------------------------------------------------------
-- 4. Restricted user: SET ROLE target_role is allowed ONLY when
--    GetCurrentRoleId() matches the JWT-claimed role. We populate
--    pg_jwt_role.role (and current_user) by calling pgjwt.set_role()
--    inside the same transaction first. After that, SET ROLE target_role
--    takes the allow branch in pg_jwt_role_ProcessUtility.
-- ---------------------------------------------------------------------------
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.valid_jwt'));
SELECT 'MARKER_HOOK_BEFORE_CLAIMED: ' || current_user;
SET ROLE target_role;
SELECT 'MARKER_HOOK_CLAIMED_OK: ' || current_user;
RESET ROLE;
SELECT 'MARKER_HOOK_AFTER_CLAIMED_RESET: ' || current_user;
COMMIT;

-- ---------------------------------------------------------------------------
-- 5. Restricted user: SET ROLE to a non-claimed role — must be rejected
--    by the hook. We deliberately do NOT call pgjwt.set_role() first, so
--    current_user stays as app_user, target_oid = dba_user OID, and the
--    hook's target_oid != claimed_oid branch fires.
-- ---------------------------------------------------------------------------
SET ROLE app_user;
SET ROLE dba_user;
SELECT 'MARKER_HOOK_REJECTED_PATH: ' || current_user;
RESET ROLE;
SELECT 'MARKER_HOOK_AFTER_REJECTED_RESET: ' || current_user;
