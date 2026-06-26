-- test_hook.sql — ProcessUtility_hook behaviour (Step 4 of plans/plan.md).
--
-- Run with: psql -f test/sql/test_hook.sql
--
-- Expectation once Step 4 is implemented:
--   * app_user  (in pg_jwt_role.restricted_session_users)
--       SET ROLE NONE              allowed
--       RESET ROLE                 allowed
--       SET ROLE target_role       allowed (matches JWT-claimed role, if set)
--       SET ROLE <other>           REJECTED by the hook
--   * dba_user  (not restricted)   SET ROLE anything is fine.
--
-- Today the hook is not installed, so SET ROLE for app_user is not blocked.
-- run_tests.sh asserts both the unimplemented (current) and implemented
-- (Step 4 done) outputs.

\set ON_ERROR_STOP 0
\set ECHO all

SHOW pg_jwt_role.restricted_session_users;
SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';

-- Restricted user: SET ROLE NONE — always allowed.
SET ROLE app_user;
SELECT current_user;
SET ROLE NONE;
SELECT current_user;

-- Restricted user: RESET ROLE — always allowed.
SET ROLE app_user;
SELECT current_user;
RESET ROLE;
SELECT current_user;

-- Unmonitored user: SET ROLE anything is fine.
SET ROLE dba_user;
SELECT current_user;
RESET ROLE;
SELECT current_user;

-- Restricted user: SET ROLE target_role is allowed (matches the
-- JWT-claimed role when the C function has populated pg_jwt_role.role).
-- In stub mode this is still allowed because the hook doesn't exist yet.
SET ROLE app_user;
SET ROLE target_role;
SELECT current_user;
RESET ROLE;
SELECT current_user;

-- Restricted user: SET ROLE to a non-claimed role — must be rejected
-- by the hook. Today (no hook) this passes; the harness flags the
-- divergence via PASS/FAIL counters.
SET ROLE app_user;
SET ROLE dba_user;
SELECT current_user;
RESET ROLE;
SELECT current_user;
