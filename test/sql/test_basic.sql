-- test_basic.sql — happy path smoke test for set_role.
--
-- Run with: psql -f test/sql/test_basic.sql
--
-- Behaviour depends on whether the atomic C function is implemented:
--   * Stub (IMPLEMENTED=0)         : set_role() raises
--                                    "not yet implemented" and the role
--                                    is NOT switched. SELECT current_user
--                                    therefore stays as the connecting role.
--   * Implemented (IMPLEMENTED=1) : set_role() succeeds, current_user
--                                    becomes the JWT-claimed role, and
--                                    the configured extra claims are
--                                    exposed via pgjwt.claim(name).

\set ON_ERROR_STOP 0
\set ECHO all

-- Sanity: extension loaded, all functions present (set_role, verify_and_set_role,
-- claim, claim_value).
SELECT proname, pronargs
  FROM pg_proc
 WHERE proname IN ('set_role', 'verify_and_set_role', 'claim', 'claim_value')
   AND pronamespace = 'pgjwt'::regnamespace
 ORDER BY proname;

-- Step 2 sanity: every GUC promised in plans/plan.md §5 must be
-- registered and reachable. We SHOW each one explicitly so a missing
-- registration shows up as an ERROR in the psql log.
SHOW pg_jwt_role.verify_key;
SHOW pg_jwt_role.role_claim;
SHOW pg_jwt_role.extra_claims;
SHOW pg_jwt_role.restricted_session_users;
SHOW pg_jwt_role.max_jwt_len;
SHOW pg_jwt_role.max_claim_len;
SHOW pg_jwt_role.role;
SHOW pg_jwt_role.claim_0;
SHOW pg_jwt_role.claim_15;

-- And the slot pool must have exactly 16 entries registered.
SELECT count(*) AS claim_slot_count
  FROM pg_settings
 WHERE name LIKE 'pg_jwt_role.claim\_%' ESCAPE '\';

SET pg_jwt_role.role_claim   = 'role';
SET pg_jwt_role.extra_claims = 'sub,email';

-- pgjwt.claim() with an unbound name must return the empty string
-- (not error) - that's the COALESCE wrapper around pgjwt.claim_value().
SELECT pgjwt.claim('sub')   AS unbound_sub,
       pgjwt.claim('email') AS unbound_email;

-- Run set_role inside a transaction so GUC_ACTION_LOCAL cleanup is visible.
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.valid_jwt'));
SELECT current_user AS current_user_after_set;
SELECT current_setting('pg_jwt_role.role',  true)              AS guc_role,
       pgjwt.claim('sub')                                     AS guc_sub,
       pgjwt.claim('email')                                   AS guc_email;
COMMIT;

-- After COMMIT, the transaction-local GUCs must revert.
SELECT pgjwt.claim('sub')   AS guc_sub_after_commit,
       pgjwt.claim('email') AS guc_email_after_commit;

-- And the role is back to whatever we logged in as.
SELECT current_user AS current_user_after_commit;
