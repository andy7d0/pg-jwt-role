-- test_limits.sql — defensive bounds enforced by Step 3.
--
-- Run with: psql -X -f test/sql/test_limits.sql (after run_tests.sh injected
-- the limits_* tokens and configured GUCs).
--
-- Behaviour once Step 3 is implemented:
--   * max_jwt_len=128  → valid HS256 token errors out (signing_input > 128)
--   * max_claim_len=2  → valid HS256 token errors out (role="target_role"
--                         has length 11 > 2)
--   * extra_claims lists 17 distinct names; the C function binds 16 and
--                         silently drops the 17th (verify_and_set_role
--                         returns success; one expected claim value is
--                         not visible).
--
-- In stub mode every set_role call surfaces an ERROR and we just look for
-- at least one ERROR per call.
--
-- Output convention: each assertion prints a sentinel on a single line
-- (MARKER_*) so run_tests.sh can grep robustly.

\set ON_ERROR_STOP 0
\set ECHO all

-- 1. max_jwt_len enforced.
RESET SESSION AUTHORIZATION;
SET pg_jwt_role.max_jwt_len = 128;
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.hs256_jwt'));
SELECT 'MARKER_AFTER_SMALL_MAX_JWT: ' || current_user AS after_small_max_jwt_marker;
SET SESSION AUTHORIZATION app_user;
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pg_jwt_role.max_jwt_len;

-- 2. max_claim_len enforced. Role "target_role" has length 11, so the
-- C function ereports ERROR when max_claim_len < 11.
SET SESSION AUTHORIZATION app_user;
SET pg_jwt_role.max_claim_len = 2;
RESET SESSION AUTHORIZATION;
BEGIN;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.hs256_jwt'));
SELECT 'MARKER_AFTER_SMALL_MAX_CLAIM: ' || current_user AS after_small_max_claim_marker;
COMMIT;
SET SESSION AUTHORIZATION app_user;
RESET pg_jwt_role.max_claim_len;
RESET SESSION AUTHORIZATION;

-- 3. Slot pool overflow. Configure 17 extra claim names; the C function
-- can only bind 16 slots, so one claim value must be silently dropped.
SET pg_jwt_role.extra_claims =
    'a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17';
BEGIN;
-- The token has those 17 names as claims. Verify all set_role succeeds
-- (the C function must not error on overflow, by design).
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.slots17_jwt'));
-- Of the 17 names, claim a1 should be present, claim a17 must NOT be
-- (slot 15 was the last one available).
SELECT 'MARKER_SLOT_FIRST: '    || COALESCE(pgjwt.claim('a1'),  '') AS slot_first,
       'MARKER_SLOT_OVERFLOW: ' || COALESCE(pgjwt.claim('a17'), '') AS slot_overflow;
COMMIT;
SET SESSION AUTHORIZATION app_user;
RESET pg_jwt_role.extra_claims;
-- Drop back to the originally-authenticated user (postgres, the bootstrap
-- superuser) so the SUSET SET in block #4 is allowed.
RESET SESSION AUTHORIZATION;

-- 4. Over-long extra_claim name (P2.5 follow-up, plans/coverage.md §P2.5).
-- The JWT is validly signed and contains a JSON claim whose key is
-- exactly 65 characters long (one past PG_JWT_MAX_CLAIM_NAME_LEN - 1 = 63).
-- pg_jwt_role.extra_claims is set to that same long key. pg_split_csv()
-- must ereport() with ERRCODE_INVALID_PARAMETER_VALUE rather than
-- silently truncating; current_user must remain the original session role.
-- This protects the documented "extra_claims" contract — a typo with a
-- long name can't silently no-op and confuse the admin.
--
-- Block #3 above ended with RESET SESSION AUTHORIZATION so su=postgres
-- and cu=postgres are in effect here, and the SUSET SET below is allowed.
--
-- The 65-character literal below is one past PG_JWT_MAX_CLAIM_NAME_LEN
-- - 1 = 63. We use a literal because PostgreSQL's SET syntax does not
-- accept function expressions on the RHS of a custom GUC assignment;
-- only string/numeric literals and `DEFAULT` work.
SET pg_jwt_role.extra_claims = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
-- SAVEPOINT isolates the set_role call so a rejection doesn't abort the
-- outer transaction and prevent us from reading current_user afterwards.
SAVEPOINT before_long;
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.long_claim_jwt'));
ROLLBACK TO SAVEPOINT before_long;
-- After a rejection we should still be the original role.
SELECT 'MARKER_AFTER_LONG_CLAIM: ' || current_user AS after_long_claim_marker;
RELEASE SAVEPOINT before_long;
RESET pg_jwt_role.extra_claims;
SET SESSION AUTHORIZATION app_user;

-- Whatever happened above, current_user must still be the original role.
SELECT 'MARKER_AFTER_ALL: ' || current_user AS after_all_marker;