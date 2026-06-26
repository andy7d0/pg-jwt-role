-- test_invalid.sql — every input that must be rejected.
--
-- Run with: psql -f test/sql/test_invalid.sql
--
-- Behaviour in both stub and implemented modes is "psql should see an
-- ERROR for every call below". We assert by simply running each call
-- with \set ON_ERROR_STOP 0; if any call succeeds unexpectedly the
-- PASS/FAIL summary at the end of run_tests.sh will flag it.

\set ON_ERROR_STOP 0
\set ECHO all

-- 1. Expired JWT.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.expired_jwt'));

-- 2. Bad signature.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.badsig_jwt'));

-- 3. Missing role claim.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.norole_jwt'));

-- 4. Role claim names a role that doesn't exist.
SELECT pgjwt.set_role(current_setting('pg_jwt_role.test.badrole_jwt'));

-- 5. Malformed JWT — only two parts.
SELECT pgjwt.set_role('aaa.bbb');

-- 6. Empty input.
SELECT pgjwt.set_role('');

-- 7. Non-JWT garbage.
SELECT pgjwt.set_role('this-is-not-a-jwt');

-- Whatever happened above, current_user must still be the original role.
SELECT current_user;
