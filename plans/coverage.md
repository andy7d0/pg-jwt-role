# Test-coverage follow-ups

This file tracks gaps in the `pg_jwt_role` test harness, identified by
cross-referencing every `test/sql/test_*.sql` file and the assertion block
in [`test/run_tests.sh`](test/run_tests.sh:1) against the implementation
status table in [`AGENTS.md`](../AGENTS.md:1).

Like [`plans/plan.md`](plan.md:1), this is a planning document, not a
source of truth for the current code. [`AGENTS.md`](../AGENTS.md:1)
remains authoritative for what `pg_jwt_role` actually does today.

## Status of the existing harness

All seven [`test/sql/test_*.sql`](../test/sql/) files are landed and the
default `scripts/test.sh` run (with `PG_JWT_ROLE_IMPLEMENTED=1`)
exercises the success-path assertions for Steps 3/4/5. The harness is
grep-based, not `pg_regress`; assertions live in
[`test/run_tests.sh:265-406`](../test/run_tests.sh:265).

### What is covered today

| Behaviour | Test | Asserted at |
|-----------|------|-------------|
| All four SQL-callable functions present in `pgjwt` schema | [`test_basic.sql:20`](../test/sql/test_basic.sql:20) | smoke [`run_tests.sh:447`](../test/run_tests.sh:447) |
| All eight config + output GUCs + 16-slot pool registered | [`test_basic.sql:29`](../test/sql/test_basic.sql:29) | smoke [`run_tests.sh:448`](../test/run_tests.sh:448) |
| Happy path: HS256, role flips, extra claims exposed | [`test_basic.sql:57`](../test/sql/test_basic.sql:57) | [`run_tests.sh:268-278`](../test/run_tests.sh:268) |
| Transaction-local GUC cleanup on COMMIT | [`test_basic.sql:66`](../test/sql/test_basic.sql:66) | implicit |
| `pgjwt.claim()` returns `''` on unbound name | [`test_basic.sql:54`](../test/sql/test_basic.sql:54) | implicit |
| HS256/384/512 happy path | [`test_algorithms.sql`](../test/sql/test_algorithms.sql:1) | [`run_tests.sh:302-308`](../test/run_tests.sh:302) |
| Unknown `alg` rejected | [`test_algorithms.sql:52`](../test/sql/test_algorithms.sql:52) | [`run_tests.sh:311`](../test/run_tests.sh:311) |
| `exp` boundary: `now-1` rejected, `now+3600` accepted, missing `exp` tolerated | [`test_exp.sql`](../test/sql/test_exp.sql:1) | [`run_tests.sh:326-348`](../test/run_tests.sh:326) |
| `max_jwt_len` enforced | [`test_limits.sql:24`](../test/sql/test_limits.sql:24) | [`run_tests.sh:350-356`](../test/run_tests.sh:350) |
| `max_claim_len` enforced | [`test_limits.sql:37`](../test/sql/test_limits.sql:37) | [`run_tests.sh:358-363`](../test/run_tests.sh:358) |
| Slot pool overflow (17 claims, 16 slots — 17th silently dropped) | [`test_limits.sql:50`](../test/sql/test_limits.sql:50) | [`run_tests.sh:366-374`](../test/run_tests.sh:366) |
| Bad signature (CRYPTO_memcmp path) | [`test_invalid.sql:17`](../test/sql/test_invalid.sql:17) | [`run_tests.sh:282-290`](../test/run_tests.sh:282) |
| Expired token, missing role claim, unknown role name | [`test_invalid.sql`](../test/sql/test_invalid.sql:1), [`test_unknown.sql`](../test/sql/test_unknown.sql:1) | [`run_tests.sh:378-390`](../test/run_tests.sh:378) |
| Base64url signature normalisation | [`test_unknown.sql:39`](../test/sql/test_unknown.sql:39) | [`run_tests.sh:392`](../test/run_tests.sh:392) |
| Malformed/empty/garbage input rejected by PL/pgSQL wrapper | [`test_invalid.sql:26`](../test/sql/test_invalid.sql:26) | [`run_tests.sh:399-404`](../test/run_tests.sh:399) |
| `ProcessUtility_hook` blocks `SET ROLE <other>` for restricted `session_user` | [`test_hook.sql:59`](../test/sql/test_hook.sql:59) | [`run_tests.sh:293-298`](../test/run_tests.sh:293) |

## Follow-ups, prioritised

### P1 — Hook allow-branches are untested (security-critical)

These are the most material gaps: the hook's three "allowed" code paths
in [`pg_jwt_role_ProcessUtility`](../pg_jwt_role.c:1049) are exercised
by the SQL but never positively asserted by the harness. Only the
rejection branch at [`pg_jwt_role.c:1102`](../pg_jwt_role.c:1102) has a
grep matching it.

1. **`SET ROLE <claimed_oid>` succeeds for restricted `session_user`.**
   [`test/sql/test_hook.sql:48`](../test/sql/test_hook.sql:48) runs
   `SET ROLE target_role` while `session_user=app_user`, but does **not**
   first call `pgjwt.set_role()` to populate `pg_jwt_role.role`.
   Therefore `GetCurrentRoleId()` at [`pg_jwt_role.c:1091`](../pg_jwt_role.c:1091)
   returns the session OID, `target_oid != claimed_oid`, and the
   rejection branch fires — the test "passes" via the rejection grep but
   the *allowed* branch is never actually exercised.
   Fix: before `SET ROLE target_role`, run `SELECT pgjwt.set_role('...valid_jwt...');`
   inside the same transaction so `pg_jwt_role.role` is populated, then
   assert `current_user=target_role` rather than asserting the rejection.
2. **`SET ROLE NONE` succeeds for restricted `session_user`.** The call
   runs at [`test/sql/test_hook.sql:30`](../test/sql/test_hook.sql:30)
   but no grep in [`test/run_tests.sh:293`](../test/run_tests.sh:293)
   checks the success path. Add an assertion that `current_user`
   after the call equals `app_user` (the session_user).
3. **`RESET ROLE` succeeds for restricted `session_user`.** Same shape
   as #2; runs at [`test/sql/test_hook.sql:36`](../test/sql/test_hook.sql:36).
4. **Unmonitored `session_user` is unrestricted.** Covered by
   [`test/sql/test_hook.sql:42`](../test/sql/test_hook.sql:42) but not
   positively asserted — add a check that
   `current_user=dba_user` after `SET ROLE dba_user` from an unrestricted
   session_user.

### P2 — Internal C-helper coverage

5. **Reject over-long claim names in [`pg_jwt_claim_slot`](../pg_jwt_role.c:817).**
   The function returns `-1` when `name` ≥ `PG_JWT_MAX_CLAIM_NAME_LEN`,
   but no test mints a JWT with a 65+ char claim name. The C function
   must ereport() in that case; verify it does.
6. **Direct invocation of [`pgjwt.claim_value`](../pg_jwt_role--1.0.sql:79).**
   Only the `COALESCE` wrapper [`pgjwt.claim`](../pg_jwt_role--1.0.sql:89)
   is called in tests. The C entry's NULL-on-unbound behaviour is
   therefore not directly observable. Add a `SELECT pgjwt.claim_value('sub');`
   call before `set_role` and assert the result is NULL.
7. **Tighten error-message regexes.** The current grep patterns in
   [`test/run_tests.sh`](../test/run_tests.sh:265-405) use broad
   alternations — e.g. `(expired|exp)`, `(max_jwt_len|exceeds|too long|signing_input)`,
   `(rejected|INS|SET ROLE)`, `(alg|signature|NONSENSE)`,
   `(does not exist|role)`, `(missing|claim)`. A different error class
   could match accidentally. Tighten to specific SQLSTATEs
   (`ERRCODE_INSUFFICIENT_PRIVILEGE`, `ERRCODE_INVALID_PARAMETER_VALUE`,
   etc.) and message substrings.

### P3 — Larger refactors (already tracked in repo)

8. **Asymmetric algorithms (RS256/384/512, ES256/384/512).** The
   [`pg_jwt_verify`](../pg_jwt_role.c:377) dispatch path is unexercised.
   [`test/test_jwt_helper.py:38`](../test/test_jwt_helper.py:38) only
   emits HS family; [`test/run_tests.sh:78`](../test/run_tests.sh:78)
   only loads an HS shared secret. The harness would need to either
   start a second cluster with a PEM key in `pg_jwt_role.verify_key`,
   or commit a fixed test key pair. Already noted as a follow-up at
   [`test/README.md:75`](../test/README.md:75).
9. **Migrate to `pg_regress`.** Replace the grep-on-psql-log harness
   with exact-output diffing. This would let us assert the exact error
   class / message / GUC value produced by the C function, closing gap
   #7 structurally. Larger refactor of
   [`test/run_tests.sh`](../test/run_tests.sh:1). Already noted as a
   follow-up at [`test/README.md:82`](../test/README.md:82).

## Ordering rationale

P1 is highest because the hook's *allow* branches are part of the
documented security model in [`AGENTS.md`](../AGENTS.md:1) ("allow
`SET ROLE <claimed_role>`, `SET ROLE NONE`, `RESET ROLE`") but are
silently untested. P2 covers internal-helper branches that have less
external visibility but still represent untested code paths in the C
file. P3 items are already tracked in `test/README.md` and are larger
undertakings.