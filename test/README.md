# pg_jwt_role — test harness

This directory contains a self-contained smoke-test harness for the
`pg_jwt_role` extension. It runs entirely inside an Alpine + PostgreSQL 18
container built by [`Dockerfile`](../Dockerfile:1).

## Files

| File | Purpose |
|------|---------|
| [`run_tests.sh`](run_tests.sh:1) | Entry point. Spins up a temp cluster, loads the extension, mints test JWTs, runs each `sql/test_*.sql`, prints a PASS/FAIL summary. |
| [`test_jwt_helper.py`](test_jwt_helper.py:1) | CLI helper that mints test JWTs. Supports `HS256`/`HS384`/`HS512`, configurable role / exp / extra claims, `--tamper-sig`, `--b64url-sig` (rewrites the signature to use base64url chars), and `--no-exp` (omits the exp claim). |
| [`sql/test_basic.sql`](sql/test_basic.sql:1) | Happy-path: a well-signed JWT, expect `current_user` to flip and extra claims to be exposed as transaction-local GUCs. |
| [`sql/test_invalid.sql`](sql/test_invalid.sql:1) | Negative-path: expired / bad-signature / missing-role / unknown-role / malformed / empty / garbage inputs — all must be rejected. |
| [`sql/test_hook.sql`](sql/test_hook.sql:1) | `ProcessUtility_hook` behaviour (Step 4 of [`plans/plan.md`](../plans/plan.md:1)): restricted session users blocked from `SET ROLE <other>`, unmonitored users unaffected. |
| [`sql/test_algorithms.sql`](sql/test_algorithms.sql:1) | Step 3: HS256 / HS384 / HS512 happy paths + unknown alg rejection. |
| [`sql/test_exp.sql`](sql/test_exp.sql:1) | Step 3: `exp` claim boundary — `exp = now-1` (just expired), `exp = now+3600` (valid), `exp` missing entirely (tolerated). |
| [`sql/test_limits.sql`](sql/test_limits.sql:1) | Step 3: `max_jwt_len` and `max_claim_len` enforcement; slot-pool overflow (17 extra claims, only 16 slots). |
| [`sql/test_unknown.sql`](sql/test_unknown.sql:1) | Step 3: unknown role, missing role claim, base64url signature normalisation, empty / garbage input. |

## How it works

1. The Dockerfile's builder stage compiles [`pg_jwt_role.c`](../pg_jwt_role.c:1)
   against `postgres:18-alpine` and installs the `.so` + SQL/control files
   into `$libdir` / `$sharedir`.
2. The runtime stage copies those artifacts into a slim `postgres:18-alpine`
   image, adds Python + PyJWT for the JWT helper, and sets
   [`run_tests.sh`](run_tests.sh:1) as the entrypoint.
3. On container start the script:
   - `initdb`s a cluster,
   - starts `postgres` with `shared_preload_libraries=pg_jwt_role`,
   - creates roles (`app_user`, `dba_user`, `target_role`) and the
     extension,
   - mints test JWTs into a temp directory (one per scenario, see below),
   - runs each `sql/test_*.sql` via `psql -X`,
   - greps the output for expected markers and reports PASS/FAIL.

### Tokens minted by `run_tests.sh`

The harness mints the following JWTs before running the tests. Each one
is loaded into a session-local GUC (`pg_jwt_role.test.<name>`) so the
SQL files can `set_role(current_setting('pg_jwt_role.test.<name>'))`
without juggling temp files from inside psql.

| Token | Purpose | Used by |
|-------|---------|---------|
| `valid` | HS256, role=target_role, future exp, sub+email | test_basic, test_unknown |
| `expired` | HS256, exp = now-3600 | test_invalid |
| `badsig` | HS256 with byte 0 of signature flipped | test_invalid |
| `norole` | HS256 with no `role` claim | test_invalid, test_unknown |
| `badrole` | HS256 with role=`no_such_role_xyz` | test_invalid, test_unknown |
| `hs384` | HS384 with same payload as `valid` | test_algorithms |
| `hs512` | HS512 with same payload as `valid` | test_algorithms |
| `unkalg` | HS256 token with header `alg` rewritten to `NONSENSE` | test_algorithms |
| `exp_recent` | HS256, exp = now-1 | test_exp |
| `exp_future` | HS256, exp = now+3600 (alias of `valid`) | test_exp |
| `exp_missing` | HS256, no exp claim | test_exp |
| `b64url_sig` | HS256, signature rewritten to use base64url chars | test_unknown |
| `slots17` | HS256, 17 distinct extra claims | test_limits (slot overflow) |

## Stub vs implemented mode

The C function [`pg_jwt_verify_and_set_role`](../pg_jwt_role.c:1) is a
stub until Step 3 of [`plans/plan.md`](../plans/plan.md:643) lands. While
the stub is in place, every call to `set_role()` raises
*"pg_jwt_role: verify_and_set_role is not yet implemented"*. The harness
treats that as a passing outcome for any test that exercises invalid
inputs (basic, invalid, algorithms, exp, limits, unknown) and skips the
hook assertion in `test_hook`.

Set `PG_JWT_ROLE_IMPLEMENTED=1` (in [`docker-compose.yml`](../docker-compose.yml:1))
once Steps 3 and 4 are merged to switch to the real assertions.

### What is *not* covered yet

- **RS256 / ES256 / RS384 / RS512 / ES384 / ES512** — these need a PEM
  key in `pg_jwt_role.verify_key`, but that GUC is PGC_SIGHUP and the
  harness only starts one cluster with the HS secret. Adding asymmetric
  tests requires either a second cluster (and a way to serialize the
  tests) or committing a fixed test key pair. Tracked as a follow-up.
- **pg_regress-style strict regression** — the harness is still
  grep-based. Migrating to `pg_regress` would let us assert exact
  output, but that's a larger refactor of `run_tests.sh`.

## Running

```bash
docker compose build
docker compose up --abort-on-container-exit --exit-code-from test
```

To run the container directly:

```bash
docker build -t pg-jwt-role:test .
docker run --rm -e PG_JWT_ROLE_IMPLEMENTED=0 pg-jwt-role:test
