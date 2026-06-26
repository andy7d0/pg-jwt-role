# pg_jwt_role — test harness

This directory contains a self-contained smoke-test harness for the
`pg_jwt_role` extension. It runs entirely inside an Alpine + PostgreSQL 18
container built by [`Dockerfile`](../Dockerfile:1).

## Files

| File | Purpose |
|------|---------|
| [`run_tests.sh`](run_tests.sh:1) | Entry point. Spins up a temp cluster, loads the extension, mints test JWTs, runs each `sql/test_*.sql`, prints a PASS/FAIL summary. |
| [`test_jwt_helper.py`](test_jwt_helper.py:1) | CLI helper that mints HS256 JWTs with configurable role, exp, and extra claims. Optionally tampers the signature to produce an invalid token. |
| [`sql/test_basic.sql`](sql/test_basic.sql:1) | Happy-path: a well-signed JWT, expect `current_user` to flip and extra claims to be exposed as transaction-local GUCs. |
| [`sql/test_invalid.sql`](sql/test_invalid.sql:1) | Negative-path: expired / bad-signature / missing-role / unknown-role / malformed / empty / garbage inputs — all must be rejected. |
| [`sql/test_hook.sql`](sql/test_hook.sql:1) | `ProcessUtility_hook` behaviour (Step 4 of [`plans/plan.md`](../plans/plan.md:1)): restricted session users blocked from `SET ROLE <other>`, unmonitored users unaffected. |

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
   - configures `pg_jwt_role.*` GUCs via `ALTER DATABASE ... SET`,
   - mints test JWTs into a temp directory,
   - runs each `sql/test_*.sql` via `psql -X`,
   - greps the output for expected markers and reports PASS/FAIL.

## Stub vs implemented mode

The C function [`pg_jwt_verify_and_set_role`](../pg_jwt_role.c:53) is a
stub until Step 3 of [`plans/plan.md`](../plans/plan.md:643) lands. While
the stub is in place, every call to `set_role()` raises
*"pg_jwt_role: verify_and_set_role is not yet implemented"*. The harness
treats that as a passing outcome for `test_basic` and `test_invalid`,
and skips the hook assertion in `test_hook`.

Set `PG_JWT_ROLE_IMPLEMENTED=1` (in [`docker-compose.yml`](../docker-compose.yml:1))
once Steps 3 and 4 are merged to switch to the real assertions.

## Running

```bash
docker compose build
docker compose up --abort-on-container-exit --exit-code-from test
```

To run the container directly:

```bash
docker build -t pg-jwt-role:test .
docker run --rm -e PG_JWT_ROLE_IMPLEMENTED=0 pg-jwt-role:test
```
