# pg_jwt_role

A PostgreSQL 18 extension that performs **JWT-based role switching** inside the
database. A caller invokes `pgjwt.set_role(jwt_token text)`; if the JWT
signature verifies against a configured key, the database role is switched to
whichever role is named in a configurable claim (default `role`), and selected
extra claims (default `sub,email`) are exposed as transaction-local GUCs via
the SQL helper `pgjwt.claim(name)`.

The signature check, JSON parsing, `exp` check, role switch, and GUC writes
happen in a **single atomic C function** — `SetCurrentRoleId` is unreachable
without a verified signature. A `ProcessUtility_hook` additionally blocks
`SET ROLE <other>` for restricted session users, so the JWT path is the only
way to elevate.

> **Schema note:** PostgreSQL reserves the `pg_` prefix for system catalogs, so
> the extension installs its objects into a dedicated `pgjwt` schema (see
> [`pg_jwt_role.control`](pg_jwt_role.control)). The function names
> (`pg_jwt_role.set_role`, `pg_jwt_role.verify_and_set_role`) are part of the
> public API contract and resolve via `pgjwt` once the extension is installed.

For the full architecture, security model, and step-by-step implementation
plan, see [`plans/plan.md`](plans/plan.md:1). For the agent-facing
conventions, see [`AGENTS.md`](AGENTS.md).

---

## Table of contents

- [Building](#building)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Testing](#testing)
- [Repo layout](#repo-layout)
- [Limitations](#limitations)

---

## Building

The extension is plain PGXS — a C11 shared object that links against
`libssl` / `libcrypto`:

```bash
make            # builds pg_jwt_role.so
make install    # installs into $(pg_config --pkglibdir) and $(pg_config --sharedir)
```

[`Makefile`](Makefile:1) adds `-lssl -lcrypto` and the `CFLAGS` of
`-Wall -Wno-unused-parameter -std=c11`. No autoconf; the build is a single
`include $(PGXS)` after `MODULE_big` is set.

### Container build

A multi-stage Alpine + PostgreSQL 18 build is provided for a self-contained
test environment. See [Testing](#testing).

---

## Installation

1. Build and install on the target server (see above).
2. Add the extension to `shared_preload_libraries` so `_PG_init` runs at
   cluster start (it installs the `ProcessUtility_hook`):

   ```ini
   # postgresql.conf
   shared_preload_libraries = 'pg_jwt_role'
   ```

3. Restart PostgreSQL.
4. In every database that should accept JWT-switched roles:

   ```sql
   CREATE EXTENSION pg_jwt_role;
   ```

   The extension is `trusted = false` (see [`pg_jwt_role.control`](pg_jwt_role.control)),
   so the creating role must be a superuser. `superuser = false` because the
   extension registers `PGC_SUSET` GUCs but does not require the creator to be
   one beyond `CREATE EXTENSION` itself.

---

## Configuration

All GUCs are registered in `_PG_init` (see [`pg_jwt_role.c`](pg_jwt_role.c:1)).
Output GUCs (`pg_jwt_role.role` and the 16-slot pool
`pg_jwt_role.claim_0`..`pg_jwt_role.claim_15`) are `PGC_SUSET` so non-superusers
cannot tamper with them through `set_config()`. The C function temporarily
elevates with `SetUserIdAndSecContext` to write them.

### Input GUCs

| GUC | Context | Default | Description |
|-----|---------|---------|-------------|
| `pg_jwt_role.verify_key` | `PGC_SIGHUP` | `""` | Key material for signature verification. Raw secret for `HS256/384/512`; PEM-encoded public key or certificate for `RS256/384/512` and `ES256/384/512`. **Required** — `set_role` errors with `pg_jwt_role.verify_key is not set` otherwise. |
| `pg_jwt_role.role_claim` | `PGC_SUSET` | `role` | JWT claim name containing the target DB role. The default is applied when the GUC is empty. |
| `pg_jwt_role.extra_claims` | `PGC_SUSET` | `sub,email` | Comma-separated list of JWT claim names to expose via `pgjwt.claim(name)`. Up to 16 names, bound to a fixed slot pool at first use. |
| `pg_jwt_role.restricted_session_users` | `PGC_SIGHUP` | `""` | Comma-separated PostgreSQL role names whose `SET ROLE` is intercepted by the `ProcessUtility_hook`. Compared to `session_user` so the restriction persists across role switches. |
| `pg_jwt_role.max_jwt_len` | `PGC_SUSET` | `8192` | Maximum accepted JWT length in bytes. Must be positive. |
| `pg_jwt_role.max_claim_len` | `PGC_SUSET` | `256` | Defensive upper bound on any single claim value. Must be positive. |

### Output GUCs (read-only from SQL, written by the C function)

| GUC | Description |
|-----|-------------|
| `pg_jwt_role.role` | Resolved DB role from the most recent successful `set_role` call. |
| `pg_jwt_role.claim_0` … `pg_jwt_role.claim_15` | A fixed pool of 16 scratch slots. The C function binds a user-facing claim name to a slot on first use (`pg_jwt_claim_slot` in [`pg_jwt_role.c`](pg_jwt_role.c:1)) and writes its value here with `GUC_ACTION_LOCAL`. Read the current value via `pgjwt.claim(name)`. |

Because the C function writes the output GUCs with `GUC_ACTION_LOCAL`, they
revert automatically at `COMMIT` / `ROLLBACK`. The role switch itself
survives the transaction — it is a `SET ROLE` effect on the session, undone
only by `RESET ROLE` or another `set_role` call.

### Example `postgresql.conf` snippet

```ini
shared_preload_libraries = 'pg_jwt_role'

# HS256 secret used by test_jwt_helper.py in the test harness:
pg_jwt_role.verify_key                = 'test-secret-do-not-use-in-prod'
pg_jwt_role.role_claim                = 'role'
pg_jwt_role.extra_claims              = 'sub,email,tenant'
pg_jwt_role.restricted_session_users  = 'app_user,app_service'
```

---

## Usage

A typical request:

```sql
BEGIN;

-- The application forwards the bearer token from the HTTP layer.
SELECT pgjwt.set_role($1);   -- $1 = raw JWT

-- current_user has been switched to the role named in the JWT.
SELECT current_user;

-- Selected extra claims are now readable as transaction-local GUCs.
SELECT pgjwt.claim('sub')   AS jwt_sub,
       pgjwt.claim('email') AS jwt_email;

-- ... your real query here, running as the JWT-claimed role ...

COMMIT;   -- extra-claim GUCs revert; the role switch persists for the session
```

`pgjwt.set_role` returns the resolved role name (`text`) on success and
`ereport(ERROR)` on any verification failure. The error reaches SQL as a
normal `ERROR` and **no side effects occur** — the role is not switched, and
no output GUCs are touched.

### Reading claims outside a transaction

`pgjwt.claim(name)` is `STABLE` and returns the value bound to `name`, or the
empty string if no slot is currently bound. `pgjwt.claim_value(name)` is the
raw underlying helper and returns `NULL` for unbound names (handy with
`COALESCE` / `IS NULL`).

### Restricting `SET ROLE` for sensitive session users

Add the login role to `pg_jwt_role.restricted_session_users`. From that point
on, the `ProcessUtility_hook` ([`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1050))
allows only:

- `SET ROLE <claimed_role>` — the role currently held via `set_role`,
- `SET ROLE NONE`,
- `RESET ROLE`.

Any other `SET ROLE <name>` is rejected with an `ERROR`.

### What the PL/pgSQL wrapper does (and does not) trust

[`pgjwt.set_role`](pg_jwt_role--1.0.sql:105) is intentionally limited to
mechanical operations:

1. Split the JWT by `.` (`split_part`).
2. Convert base64url to base64 (character substitution + `=` padding).
3. `decode(..., 'base64')` the header and payload.
4. Extract `alg` from the header JSON.
5. Hand the rest to the C function.

The PL/pgSQL layer **never** parses the payload, checks `exp`, extracts the
role, or writes GUCs. All of that happens inside the atomic C function, after
`HMAC` / `EVP_DigestVerify` returns success.

---

## Security model

The whole point of the extension is that **there is exactly one way to
become a non-default role inside a session**: a successfully verified JWT.
The model rests on two layers.

### 1. Atomic C function

[`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537) is the only SQL-callable
function that touches `SetCurrentRoleId`. The flow is:

```
verify signature ──► FAIL ──► ereport(ERROR), no side effects
                 └─► OK   ──► JSON-scan payload
                              ├─ check exp vs time(NULL)
                              ├─ extract role_claim → SetCurrentRoleId
                              └─ for each extra_claim:
                                 set_config_option(GUC_ACTION_LOCAL)
                                 under temporary superuser elevation
```

The signature compare for HMAC is constant-time (`CRYPTO_memcmp`). The
JSON parser is a hand-rolled linear scan — no full parser is needed and no
extra allocation happens (`palloc` / `malloc` are not used anywhere; all
buffers are fixed-size on the stack — see [`plans/plan.md` §8](plans/plan.md:408)).

The privilege elevation pattern around `set_config_option` (see
[`plans/plan.md` §9](plans/plan.md:500)):

```c
GetUserIdAndSecContext(&save_uid, &save_sec);
SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID, SECURITY_SUPERUSER);
/* write pg_jwt_role.role + each pg_jwt_role.claim_<N> */
SetUserIdAndSecContext(save_uid, save_sec);
```

This is safe because the elevation is **strictly contained** inside the
function: only the GUC writes happen between save and restore, and only
after the signature has been verified.

### 2. `ProcessUtility_hook`

[`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1050) intercepts `SET ROLE` for
session users listed in `pg_jwt_role.restricted_session_users`:

- Allows `SET ROLE <target>` only when `target`'s OID matches the role
  currently held (`GetCurrentRoleId()`).
- Allows `SET ROLE NONE` and `RESET ROLE`.
- Rejects everything else.

The hook is keyed off `session_user`, not `current_user`, so a restricted
user cannot escape the restriction by first switching to another role.

### Threat model

- ✅ A caller with a validly-signed JWT can become the role the JWT names.
- ✅ A caller with a tampered signature, wrong key, wrong alg, or expired
  `exp` is rejected with no side effects.
- ✅ A restricted session user cannot elevate to any role except via
  `set_role`, and `set_role` requires a valid signature.
- ⚠️ `SET SESSION AUTHORIZATION` is a separate superuser-only escape hatch
  and is **not** intercepted by this extension. Do not grant
  `app_user` / `app_service` superuser; if you need the `SESSION
  AUTHORIZATION` bypass for administrative reasons, use a separate
  superuser account.
- ⚠️ The `verify_key` GUC is `PGC_SIGHUP`: it can be read from
  `pg_file_settings` by any user with `pg_read_server_files`, and
  `SHOW pg_jwt_role.verify_key` is visible to superusers. Treat it as
  secret material.

---

## API reference

### SQL

| Function | Returns | Volatility | Notes |
|----------|---------|------------|-------|
| `pgjwt.set_role(jwt_token text)` | `text` — the resolved role | `VOLATILE` | Atomic signature verify + role switch + extra-claim GUC writes. |
| `pgjwt.verify_and_set_role(alg text, signing_input bytea, signature_b64 text, payload_decoded bytea)` | `text` | `VOLATILE` `STRICT` | The C entry point. Callers should normally use `set_role`; this is exposed for advanced / testing uses. |
| `pgjwt.claim(name text)` | `text` | `STABLE` | Reads the current transaction-local value bound to `name`, or `''` if unbound. |
| `pgjwt.claim_value(name text)` | `text` (nullable) | `VOLATILE` | Raw underlying helper. Returns `NULL` for unbound names. |

All SQL functions install with `SET search_path = pg_catalog` and
`GRANT EXECUTE TO PUBLIC`. The schema is `pgjwt` (see the schema note at
the top of this README).

### C (internal)

| Function | Purpose |
|----------|---------|
| [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537) | The single SQL-callable atomic verify + set-role + set-claims entry point. |
| `pg_jwt_role_ProcessUtility` ([`pg_jwt_role.c:1050`](pg_jwt_role.c:1050)) | `ProcessUtility_hook` implementation. |
| `pg_jwt_claim_value` | SQL-callable lookup of a claim value by user-facing name. |
| `pg_jwt_claim_slot` / `pg_jwt_claim_slot_lookup` / `pg_jwt_claim_slot_guc_name` | Per-backend claim-slot binding helpers used internally. |

---

## Testing

The repo ships a self-contained test harness that spins up a temporary
PostgreSQL 18 cluster inside the [`Dockerfile`](Dockerfile:1) image and runs
all `test/sql/test_*.sql` files. The wrapper exports your host UID/GID so
the container matches your filesystem ownership.

```bash
scripts/test.sh                # build the image and run the tests
scripts/test.sh --no-build     # run without rebuilding
scripts/test.sh --rebuild      # force a clean rebuild
scripts/test.sh --implemented  # explicit: PG_JWT_ROLE_IMPLEMENTED=1 (default)
scripts/test.sh --stub         # PG_JWT_ROLE_IMPLEMENTED=0 — for stub-only runs
```

The `--implemented` flag is now the default; the flag is kept for backwards
compatibility and future stub-only runs.

### Test cases

| File | What it covers |
|------|----------------|
| [`test/sql/test_basic.sql`](test/sql/test_basic.sql:1) | Happy path: signed JWT, role flips, extra claims exposed, `COMMIT` reverts the GUCs. |
| [`test/sql/test_invalid.sql`](test/sql/test_invalid.sql:1) | Expired, bad signature, missing role, unknown role, malformed, empty, garbage inputs. |
| [`test/sql/test_hook.sql`](test/sql/test_hook.sql:1) | `ProcessUtility_hook` for restricted session users (`SET ROLE <other>` blocked, `SET ROLE <claimed>` allowed). |
| [`test/sql/test_algorithms.sql`](test/sql/test_algorithms.sql:1) | `HS256` / `HS384` / `HS512` happy paths + unknown `alg` rejection. |
| [`test/sql/test_exp.sql`](test/sql/test_exp.sql:1) | `exp` boundary: `now-1`, `now+3600`, missing entirely. |
| [`test/sql/test_limits.sql`](test/sql/test_limits.sql:1) | `max_jwt_len` and `max_claim_len` enforcement; 17-extra-claim slot overflow. |
| [`test/sql/test_unknown.sql`](test/sql/test_unknown.sql:1) | Unknown role, missing role claim, base64url signature normalisation, empty / garbage input. |

The harness mints test JWTs with [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1)
and exposes them as session-local GUCs (`pg_jwt_role.test.<name>`) so the
SQL files can call `set_role(current_setting('pg_jwt_role.test.<name>'))`
without juggling temp files. See [`test/README.md`](test/README.md:1) for
the full list of minted tokens.

### Running an individual test by hand

If you have a local PostgreSQL 18 with the extension installed, the SQL
files are plain psql scripts:

```bash
psql -X -v ON_ERROR_STOP=1 -f test/sql/test_basic.sql
```

You will need to have minted the JWTs the file references yourself
(`test_jwt_helper.py` is a self-contained CLI for that) and to have set
`pg_jwt_role.verify_key` to the matching secret.

---

## Repo layout

| File | Purpose |
|------|---------|
| [`Makefile`](Makefile:1) | PGXS build, links `-lssl -lcrypto`, C11. |
| [`pg_jwt_role.control`](pg_jwt_role.control) | Extension metadata (`default_version 1.0`, `schema pgjwt`, `trusted false`). |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | Single C entry point `_PG_init` + atomic [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537) + [`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1050) hook + claim-slot helpers. |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | SQL declarations + PL/pgSQL [`pgjwt.set_role`](pg_jwt_role--1.0.sql:105) wrapper + `pgjwt.claim` / `pgjwt.claim_value` helpers. |
| [`Dockerfile`](Dockerfile:1) | Multi-stage Alpine + PostgreSQL 18 build & test container. |
| [`docker-compose.yml`](docker-compose.yml:1) | Compose service for the test image; passes `HOST_UID` / `HOST_GID`. |
| [`scripts/test.sh`](scripts/test.sh:1) | Host-side wrapper: exports `HOST_UID`/`HOST_GID` and runs the test container. |
| [`test/`](test/) | psql-based smoke tests + [`test_jwt_helper.py`](test/test_jwt_helper.py:1) JWT minter + `run_tests.sh` harness. |
| [`plans/plan.md`](plans/plan.md:1) | Full architecture, GUC table, C internals, test plan. |
| [`AGENTS.md`](AGENTS.md) | Agent-facing conventions and project status. |

---

## Limitations

- **Stack-only buffers.** The C function uses fixed-size stack buffers
  (alg 16, sig 512, key 4096, payload 1024, claim values 256 each × 16).
  Defensive GUCs (`max_jwt_len`, `max_claim_len`) reject inputs that would
  exceed them. If you need to verify very large JWTs, raise those GUCs
  **and** rebuild after widening the buffers in
  [`pg_jwt_role.c`](pg_jwt_role.c:1).
- **Single algorithm per call.** The `alg` is read from the JWT header
  itself; the dispatcher in [`pg_jwt_role.c`](pg_jwt_role.c:1) uses one
  `verify_key` to cover whichever algorithm the token claims. Mixing
  algorithms requires re-keying or running separate databases.
- **No `pg_regress` integration (yet).** The tests are psql-based; a
  `pg_regress` conversion is on the roadmap (see
  [`AGENTS.md`](AGENTS.md) implementation-state table, Step 7 "optional").
- **No JWK rotation, no JWKS, no kid resolution.** `verify_key` is a single
  static blob. Key rotation means a config change + `pg_reload_conf()`.
- **No `exp` leeway / clock skew config.** `exp` is compared against
  `time(NULL)` with a 1-second slack inside the C function. If you need
  leeway, edit [`pg_jwt_role.c`](pg_jwt_role.c:1) near the `exp` check.

---

## License

This project is provided as-is. No license file is included at the time of
writing — add one before publishing.
