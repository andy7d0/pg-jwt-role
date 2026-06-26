# AGENTS.md — Guide for AI Coding Agents

This file gives AI coding agents the minimum context needed to work effectively on
[`pg_jwt_role`](Makefile). For the full architecture, security model, and step-by-step
implementation plan, read [`plans/plan.md`](plans/plan.md:1).

## What this project is

[`pg_jwt_role`](pg_jwt_role.c:1) is a PostgreSQL 18 extension that performs
**JWT-based role switching**. A caller invokes
[`pg_jwt_role.set_role(jwt_token text)`](pg_jwt_role--1.0.sql:27); if the JWT
signature verifies against a configured key, the database role is switched to
whatever role is named in a configurable claim (default `role`), and selected
extra claims (default `sub,email`) are exposed as transaction-local GUCs
via the SQL helper `pgjwt.claim(name)`.

A `ProcessUtility_hook` blocks `SET ROLE <other>` for restricted session users
so the JWT path is the only way to elevate.

## The non-negotiable security rule

> **Atomicity boundary.** [`SetCurrentRoleId()`](pg_jwt_role.c:39) is only
> reachable *after* a successful OpenSSL signature check, and only via the
> single C function [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:39).

Never add a separate SQL-callable function that touches
`SetCurrentRoleId` / role state without going through signature verification
first. The whole security model depends on this single atomic call.

The PL/pgSQL layer ([`set_role`](pg_jwt_role--1.0.sql:27)) is intentionally
limited to *mechanical* operations: `split_part`, base64url→base64 character
substitution, `decode(..., 'base64')`, and header `alg` extraction. Anything
that requires trusting the JWT (JSON-parse of payload, `exp` check, role
extraction, GUC writes) happens **inside** the C function, after `HMAC` /
`EVP_DigestVerify` returns success.

## Architecture at a glance

```
PL/pgSQL set_role(text)              C verify_and_set_role(...) → text
───────────────────────              ────────────────────────────────────
split_part(token, '.', 1/2/3)   →    OpenSSL verify (HS* / RS* / ES*)
replace('-','+') '_','/'             ├─ FAIL → ereport(ERROR), no side effects
decode(..., 'base64')                └─ OK   → JSON-scan payload
extract 'alg' from header                ├─ extract role_claim → SetCurrentRoleId
delegate to C function                    ├─ check exp vs time(NULL)
                                         └─ for each extra_claim:
                                            set_config_option(GUC_ACTION_LOCAL)

ProcessUtility_hook (separate)
──────────────────────────────
Intercepts SET ROLE for session_users listed in
pg_jwt_role.restricted_session_users. Allowed only if target ==
JWT-claimed role, or if command is SET ROLE NONE / RESET ROLE.
```

## Repo layout

| File | Purpose |
|------|---------|
| [`Makefile`](Makefile:1) | PGXS build, links `-lssl -lcrypto`, C11 |
| [`pg_jwt_role.control`](pg_jwt_role.control) | Extension metadata (default_version `1.0`) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | Single C entry point `_PG_init` + `pg_jwt_verify_and_set_role` |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | SQL declarations + PL/pgSQL `set_role` wrapper |
| [`plans/plan.md`](plans/plan.md:1) | Full architecture, GUC table, C internals, test plan |

Now present: [`pg_jwt_role.c`](pg_jwt_role.c:1) (with GUCs registered),
[`Dockerfile`](Dockerfile:1), [`docker-compose.yml`](docker-compose.yml:1),
[`scripts/test.sh`](scripts/test.sh:1), and the [`test/`](test/) directory
(SQL smoke tests + Python JWT helper). See [`plans/plan.md` §4](plans/plan.md:198).

The extension installs into a dedicated schema named `pgjwt` (see
[`pg_jwt_role.control`](pg_jwt_role.control)). PostgreSQL reserves the
`pg_` prefix for system catalogs, so the extension can't install into
a `pg_jwt_role` schema itself; call sites refer to the functions as
`pgjwt.set_role()` and `pgjwt.verify_and_set_role()`.

## Implementation state

| Step | Status | What's done | What's next |
|------|--------|-------------|-------------|
| 1 — project skeleton | ✅ done | Makefile, .control, C stub, SQL/PLpgSQL wrapper | — |
| 2 — GUC registration in `_PG_init` | ✅ done | Config GUCs (PGC_SIGHUP/PGC_SUSET) + `pg_jwt_role.role` + 16 slot GUCs `pg_jwt_role.claim_0`..`claim_15` + slot-binding helpers `pg_jwt_claim_slot`/`pg_jwt_claim_slot_lookup`/`pg_jwt_claim_slot_guc_name` + SQL helper `pgjwt.claim(name)` | — |
| 3 — atomic C function body | ✅ done | Full impl of [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537) in [`pg_jwt_role.c`](pg_jwt_role.c:1): HS256/384/512 + RS*/ES* dispatch, constant-time `CRYPTO_memcmp` HMAC, `pg_jwt_verify` algorithm table, hand-rolled `pg_json_extract_value` JSON scanner, `exp` check, `SetCurrentRoleId` + GUC writes under temporary superuser elevation via `SetUserIdAndSecContext` | — |
| 4 — `ProcessUtility_hook` | ✅ done | Installed in `_PG_init`, implemented as [`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1050) in [`pg_jwt_role.c`](pg_jwt_role.c:1). Restricts `SET ROLE <other>` for session_users in `pg_jwt_role.restricted_session_users`; allows `SET ROLE <claimed>`, `SET ROLE NONE`, `RESET ROLE`. Keyed off `session_user`, not `current_user` | — |
| 5 — PL/pgSQL wrapper | ✅ done (landed) | [`pgjwt.set_role`](pg_jwt_role--1.0.sql:87) in [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1): splits by `.`, base64url → base64 + `=` padding for the PG-strict decoder, decodes header for `alg`, delegates everything trust-requiring to the atomic C function. Schema is `pgjwt` per extension-control; see [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql) header comment for the schema-name deviation from plan §6 | — |
| 6 — Dockerfile + compose | ✅ done | Multi-stage Alpine + PG 18 build, host UID mapping | — |
| 7 — tests | ✅ done | [`test_basic`](test/sql/test_basic.sql), [`test_invalid`](test/sql/test_invalid.sql), [`test_hook`](test/sql/test_hook.sql), [`test_algorithms`](test/sql/test_algorithms.sql), [`test_exp`](test/sql/test_exp.sql), [`test_limits`](test/sql/test_limits.sql), [`test_unknown`](test/sql/test_unknown.sql) + [`test_jwt_helper.py`](test/test_jwt_helper.py). Run with `scripts/test.sh --implemented` to exercise the full Steps 3/4/5 impl; default mode asserts the stub's "not yet implemented" behaviour | optional: convert to `pg_regress` for a proper expected-output workflow |
| 8 — README | ⏳ todo | — | install / config / security model docs |

## Running the tests

```bash
scripts/test.sh                # build the image and run the tests
scripts/test.sh --no-build     # run without rebuilding
scripts/test.sh --rebuild      # force a clean rebuild
scripts/test.sh --implemented  # run with PG_JWT_ROLE_IMPLEMENTED=1
```

The wrapper exports `HOST_UID`/`HOST_GID` from your shell so the
container builds and runs as you. The image creates a matching user
account at build time (`adduser -u $HOST_UID -G $HOST_GID`) so
initdb's `getpwnam()` check succeeds without any `pg_passwd`
gymnastics inside the container.

## C implementation rules (Step 3)

These are hard constraints from [`plans/plan.md` §8](plans/plan.md:408):

- **No `palloc`, no `malloc`.** Use only fixed-size stack buffers.
  Reference sizes from the plan: alg 16, sig 512, key 4096, payload 1024,
  claim values 256 each × 16.
- **Constant-time signature compare.** Use `CRYPTO_memcmp` for HMAC.
- **Algorithm dispatch** based on the `alg` arg passed from PL/pgSQL:
  - `HS256/384/512` → `HMAC(EVP_sha*, ...)`
  - `RS256/384/512` → `EVP_DigestVerify*` with PEM RSA key from `verify_key`
  - `ES256/384/512` → `EVP_DigestVerify*` with PEM EC key from `verify_key`
- **JSON parsing** is a hand-rolled linear scan with `strstr` — no full parser
  needed (see [`pg_json_extract_value`](plans/plan.md:429)).
- **Privilege elevation for GUC writes.** Output GUCs are registered
  `PGC_SUSET`, so non-superusers can't `set_config()` them directly. Inside
  the C function, after signature passes, wrap `set_config_option` calls in:
  ```c
  GetUserIdAndSecContext(&save_uid, &save_sec);
  SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID, SECURITY_SUPERUSER);
  /* for each extra claim name:
   *   slot = pg_jwt_claim_slot(name);
   *   pg_jwt_claim_slot_guc_name(slot, guc_name, sizeof(guc_name));
   *   set_config_option(guc_name, value, PGC_SUSET, PGC_S_SESSION,
   *                     GUC_ACTION_LOCAL, true, 0, false);
   */
  SetUserIdAndSecContext(save_uid, save_sec);
  ```
  `pg_jwt_claim_slot(name)` lazily binds `name` to a free slot in the
  per-backend static table (see Step 2 in the table above); existing
  bindings are reused. See [`plans/plan.md` §9](plans/plan.md:500).

## ProcessUtility hook rules (Step 4)

- Restriction is keyed off **`session_user`**, not `current_user` — so the
  restriction persists across role switches inside the session.
- Allow `SET ROLE <claimed_role>` (matches `GetCurrentRoleId()`), `SET ROLE NONE`,
  and `RESET ROLE`. Block everything else for restricted session users.
- Chain to `next_ProcessUtility_hook` (or
  `standard_ProcessUtility`) at the end.
- `SET SESSION AUTHORIZATION` is superuser-only — do not intercept.
- See [`plans/plan.md` §7](plans/plan.md:322) for the canonical implementation.

## Build / test commands

The extension builds with standard PGXS:

```bash
make            # builds pg_jwt_role.so
make install    # installs into $(pg_config --pkglibdir) and $(pg_config --sharedir)
```

To load it, add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_jwt_role'
```

then in SQL:

```sql
CREATE EXTENSION pg_jwt_role;
```

Tests are not yet wired up — when implementing Step 7, follow the
`pg_regress`-style layout shown in [`plans/plan.md` §4](plans/plan.md:198) and
the cases in [`plans/plan.md` §11](plans/plan.md:611).

## Style conventions

- **C**: C11, `-Wall -Wno-unused-parameter` (from [`Makefile`](Makefile:18)).
  Match the existing comment style in [`pg_jwt_role.c`](pg_jwt_role.c:1).
- **SQL/PLpgSQL**: `SET search_path = pg_catalog` on every function; `STRICT`
  on the C function; `VOLATILE` everywhere (role switch is volatile by nature).
- **Naming**: `pg_jwt_*` prefix for C internal helpers, `pg_jwt_role.*` for
  GUCs, `pg_jwt_role.*` for SQL functions.
- **Comments**: file-header comment on `pg_jwt_role.c` should mention which
  plan step is current — keep it in sync as steps land.

## When you're unsure

1. Re-read [`plans/plan.md`](plans/plan.md:1). It is the source of truth.
2. The security model has exactly two layers — **atomic C function** and
   **ProcessUtility hook**. Anything you add should fit into one of them or
   be clearly outside the trust boundary (e.g., the PL/pgSQL wrapper).
3. If a change seems to require a new SQL-callable path to
   `SetCurrentRoleId`, **stop and reconsider** — the atomicity rule is the
   whole point.