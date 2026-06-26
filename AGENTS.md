# AGENTS.md — Guide for AI Coding Agents

This file is the source of truth for [`pg_jwt_role`](Makefile) as it exists
in the repo today. It reflects only what is implemented and how the code
is wired together.

`plans/plan.md` is kept on disk for historical reference — it captures the
original design and the step-by-step execution order we followed when the
extension was being built. Every step in that plan has landed; nothing in
`AGENTS.md` should defer to it as a future-work plan. If a section here
contradicts `plans/plan.md`, this file wins.

## What this project is

[`pg_jwt_role`](pg_jwt_role.c:1) is a PostgreSQL 18 extension that performs
**JWT-based role switching**. A caller invokes
[`pgjwt.set_role(jwt_token text)`](pg_jwt_role--1.0.sql:105); if the JWT
signature verifies against a configured key, the database role is switched to
whatever role is named in a configurable claim (default `role`), and selected
extra claims (default `sub,email`) are exposed as transaction-local GUCs
via the SQL helper `pgjwt.claim(name)`.

A `ProcessUtility_hook` blocks `SET ROLE <other>` for restricted session users
so the JWT path is the only way to elevate.

## The non-negotiable security rule

> **Atomicity boundary.** [`SetCurrentRoleId()`](pg_jwt_role.c:736) is only
> reachable *after* a successful OpenSSL signature check, and only via the
> single C function [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537).

Never add a separate SQL-callable function that touches
`SetCurrentRoleId` / role state without going through signature verification
first. The whole security model depends on this single atomic call.

The PL/pgSQL layer ([`pgjwt.set_role`](pg_jwt_role--1.0.sql:105)) is intentionally
limited to *mechanical* operations: `split_part`, base64url→base64 character
substitution with `=` padding, `decode(..., 'base64')`, and header `alg`
extraction. Anything that requires trusting the JWT (JSON-parse of payload,
`exp` check, role extraction, GUC writes) happens **inside** the C function,
after `HMAC` / `EVP_DigestVerify` returns success.

## Architecture at a glance

```
PL/pgSQL set_role(text)              C verify_and_set_role(...) → text
───────────────────────              ────────────────────────────────────
split_part(token, '.', 1/2/3)   →    OpenSSL verify (HS* / RS* / ES*)
replace('-','+') '_','/'             ├─ FAIL → ereport(ERROR), no side effects
+= '=' padding to multiple of 4       └─ OK   → JSON-scan payload
decode(..., 'base64')                    ├─ check exp vs time(NULL)
extract 'alg' from header                ├─ extract role_claim → SetCurrentRoleId
delegate to C function                    └─ for each extra_claim:
                                            pg_jwt_claim_slot + set_config_option(GUC_ACTION_LOCAL)

ProcessUtility_hook (separate)
──────────────────────────────
Intercepts SET ROLE for session_users listed in
pg_jwt_role.restricted_session_users. Allowed only if target ==
JWT-claimed role, or if command is SET ROLE NONE / RESET ROLE.
Keyed off session_user, not current_user.
```

## Repo layout

| File | Purpose |
|------|---------|
| [`Makefile`](Makefile:1) | PGXS build, links `-lssl -lcrypto`, C11 |
| [`pg_jwt_role.control`](pg_jwt_role.control) | Extension metadata (`default_version 1.0`, `schema pgjwt`, `superuser=false`, `trusted=false`) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | Single C entry point `_PG_init` + `pg_jwt_verify_and_set_role` + `pg_jwt_claim_value` + `pg_jwt_role_ProcessUtility` |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | `pgjwt.verify_and_set_role`, `pgjwt.claim_value`, `pgjwt.claim`, PL/pgSQL `pgjwt.set_role` wrapper |
| [`Dockerfile`](Dockerfile:1) | Multi-stage Alpine + PG 18 build, host UID mapping |
| [`docker-compose.yml`](docker-compose.yml:1) | Test runner + optional `pg` companion service |
| [`scripts/test.sh`](scripts/test.sh:1) | Host-UID-aware wrapper around `docker compose run` |
| [`test/`](test/) | SQL smoke tests + Python JWT helper (`test_jwt_helper.py`) |
| [`README.md`](README.md) | User-facing install / configuration / API docs |
| [`plans/plan.md`](plans/plan.md:1) | Historical design document. **Not** the source of truth — see top of file. |

The extension installs into a dedicated schema named `pgjwt` (see
[`pg_jwt_role.control`](pg_jwt_role.control)). PostgreSQL reserves the
`pg_` prefix for system catalogs, so the extension can't install into
a `pg_jwt_role` schema itself; call sites refer to the functions as
`pgjwt.set_role()` and `pgjwt.verify_and_set_role()`.

## Implementation status

All steps from the original plan have landed. There is no pending work in
`AGENTS.md`. Open follow-ups (if any) live in code comments or `README.md`
limitations, not here.

| Step | Status | Where it lives |
|------|--------|----------------|
| 1 — project skeleton | ✅ done | [`Makefile`](Makefile:1), [`pg_jwt_role.control`](pg_jwt_role.control), [`pg_jwt_role.c`](pg_jwt_role.c:1), [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) |
| 2 — GUC registration in `_PG_init` | ✅ done | [`_PG_init`](pg_jwt_role.c:1133): config GUCs (`verify_key`, `role_claim`, `extra_claims`, `restricted_session_users`, `max_jwt_len`, `max_claim_len`) + output GUC `pg_jwt_role.role` + 16-slot pool `pg_jwt_role.claim_0..claim_15` + slot-binding helpers `pg_jwt_claim_slot` / `pg_jwt_claim_slot_lookup` / `pg_jwt_claim_slot_guc_name` |
| 3 — atomic C function body | ✅ done | [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537): HS256/384/512 + RS*/ES* dispatch via [`pg_jwt_verify`](pg_jwt_role.c:377), constant-time `CRYPTO_memcmp` HMAC, [`pg_json_extract_value`](pg_jwt_role.c:242) JSON scanner, `exp` check, [`SetCurrentRoleId`](pg_jwt_role.c:736) + GUC writes under temporary superuser elevation via `SetUserIdAndSecContext`. [`pg_split_csv`](pg_jwt_role.c:328) ereports `ERRCODE_INVALID_PARAMETER_VALUE` when an `extra_claims` entry exceeds `PG_JWT_MAX_CLAIM_NAME_LEN - 1` (P2.5 hardening; misconfigured long claim names are rejected instead of silently truncated) |
| 4 — `ProcessUtility_hook` | ✅ done | Installed in [`_PG_init`](pg_jwt_role.c:1282), implemented as [`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1049). Restricts `SET ROLE <other>` for session_users in `pg_jwt_role.restricted_session_users`; allows `SET ROLE <claimed>`, `SET ROLE NONE`, `RESET ROLE`. Keyed off `session_user`, not `current_user` |
| 5 — PL/pgSQL wrapper | ✅ done | [`pgjwt.set_role`](pg_jwt_role--1.0.sql:105): splits by `.`, base64url → base64 with `=` padding for the PG-strict decoder, decodes header for `alg`, delegates everything trust-requiring to the atomic C function |
| 6 — Dockerfile + compose | ✅ done | [`Dockerfile`](Dockerfile:1) (multi-stage Alpine + PG 18, host UID/GID via `adduser`), [`docker-compose.yml`](docker-compose.yml:1) (`test` + optional `pg` profile) |
| 7 — tests | ✅ done | [`test_basic`](test/sql/test_basic.sql), [`test_invalid`](test/sql/test_invalid.sql), [`test_hook`](test/sql/test_hook.sql), [`test_algorithms`](test/sql/test_algorithms.sql), [`test_exp`](test/sql/test_exp.sql), [`test_limits`](test/sql/test_limits.sql), [`test_unknown`](test/sql/test_unknown.sql) + [`test_jwt_helper.py`](test/test_jwt_helper.py). Run with `scripts/test.sh` (default is the implemented-mode assertions; `--stub` reproduces the legacy stub behaviour, which no longer matches the code) |
| 8 — README | ✅ done | [`README.md`](README.md): install, configuration GUCs, usage, security model, API reference, test commands, limitations |

### Documented deviations from the original plan

Two architectural choices in the implementation differ from `plans/plan.md`.
Both are already justified in code comments and the SQL file's header. They
are listed here so agents don't try to "fix" them by reverting to the plan.

1. **Slot pool instead of one GUC per claim name.** [`plans/plan.md` §5](plans/plan.md:223)
   imagines a `pg_jwt_role.<claim_name>` GUC registered dynamically for each
   name in `pg_jwt_role.extra_claims`. PGXS does not support registering
   custom GUCs outside of `_PG_init`, so the implementation registers a
   fixed pool of 16 slots (`pg_jwt_role.claim_0..claim_15`) and binds claim
   names to slots lazily at first use. See the file-header comment on
   [`pg_jwt_role.c`](pg_jwt_role.c:37) and the binding helpers
   [`pg_jwt_claim_slot`](pg_jwt_role.c:817) /
   [`pg_jwt_claim_slot_lookup`](pg_jwt_role.c:861) /
   [`pg_jwt_claim_slot_guc_name`](pg_jwt_role.c:886).
2. **`pgjwt` schema instead of `pg_jwt_role`.** [`plans/plan.md` §6](plans/plan.md:249)
   uses `pg_jwt_role.set_role(...)` literally; PostgreSQL reserves the
   `pg_` prefix for system catalogs, so the extension installs into a
   `pgjwt` schema ([`pg_jwt_role.control`](pg_jwt_role.control)) and call
   sites use `pgjwt.set_role(...)`. The SQL header comment on
   [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) flags this.

## Running the tests

```bash
scripts/test.sh                # build the image and run the tests (IMPLEMENTED=1)
scripts/test.sh --no-build     # run without rebuilding
scripts/test.sh --rebuild      # force a clean rebuild
scripts/test.sh --stub         # run with PG_JWT_ROLE_IMPLEMENTED=0 (legacy expectations)
scripts/test.sh --implemented  # run with PG_JWT_ROLE_IMPLEMENTED=1 (default)
```

The wrapper exports `HOST_UID` / `HOST_GID` from your shell so the
container builds and runs as you. The image creates a matching user
account at build time (`adduser -u $HOST_UID -G $HOST_GID`) so
initdb's `getpwnam()` check succeeds without any `pg_passwd`
gymnastics inside the container.

The default mode (`PG_JWT_ROLE_IMPLEMENTED=1`) exercises the full
Steps 3/4/5 implementation; `--stub` exists for reproducing the
historical stub-mode expectations only — it does not match the code
shipped today and should be considered archival.

## C implementation rules (Step 3)

These are hard constraints originally from `plans/plan.md` §8 and now baked
into the code:

- **No `palloc`, no `malloc`.** Use only fixed-size stack buffers.
  Reference sizes from the plan: alg 16, sig 512, key 4096, payload 1024,
  claim values 256 each × 16. See [`pg_jwt_role.c:113-133`](pg_jwt_role.c:113).
- **Constant-time signature compare.** Use `CRYPTO_memcmp` for HMAC
  ([`pg_jwt_role.c:460`](pg_jwt_role.c:460)).
- **Algorithm dispatch** based on the `alg` arg passed from PL/pgSQL
  ([`pg_jwt_verify`](pg_jwt_role.c:377)):
  - `HS256/384/512` → `HMAC(EVP_sha*, ...)`
  - `RS256/384/512` → `EVP_DigestVerify*` with PEM RSA key from `verify_key`
  - `ES256/384/512` → `EVP_DigestVerify*` with PEM EC key from `verify_key`
- **JSON parsing** is a hand-rolled linear scan with `strstr` — no full parser
  needed ([`pg_json_extract_value`](pg_jwt_role.c:242)).
- **Privilege elevation for GUC writes.** Output GUCs are registered
  `PGC_SUSET`, so non-superusers can't `set_config()` them directly. Inside
  the C function, after signature passes, [`SetCurrentRoleId`](pg_jwt_role.c:736)
  is followed by:
  ```c
  GetUserIdAndSecContext(&save_userid, &save_sec);
  SetUserIdAndSecContext(10, 0); /* bootstrap superuser, no security flags */
  /* for each extra claim name:
   *   slot = pg_jwt_claim_slot(name);
   *   pg_jwt_claim_slot_guc_name(slot, guc_name, sizeof(guc_name));
   *   set_config_option(guc_name, value, PGC_SUSET, PGC_S_SESSION,
   *                     GUC_ACTION_LOCAL, true, 0, false);
   */
  SetUserIdAndSecContext(save_userid, save_sec);
  ```
  The hard-coded `10` is `BOOTSTRAP_SUPERUSERID` — PG 18 removed the
  public macro, but the value is stable. The PG 18 security context is a
  bitmask where zero flags signals "superuser"; the comment block at
  [`pg_jwt_role.c:738-749`](pg_jwt_role.c:738) explains.
  `pg_jwt_claim_slot(name)` lazily binds `name` to a free slot in the
  per-backend static table; existing bindings are reused.

## ProcessUtility hook rules (Step 4)

- Restriction is keyed off **`session_user`**, not `current_user` — so the
  restriction persists across role switches inside the session.
- Allow `SET ROLE <claimed_role>` (matches `GetCurrentRoleId()`), `SET ROLE NONE`,
  and `RESET ROLE`. Block everything else for restricted session users.
- Chain to `next_ProcessUtility_hook` (or `standard_ProcessUtility`) at the end.
- `SET SESSION AUTHORIZATION` is superuser-only — do not intercept.

## Build / test commands (host build, no Docker)

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

The Docker wrapper ([`scripts/test.sh`](scripts/test.sh:1)) is the
recommended test path because it pins the PG 18 toolchain and host UID.

## Style conventions

- **C**: C11, `-Wall -Wno-unused-parameter` (from [`Makefile`](Makefile:18)).
  Match the existing comment style in [`pg_jwt_role.c`](pg_jwt_role.c:1).
- **SQL/PLpgSQL**: `SET search_path = pg_catalog` on every function; `STRICT`
  on the C function; `VOLATILE` everywhere role work happens (role switch is
  volatile by nature). The `pgjwt.claim(name)` read helper is `STABLE` since
  it does not change role state.
- **Naming**: `pg_jwt_*` prefix for C internal helpers, `pg_jwt_role.*` for
  GUCs, `pgjwt.*` for SQL-callable functions (matches the `pgjwt` schema).
- **Comments**: file-header comment on `pg_jwt_role.c` enumerates which plan
  steps are landed; keep it in sync if new steps appear.

## When you're unsure

1. Re-read this file. It is the source of truth for the current code.
2. `plans/plan.md` is historical only — use it to understand the *why* of a
   design decision, not to learn what *should* exist. If this file and the
   plan disagree, this file wins.
3. The security model has exactly two layers — **atomic C function** and
   **ProcessUtility hook**. Anything you add should fit into one of them or
   be clearly outside the trust boundary (e.g., the PL/pgSQL wrapper).
4. If a change seems to require a new SQL-callable path to
   `SetCurrentRoleId`, **stop and reconsider** — the atomicity rule is the
   whole point.