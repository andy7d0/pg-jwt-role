# `pg_jwt_role` — Code Statistics

Snapshot of every source file in the repository, broken down by category.
Numbers come from [`wc -l -c`](Makefile:1) on the working tree at the time
of generation. "Functions" are counted by hand where possible (regex is
fragile across macros like `PG_FUNCTION_INFO_V1`); the values are
approximate but reproducible.

Totals: **22 files · 4,518 lines · 193,035 characters**.

## 1. Category summary

| Category     | Files | Lines  | Chars   | Avg LOC/file |
|--------------|------:|-------:|--------:|-------------:|
| Code         |     7 |  1,776 |  65,136 |         254   |
| Tests        |     9 |  1,096 |  46,765 |         122   |
| Docs         |     4 |  1,377 |  75,672 |         344   |
| Build/Config |     2 |    269 |    5,462 |         135   |
| **Total**    | **22**| **4,518** | **193,035** | **205** |

Category placement rules used in this report:

- **Code** — languages that get compiled or interpreted at runtime: `.c`,
  `.sql` (the extension's install/script), `.py` helpers used by the test
  runner.
- **Tests** — SQL `.sql` files under `test/sql/` exercising the extension,
  plus the [`test/run_tests.sh`](test/run_tests.sh:1) driver and
  [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1) (helper invoked
  *by* the test driver to forge/tamper tokens — counted as tests since it
  has no production callers).
- **Docs** — Markdown intended for humans: `README.md`, `AGENTS.md`,
  [`plans/plan.md`](plans/plan.md:1), [`plans/coverage.md`](plans/coverage.md:1),
  [`test/README.md`](test/README.md:1).
- **Build/Config** — [`Makefile`](Makefile:1),
  [`pg_jwt_role.control`](pg_jwt_role.control),
  [`Dockerfile`](Dockerfile:1), [`docker-compose.yml`](docker-compose.yml:1),
  [`scripts/test.sh`](scripts/test.sh:1) (thin host-UID wrapper around
  `docker compose` — closer to CI plumbing than application code).

## 2. Per-file breakdown

### 2.1 Code (7 files, 1,776 LoC, 65,136 chars)

| File | Lines | Chars | Comment lines | Functions |
|------|------:|------:|--------------:|----------:|
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 1,302 | 46,117 | 434 | 10 |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | 172 | 7,618 | 87 | 4 |
| [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1) | 131 | 4,933 | 18 | 6 |
| [`scripts/test.sh`](scripts/test.sh:1) | 68 | 2,330 | 35 | 0¹ |
| [`test/run_tests.sh`](test/run_tests.sh:1) | 537 | 23,660 | 122 | 5 |

¹ [`scripts/test.sh`](scripts/test.sh:1) is a flat top-level bash script
(no `foo() { … }` definitions) — it just exports UID/GID and invokes
`docker compose run`.

**C function inventory in [`pg_jwt_role.c`](pg_jwt_role.c:1)** (10
definitions + 1 module-magic macro):

| Line | Symbol | Kind |
|-----:|--------|------|
| 100  | `PG_MODULE_MAGIC` | Module linkage macro |
| 243  | [`pg_json_extract_value`](pg_jwt_role.c:242) | static helper |
| 329  | [`pg_split_csv`](pg_jwt_role.c:328) | static helper |
| 396  | [`pg_jwt_verify`](pg_jwt_role.c:377) | static helper (alg dispatch) |
| 555  | [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:537) | SQL-callable (`PG_FUNCTION_ARGS`) |
| 835  | [`pg_jwt_claim_slot`](pg_jwt_role.c:817) | extern helper |
| 879  | [`pg_jwt_claim_slot_lookup`](pg_jwt_role.c:861) | extern helper |
| 904  | [`pg_jwt_claim_slot_guc_name`](pg_jwt_role.c:886) | extern helper |
| 929  | [`pg_jwt_claim_value`](pg_jwt_role.c:929) | SQL-callable (`PG_FUNCTION_ARGS`) |
| 1068 | [`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:1049) | ProcessUtility hook |
| 1151 | [`_PG_init`](pg_jwt_role.c:1133) | `_PG_init` (loads GUCs + hook) |

**SQL/PLpgSQL function inventory in [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1)** (4 `CREATE FUNCTION`):

| Line | Name |
|-----:|------|
| 60   | `pgjwt.verify_and_set_role` (C-callable wrapper) |
| 79   | `pgjwt.claim_value` (C-callable wrapper) |
| 89   | `pgjwt.claim` (SQL helper, `STABLE`) |
| 105  | `pgjwt.set_role` (PL/pgSQL wrapper) |

**Python function inventory in [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1)** (6 `def`s):

| Line | Name |
|-----:|------|
| 41   | `b64url_decode` |
| 47   | `b64url_encode` |
| 51   | `std_b64url_mix` |
| 71   | `tamper_signature` |
| 79   | `b64urlify_signature` |
| 85   | `main` |

**Bash function inventory in [`test/run_tests.sh`](test/run_tests.sh:1)** (5 functions).

### 2.2 Tests (9 files, 1,096 LoC, 46,765 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`test/sql/test_basic.sql`](test/sql/test_basic.sql:1) | 64 | 2,498 |
| [`test/sql/test_invalid.sql`](test/sql/test_invalid.sql:1) | 35 | 1,111 |
| [`test/sql/test_hook.sql`](test/sql/test_hook.sql:1) | 102 | 4,916 |
| [`test/sql/test_algorithms.sql`](test/sql/test_algorithms.sql:1) | 55 | 2,317 |
| [`test/sql/test_exp.sql`](test/sql/test_exp.sql:1) | 43 | 1,662 |
| [`test/sql/test_limits.sql`](test/sql/test_limits.sql:1) | 81 | 3,679 |
| [`test/sql/test_unknown.sql`](test/sql/test_unknown.sql:1) | 48 | 1,889 |

(Plus the test driver / helpers already counted under Code:
[`test/run_tests.sh`](test/run_tests.sh:1) and
[`test/test_jwt_helper.py`](test/test_jwt_helper.py:1).)

### 2.3 Docs (4 files, 1,377 LoC, 75,672 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`README.md`](README.md) | 388 | 17,496 |
| [`AGENTS.md`](AGENTS.md) | 241 | 14,474 |
| [`plans/plan.md`](plans/plan.md:1) | 776 | 34,167 |
| [`plans/coverage.md`](plans/coverage.md:1) | 133 | 9,535 |
| [`test/README.md`](test/README.md:1) | 97 | 5,562 |

Note: [`plans/plan.md`](plans/plan.md:1) is the largest single file at
**776 lines / 34,167 chars**, but per [`AGENTS.md`](AGENTS.md) it is
historical-only and not the source of truth.

### 2.4 Build / Config (5 files, 269 LoC, 5,462 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`Makefile`](Makefile:1) | 17 | 428 |
| [`pg_jwt_role.control`](pg_jwt_role.control) | 19 | 1,019 |
| [`Dockerfile`](Dockerfile:1) | 134 | 5,181 |
| [`docker-compose.yml`](docker-compose.yml:1) | 75 | 2,443 |
| [`scripts/test.sh`](scripts/test.sh:1) | 68 | 2,330 |

## 3. Language breakdown (across all files)

| Language / format | Files | Lines | Chars |
|-------------------|------:|------:|------:|
| C (`.c`)           | 1 | 1,302 | 46,117 |
| SQL / PLpgSQL (`.sql`) | 8 | 1,600 | 22,810 |
| Markdown (`.md`)   | 5 | 1,635 | 81,234 |
| Python (`.py`)     | 1 | 131 | 4,933 |
| Bash (`.sh`)       | 2 | 605 | 25,990 |
| Dockerfile         | 1 | 134 | 5,181 |
| YAML (`.yml`)      | 1 | 75 | 2,443 |
| Make (`Makefile`)  | 1 | 17 | 428 |
| Extension control (`.control`) | 1 | 19 | 1,019 |

## 4. Code-vs-comment ratios (production source only)

| File | Lines | Comment lines | Comment density |
|------|------:|--------------:|----------------:|
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 1,302 | 434 | **33%** |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | 172 | 87 | **51%** |
| [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1) | 131 | 18 | 14% |
| [`scripts/test.sh`](scripts/test.sh:1) | 68 | 35 | 51% |
| [`test/run_tests.sh`](test/run_tests.sh:1) | 537 | 122 | 23% |

The C source is unusually comment-dense for a Postgres extension (33%
comment lines), reflecting the deliberate "self-documenting security
model" called out in [`AGENTS.md`](AGENTS.md).

## 5. Function totals

| Language | Functions defined |
|----------|------------------:|
| C (in [`pg_jwt_role.c`](pg_jwt_role.c:1)) | 10 (+ 1 module-magic macro) |
| SQL/PLpgSQL (in [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1)) | 4 |
| Python (in [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1)) | 6 |
| Bash (in [`test/run_tests.sh`](test/run_tests.sh:1)) | 5 |
| **Total** | **25** (+ 1 macro) |

## 6. How to regenerate

```bash
# Per-file line + char counts
wc -l -c $(find . -type f \
   -not -path './.git/*' \
   -not -path './code-stat.md') | sort -k2 -n

# Comment density per production file
for f in pg_jwt_role.c pg_jwt_role--1.0.sql \
         test/test_jwt_helper.py scripts/test.sh \
         test/run_tests.sh; do
  printf '%-40s %5d total / %5d comment\n' \
    "$f" "$(wc -l < "$f")" \
    "$(grep -cE '^\s*(//|/\*|\*|--|#|\"\"\")' "$f")"
done

# Function inventory
grep -nE '^[A-Za-z_].*\(' pg_jwt_role.c
grep -nE 'CREATE\s+(OR\s+REPLACE\s+)?FUNCTION' pg_jwt_role--1.0.sql
grep -nE '^\s*def\s+' test/test_jwt_helper.py
grep -nE '^[A-Za-z_][A-Za-z0-9_]*\(\)' test/run_tests.sh