# `pg_jwt_role` — Code Statistics

Snapshot of every source file in the repository, broken down by category.
Numbers come from `wc -l -c` on the working tree at the time of generation.
"Functions" are counted by hand where possible (regex is fragile across macros
like `PG_FUNCTION_INFO_V1`); the values are approximate but reproducible.

Totals: **28 files · 4,804 lines · 204,719 characters**.
([`code-stat.md`](code-stat.md:1) itself is excluded from the count; the build
cache `test/__pycache__/*.pyc` is excluded as a build artefact.)

## 1. Category summary

| Category     | Files | Lines  | Chars    | Avg LOC/file |
|--------------|------:|-------:|---------:|-------------:|
| Code         |    10 |  1,833 |   66,532 |          183 |
| Tests        |     8 |  1,010 |   44,496 |          126 |
| Docs         |     5 |  1,641 |   81,902 |          328 |
| Build/Config |     5 |    320 |   11,789 |           64 |
| **Total**    | **28**| **4,804**| **204,719**| **172**    |

Category placement rules used in this report (each file is counted once):

- **Code** — files compiled or interpreted by the extension itself:
  [`pg_jwt_role.c`](pg_jwt_role.c:1),
  [`pg_jwt_base64.c`](pg_jwt_base64.c:1),
  [`pg_jwt_csv.c`](pg_jwt_csv.c:1),
  [`pg_jwt_csv.h`](pg_jwt_csv.h:1),
  [`pg_jwt_json.c`](pg_jwt_json.c:1),
  [`pg_jwt_json.h`](pg_jwt_json.h:1),
  [`pg_jwt_strlist.c`](pg_jwt_strlist.c:1),
  [`pg_jwt_strlist.h`](pg_jwt_strlist.h:1),
  [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1), and
  [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1).
  The base64 / CSV / JSON / string-list modules were extracted from
  [`pg_jwt_role.c`](pg_jwt_role.c:1) so the main translation unit stays focused
  on the security-critical verify-and-set-role flow. The Python helper is invoked
  by the test driver to forge and tamper JWTs; it has no production callers, but
  it is a standalone runtime module (not a SQL test artefact), so it sits in
  **Code**.
- **Tests** — SQL `.sql` files under [`test/sql/`](test/sql/) exercising the
  extension, plus [`test/run_tests.sh`](test/run_tests.sh:1) (the bash driver
  that orchestrates the SQL tests and container lifecycle).
- **Docs** — Markdown intended for humans: [`README.md`](README.md:1),
  [`AGENTS.md`](AGENTS.md:1), [`plans/plan.md`](plans/plan.md:1),
  [`plans/coverage.md`](plans/coverage.md:1), [`test/README.md`](test/README.md:1).
- **Build/Config** — [`Makefile`](Makefile:1),
  [`pg_jwt_role.control`](pg_jwt_role.control:1),
  [`Dockerfile`](Dockerfile:1), [`docker-compose.yml`](docker-compose.yml:1),
  [`scripts/test.sh`](scripts/test.sh:1) (thin host-UID wrapper around
  `docker compose` — closer to CI plumbing than application code).

## 2. Per-file breakdown

### 2.1 Code (10 files, 1,833 LoC, 66,532 chars)

| File | Lines | Chars | Comment lines | Functions |
|------|------:|------:|--------------:|----------:|
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 1,058 | 40,035 | 401 | 10 |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | 172 | 7,618 | 87 | 4 |
| [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1) | 131 | 4,933 | 11 | 6 |
| [`pg_jwt_base64.c`](pg_jwt_base64.c:1) | 156 | 5,136 | 61 | 2 |
| [`pg_jwt_csv.c`](pg_jwt_csv.c:1) | 80 | 2,416 | 32 | 1 |
| [`pg_jwt_csv.h`](pg_jwt_csv.h:1) | 21 | 627 | 16 | 0 |
| [`pg_jwt_json.c`](pg_jwt_json.c:1) | 99 | 2,561 | 25 | 1 |
| [`pg_jwt_json.h`](pg_jwt_json.h:1) | 16 | 392 | 11 | 0 |
| [`pg_jwt_strlist.c`](pg_jwt_strlist.c:1) | 72 | 1,900 | 27 | 1 |
| [`pg_jwt_strlist.h`](pg_jwt_strlist.h:1) | 28 | 914 | 24 | 0 |

**C function inventory across all `.c` files** (15 function definitions +
2 `PG_FUNCTION_INFO_V1` linkage macros + 1 `PG_MODULE_MAGIC` macro):

| File | Line | Symbol | Kind |
|------|-----:|--------|------|
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 100 | `PG_MODULE_MAGIC` | Module linkage macro |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 192 | [`pg_jwt_verify`](pg_jwt_role.c:192) | static helper (alg dispatch) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 349 | `PG_FUNCTION_INFO_V1(pg_jwt_verify_and_set_role)` | linkage macro |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 351 | [`pg_jwt_verify_and_set_role`](pg_jwt_role.c:351) | SQL-callable (`PG_FUNCTION_ARGS`) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 600 | [`pg_jwt_positive_int_check`](pg_jwt_role.c:600) | GUC check hook |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 632 | [`pg_jwt_claim_slot`](pg_jwt_role.c:632) | extern helper |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 676 | [`pg_jwt_claim_slot_lookup`](pg_jwt_role.c:676) | extern helper |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 701 | [`pg_jwt_claim_slot_guc_name`](pg_jwt_role.c:701) | extern helper |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 724 | `PG_FUNCTION_INFO_V1(pg_jwt_claim_value)` | linkage macro |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 726 | [`pg_jwt_claim_value`](pg_jwt_role.c:726) | SQL-callable (`PG_FUNCTION_ARGS`) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 799 | [`is_session_user_restricted`](pg_jwt_role.c:799) | static helper (hook) |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 824 | [`pg_jwt_role_ProcessUtility`](pg_jwt_role.c:824) | ProcessUtility hook |
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 907 | [`_PG_init`](pg_jwt_role.c:907) | `_PG_init` (loads GUCs + hook) |
| [`pg_jwt_base64.c`](pg_jwt_base64.c:1) | 43 | [`pg_base64_decode`](pg_jwt_base64.c:43) | public helper |
| [`pg_jwt_base64.c`](pg_jwt_base64.c:1) | 117 | [`pg_base64url_decode`](pg_jwt_base64.c:117) | public helper |
| [`pg_jwt_csv.c`](pg_jwt_csv.c:1) | 31 | [`pg_split_csv`](pg_jwt_csv.c:31) | public helper |
| [`pg_jwt_json.c`](pg_jwt_json.c:1) | 30 | [`pg_json_extract_value`](pg_jwt_json.c:30) | public helper |
| [`pg_jwt_strlist.c`](pg_jwt_strlist.c:1) | 28 | [`pg_jwt_strlist_contains`](pg_jwt_strlist.c:28) | public helper |

Note: the header files ([`pg_jwt_csv.h`](pg_jwt_csv.h:1),
[`pg_jwt_json.h`](pg_jwt_json.h:1), [`pg_jwt_strlist.h`](pg_jwt_strlist.h:1))
only export the corresponding function declarations and macros, so they are
listed in the per-file table with 0 functions.

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

### 2.2 Tests (8 files, 1,010 LoC, 44,496 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`test/run_tests.sh`](test/run_tests.sh:1) | 556 | 24,842 |
| [`test/sql/test_basic.sql`](test/sql/test_basic.sql:1) | 76 | 3,230 |
| [`test/sql/test_invalid.sql`](test/sql/test_invalid.sql:1) | 35 | 1,111 |
| [`test/sql/test_hook.sql`](test/sql/test_hook.sql:1) | 102 | 4,916 |
| [`test/sql/test_algorithms.sql`](test/sql/test_algorithms.sql:1) | 55 | 2,317 |
| [`test/sql/test_exp.sql`](test/sql/test_exp.sql:1) | 43 | 1,662 |
| [`test/sql/test_limits.sql`](test/sql/test_limits.sql:1) | 95 | 4,529 |
| [`test/sql/test_unknown.sql`](test/sql/test_unknown.sql:1) | 48 | 1,889 |

**Bash function inventory in [`test/run_tests.sh`](test/run_tests.sh:1)** (5 functions):

| Line | Name |
|-----:|------|
| 40   | `cleanup` |
| 141  | `emit_jwt` |
| 152  | `emit_jwt_alg` |
| 163  | `emit_jwt_noexp` |
| 229  | `run_test` |

### 2.3 Docs (5 files, 1,641 LoC, 81,902 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`README.md`](README.md:1) | 388 | 17,496 |
| [`AGENTS.md`](AGENTS.md:1) | 242 | 14,707 |
| [`plans/plan.md`](plans/plan.md:1) | 776 | 34,167 |
| [`plans/coverage.md`](plans/coverage.md:1) | 138 | 9,970 |
| [`test/README.md`](test/README.md:1) | 97 | 5,562 |

Note: [`plans/plan.md`](plans/plan.md:1) is the largest single file at
**776 lines / 34,167 chars**, but per [`AGENTS.md`](AGENTS.md:1) it is
historical-only and not the source of truth.

### 2.4 Build / Config (5 files, 320 LoC, 11,789 chars)

| File | Lines | Chars |
|------|------:|------:|
| [`Makefile`](Makefile:1) | 17 | 488 |
| [`pg_jwt_role.control`](pg_jwt_role.control:1) | 19 | 1,019 |
| [`Dockerfile`](Dockerfile:1) | 141 | 5,509 |
| [`docker-compose.yml`](docker-compose.yml:1) | 75 | 2,443 |
| [`scripts/test.sh`](scripts/test.sh:1) | 68 | 2,330 |

[`scripts/test.sh`](scripts/test.sh:1) is a flat top-level bash script
(no `foo() { … }` definitions) — it just exports UID/GID and invokes
`docker compose run`.

## 3. Language breakdown (across all files)

| Language / format | Files | Lines | Chars |
|-------------------|------:|------:|------:|
| C (`.c`)                  | 5 | 1,465 |  52,048 |
| C headers (`.h`)          | 3 |    65 |   1,933 |
| SQL / PLpgSQL (`.sql`)    | 8 |   626 |  27,272 |
| Markdown (`.md`)          | 5 | 1,641 |  81,902 |
| Python (`.py`)            | 1 |   131 |   4,933 |
| Bash (`.sh`)              | 2 |   624 |  27,172 |
| Dockerfile                | 1 |   141 |   5,509 |
| YAML (`.yml`)             | 1 |    75 |   2,443 |
| Make (`Makefile`)         | 1 |    17 |     488 |
| Extension control (`.control`) | 1 |    19 |   1,019 |

Per-language rows sum to **4,804 lines / 204,719 chars**, matching the
global `wc -l -c` total.

## 4. Code-vs-comment ratios (production source only)

| File | Lines | Comment lines | Comment density |
|------|------:|--------------:|----------------:|
| [`pg_jwt_role.c`](pg_jwt_role.c:1) | 1,058 | 401 | **38%** |
| [`pg_jwt_base64.c`](pg_jwt_base64.c:1) | 156 | 61 | **39%** |
| [`pg_jwt_csv.c`](pg_jwt_csv.c:1) | 80 | 32 | **40%** |
| [`pg_jwt_csv.h`](pg_jwt_csv.h:1) | 21 | 16 | **76%** |
| [`pg_jwt_json.c`](pg_jwt_json.c:1) | 99 | 25 | **25%** |
| [`pg_jwt_json.h`](pg_jwt_json.h:1) | 16 | 11 | **69%** |
| [`pg_jwt_strlist.c`](pg_jwt_strlist.c:1) | 72 | 27 | **38%** |
| [`pg_jwt_strlist.h`](pg_jwt_strlist.h:1) | 28 | 24 | **86%** |
| [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1) | 172 | 87 | **51%** |
| [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1) | 131 | 11 | 8% |
| [`test/run_tests.sh`](test/run_tests.sh:1) | 556 | 137 | **25%** |
| [`scripts/test.sh`](scripts/test.sh:1) | 68 | 35 | **51%** |

The C source is unusually comment-dense for a Postgres extension (the 8 `.c/.h`
files combined are ~40% comment lines), reflecting the deliberate
"self-documenting security model" called out in [`AGENTS.md`](AGENTS.md:1).
The small headers are especially dense because they are almost entirely
file-header + API documentation.

## 5. Function totals

| Language | Functions defined |
|----------|------------------:|
| C (all `.c` files) | 15 (+ 2 `PG_FUNCTION_INFO_V1` linkage macros + 1 `PG_MODULE_MAGIC`) |
| SQL/PLpgSQL (in [`pg_jwt_role--1.0.sql`](pg_jwt_role--1.0.sql:1)) | 4 |
| Python (in [`test/test_jwt_helper.py`](test/test_jwt_helper.py:1)) | 6 |
| Bash (in [`test/run_tests.sh`](test/run_tests.sh:1)) | 5 |
| **Total** | **30** (+ 3 macros) |

## 6. How to regenerate

```bash
# Per-file line + char counts
wc -l -c $(find . -type f \
   -not -path './.git/*' \
   -not -path './code-stat.md' \
   -not -name '*.pyc') | sort -k2 -n

# Comment density per production file
for f in pg_jwt_role.c pg_jwt_base64.c pg_jwt_csv.c pg_jwt_csv.h \
         pg_jwt_json.c pg_jwt_json.h pg_jwt_strlist.c pg_jwt_strlist.h \
         pg_jwt_role--1.0.sql test/test_jwt_helper.py scripts/test.sh \
         test/run_tests.sh; do
  printf '%-40s %5d total / %5d comment\n' \
    "$f" "$(wc -l < "$f")" \
    "$(grep -cE '^[[:space:]]*(//|/\*|\*|--|#)' "$f")"
done

# Function inventory across the split C modules
for f in pg_jwt_role.c pg_jwt_base64.c pg_jwt_csv.c pg_jwt_json.c pg_jwt_strlist.c; do
  echo "=== $f ==="
  grep -nE '^[A-Za-z_].*\(' "$f"
done

# Other function inventories
grep -nE 'CREATE[[:space:]]+(OR[[:space:]]+REPLACE[[:space:]]+)?FUNCTION' pg_jwt_role--1.0.sql
grep -nE '^[[:space:]]*def[[:space:]]+' test/test_jwt_helper.py
grep -nE '^[A-Za-z_][A-Za-z0-9_]*\(\)' test/run_tests.sh
```
