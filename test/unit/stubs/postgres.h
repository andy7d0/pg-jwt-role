/*
 * postgres.h — minimal test-only stub.
 *
 * The real postgres.h (via c.h) pulls in bool, size_t, NULL, the PG
 * error-reporting machinery, etc. The extracted helper modules
 * (pg_jwt_base64.c, pg_jwt_json.c, pg_jwt_csv.c) include "postgres.h"
 * only for convention; their bodies use nothing from it that isn't
 * already provided by the standard C headers below. This stub exists
 * so those files compile unchanged outside a PostgreSQL source tree,
 * letting the real production code be unit-tested directly.
 *
 * This header is ONLY on the include path during unit-test compilation
 * (see test/unit/run_unit_tests.sh); it never participates in the PGXS
 * build of pg_jwt_role.so.
 */
#ifndef STUB_POSTGRES_H
#define STUB_POSTGRES_H

#include <stdbool.h>
#include <stddef.h>

#endif /* STUB_POSTGRES_H */
