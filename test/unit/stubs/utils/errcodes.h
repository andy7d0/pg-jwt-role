/*
 * utils/errcodes.h — minimal test-only stub.
 *
 * The real PostgreSQL errcodes.h defines the ERRCODE_* macros used by
 * ereport(). Only pg_split_csv() in pg_jwt_csv.c actually references an
 * errcode (ERRCODE_INVALID_PARAMETER_VALUE), so this stub needs just
 * that one. Kept as a plain int sentinel matching the real macro's form
 * so the production call site compiles unchanged.
 */
#ifndef STUB_UTILS_ERRCODES_H
#define STUB_UTILS_ERRCODES_H

/* Mirrors the real MakeMacroSQLSTATE() integer form. Only the value
 * ERRCODE_INVALID_PARAMETER_VALUE is consumed by the helpers under
 * test; keep it as an int compatible with the stub errcode() below. */
#define ERRCODE_INVALID_PARAMETER_VALUE 22023

#endif /* STUB_UTILS_ERRCODES_H */
