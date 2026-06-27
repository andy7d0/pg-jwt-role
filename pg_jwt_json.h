/*
 * pg_jwt_json.h
 *
 * Tiny JSON helper used by pg_jwt_role. Not a full parser: scans a flat
 * object for "<key>": and copies the scalar value into caller-provided
 * storage.
 */
#ifndef PG_JWT_JSON_H
#define PG_JWT_JSON_H

#include <stdbool.h>

bool pg_json_extract_value(const char *json, const char *key,
                           char *out, int outlen);

#endif /* PG_JWT_JSON_H */
