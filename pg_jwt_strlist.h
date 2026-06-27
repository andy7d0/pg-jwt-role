/*
 * pg_jwt_strlist.h
 *
 * String-list membership helper used by pg_jwt_role. Extracted from
 * pg_jwt_role.c so the main translation unit can stay focused on the
 * security-critical verify-and-set-role flow.
 *
 * The list format is a comma-separated string of tokens with optional
 * leading/trailing ASCII whitespace around each token. Empty tokens are
 * ignored.
 */
#ifndef PG_JWT_STRLIST_H
#define PG_JWT_STRLIST_H

#include <stdbool.h>

/*
 * pg_jwt_strlist_contains - return true iff `list` contains a token that
 * compares equal to `target` under exact byte-for-byte comparison after
 * trimming ASCII whitespace from each token.
 *
 * Both `list` and `target` must be NUL-terminated strings. `target` is
 * not trimmed; callers should supply it in normal form (e.g. from
 * GetUserNameFromId()).
 */
bool pg_jwt_strlist_contains(const char *list, const char *target);

#endif /* PG_JWT_STRLIST_H */
