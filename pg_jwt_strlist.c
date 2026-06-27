/*
 * pg_jwt_strlist.c
 *
 * String-list membership helper used by pg_jwt_role. Extracted from
 * pg_jwt_role.c so the main translation unit can stay focused on the
 * security-critical verify-and-set-role flow.
 *
 * This file is intentionally dependency-free: it only needs standard C
 * headers and can be compiled without PostgreSQL or OpenSSL headers.
 */

#include <stdbool.h>
#include <string.h>

#include "pg_jwt_strlist.h"

/*
 * pg_jwt_strlist_contains - return true iff `list` contains a token that
 * compares equal to `target` under exact byte-for-byte comparison after
 * trimming ASCII whitespace from each token.
 *
 * The list is scanned once without copying tokens. Empty tokens and
 * tokens consisting only of whitespace are skipped. Comparison uses
 * memcmp on the trimmed token length, so it is case-sensitive and
 * whitespace-sensitive inside the token, matching PostgreSQL role-name
 * semantics.
 */
bool pg_jwt_strlist_contains(const char *list, const char *target)
{
    const char *p;
    size_t target_len;

    if (list == NULL || target == NULL)
        return false;

    if (list[0] == '\0' || target[0] == '\0')
        return false;

    target_len = strlen(target);

    for (p = list; *p != '\0';)
    {
        const char *start;
        const char *end;
        size_t len;

        /* skip leading whitespace */
        while (*p == ' ' || *p == '\t')
            p++;
        start = p;

        /* find next comma or end */
        while (*p != '\0' && *p != ',')
            p++;
        end = p;

        /* trim trailing whitespace */
        while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
            end--;

        len = (size_t)(end - start);
        if (len > 0 &&
            len == target_len &&
            memcmp(start, target, len) == 0)
            return true;

        if (*p == ',')
            p++;
    }

    return false;
}
