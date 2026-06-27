/*
 * pg_jwt_csv.c
 *
 * Small CSV tokeniser used by pg_jwt_role. Extracted from
 * pg_jwt_role.c so the main translation unit can stay focused on the
 * security-critical verify-and-set-role flow.
 */

#include "postgres.h"
#include "utils/errcodes.h"
#include "utils/elog.h"

#include <string.h>

#include "pg_jwt_csv.h"

/*
 * pg_split_csv - copy the comma-separated names from `csv` into
 * `names`, one per row. Returns the count copied (>= 0), truncated to
 * `max`. Names are trimmed of leading/trailing ASCII whitespace;
 * empty entries are skipped.
 *
 * Names longer than PG_JWT_MAX_CSV_NAME_LEN - 1 bytes (including the
 * NUL) are a hard configuration error. We ereport() instead of
 * silently truncating, because the configured `extra_claims` GUC and
 * the actual JSON claim the C function then looks up would silently
 * disagree — admins would see "my claim was set but its value is
 * empty" with no explanation. The token is rejected before the
 * signature is even consulted so the failure is unambiguous.
 */
int pg_split_csv(const char *csv,
                 char names[][PG_JWT_MAX_CSV_NAME_LEN], int max)
{
    int n = 0;
    const char *p;

    if (csv == NULL || max <= 0)
        return 0;

    p = csv;
    while (*p && n < max)
    {
        const char *start;
        const char *end;
        int len;

        while (*p == ' ' || *p == '\t')
            p++;
        start = p;
        while (*p && *p != ',')
            p++;
        end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
            end--;

        len = (int)(end - start);
        if (len > 0)
        {
            /*
             * Bound the destination: PG_JWT_MAX_CSV_NAME_LEN includes
             * the NUL, so a user-facing name must be strictly shorter.
             * Reject rather than truncate so misconfigured extra_claims
             * can't silently no-op.
             */
            if (len >= PG_JWT_MAX_CSV_NAME_LEN)
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("pg_jwt_role: extra_claims entry too long "
                                "(max %d bytes)",
                                PG_JWT_MAX_CSV_NAME_LEN - 1)));
            memcpy(names[n], start, len);
            names[n][len] = '\0';
            n++;
        }

        if (*p == ',')
            p++;
    }
    return n;
}
