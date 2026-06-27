/*
 * pg_jwt_json.c
 *
 * Minimal JSON value extractor used by pg_jwt_role. Extracted from
 * pg_jwt_role.c so the main translation unit can stay focused on the
 * security-critical verify-and-set-role flow.
 *
 * This is deliberately NOT a full JSON parser. It searches a flat
 * object for "<key>": with strstr, then extracts either a quoted
 * string (with simple \, " escape handling) or a bare
 * numeric/bool/null literal terminated by ',', '}', or whitespace.
 */

#include "postgres.h"
#include "utils/errcodes.h"
#include "utils/elog.h"

#include <string.h>

#include "pg_jwt_json.h"

/*
 * Internal helper: length limit for the "<key>": pattern buffer.
 * We keep this small because pg_jwt_role only ever scans a fixed-size
 * payload buffer; an oversized key is an invalid input rather than
 * something that needs dynamic allocation.
 */
#define PG_JWT_MAX_PATTERN_LEN 64

bool pg_json_extract_value(const char *json, const char *key,
                           char *out, int outlen)
{
    char pattern[PG_JWT_MAX_PATTERN_LEN + 8];
    int key_len;
    int pattern_len;
    const char *p;
    int i;

    if (json == NULL || key == NULL || out == NULL || outlen < 2)
        return false;

    key_len = (int)strlen(key);
    if (key_len <= 0 || key_len >= PG_JWT_MAX_PATTERN_LEN)
        return false;
    if (key_len + 4 > (int)sizeof(pattern))
        return false;

    pattern[0] = '"';
    memcpy(pattern + 1, key, key_len);
    pattern[1 + key_len] = '"';
    pattern[2 + key_len] = ':';
    pattern_len = 3 + key_len;
    pattern[pattern_len] = '\0';

    p = strstr(json, pattern);
    if (p == NULL)
        return false;
    p += pattern_len;

    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;

    if (*p == '"')
    {
        p++;
        i = 0;
        while (*p && *p != '"')
        {
            if (*p == '\\' && *(p + 1))
            {
                p++;
                if (i < outlen - 1)
                    out[i++] = *p;
                p++;
            }
            else
            {
                if (i < outlen - 1)
                    out[i++] = *p;
                p++;
            }
        }
        out[i] = '\0';
        return (i > 0);
    }

    {
        const char *start = p;
        while (*p && *p != ',' && *p != '}' &&
               *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            p++;
        i = (int)(p - start);
        if (i >= outlen)
            i = outlen - 1;
        memcpy(out, start, i);
        out[i] = '\0';
        return (i > 0);
    }
}
