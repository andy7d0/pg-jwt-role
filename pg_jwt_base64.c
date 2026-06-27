/*
 * pg_jwt_base64.c
 *
 * Base64 (RFC 4648 §4) and base64url (RFC 4648 §5) decoders used by the
 * JWT signature path in pg_jwt_role.
 *
 * Extracted from pg_jwt_role.c so that the main translation unit stays
 * focused on the security-sensitive verify-and-set-role flow. The
 * decoders here are deliberately tiny, dependency-free, and operate on
 * fixed-size stack buffers — no palloc / malloc.
 *
 * Conventions:
 *   - pg_base64_decode() expects STANDARD base64 (A-Z a-z 0-9 + /,
 *     optional '=' padding, optional ASCII whitespace). Returns the
 *     number of bytes written, or -1 on malformed input / overflow.
 *   - pg_base64url_decode() normalises base64url ('-' -> '+', '_' -> '/')
 *     into standard base64 in a scratch buffer, pads to a multiple of 4
 *     with '=' so PostgreSQL-grade strict decoders would also accept it,
 *     and then calls pg_base64_decode(). The caller still gets a length
 *     on success, -1 on malformed input / overflow.
 *
 * JWT contract: PG's PL/pgSQL wrapper already passes the signature
 * segment to the C function as a base64url string. The signature path
 * here used to do the '-' / '_' replacement inline at the call site;
 * it is now folded into pg_base64url_decode() so the caller doesn't
 * have to know about the base64 alphabet variants.
 */

#include "postgres.h"

#include <string.h>

/*
 * pg_base64_decode - decode a standard base64 string (NOT base64url)
 * into a byte buffer. Returns the number of bytes written, or -1 on
 * malformed input or buffer overflow.
 *
 * Accepts the alphabet A-Z a-z 0-9 + /, '=' padding, and embedded
 * whitespace (space, tab, CR, LF). The input is NOT NUL-terminated;
 * srclen is the exact length. The caller must normalise base64url ->
 * standard base64 ('-' -> '+', '_' -> '/') before calling.
 */
int pg_base64_decode(const char *src, int srclen, char *dst, int dstlen)
{
    int quad[4];
    int qi = 0;
    int out = 0;
    int i;

    for (i = 0; i < srclen; i++)
    {
        char c = src[i];
        int v;

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            continue;
        if (c == '=')
            break;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            v = c - '0' + 52;
        else if (c == '+')
            v = 62;
        else if (c == '/')
            v = 63;
        else
            return -1;
        quad[qi++] = v;
        if (qi == 4)
        {
            if (out + 3 > dstlen)
                return -1;
            dst[out++] = (char)((quad[0] << 2) | (quad[1] >> 4));
            dst[out++] = (char)((quad[1] << 4) | (quad[2] >> 2));
            dst[out++] = (char)((quad[2] << 6) | quad[3]);
            qi = 0;
        }
    }
    if (qi == 1)
        return -1;
    if (qi == 2)
    {
        if (out + 1 > dstlen)
            return -1;
        dst[out++] = (char)((quad[0] << 2) | (quad[1] >> 4));
    }
    else if (qi == 3)
    {
        if (out + 2 > dstlen)
            return -1;
        dst[out++] = (char)((quad[0] << 2) | (quad[1] >> 4));
        dst[out++] = (char)((quad[1] << 4) | (quad[2] >> 2));
    }
    return out;
}

/*
 * pg_base64url_decode - decode a base64url-encoded JWT segment (the
 * signature segment from PL/pgSQL) into a byte buffer. Performs the
 * alphabet substitution ('-' -> '+', '_' -> '/') into a local stack
 * buffer, appends '=' padding to a multiple of 4 (RFC 4648 §5
 * "padding is not used"), then calls pg_base64_decode().
 *
 * `scratch` must be at least srclen + 3 bytes; `scratchlen` is its
 * size. `dst` / `dstlen` are the destination byte buffer.
 *
 * Returns the number of bytes written, or -1 on malformed input,
 * alphabet-substitution failure, padding overflow, or decode error.
 *
 * The scratch + dst split mirrors the rule from plans/plan.md §8:
 * no palloc / malloc; both buffers must be caller-provided stack
 * storage.
 */
int pg_base64url_decode(const char *src, int srclen,
                        char *scratch, int scratchlen,
                        char *dst, int dstlen)
{
    int i;
    int padded_len;

    if (src == NULL || scratch == NULL || dst == NULL)
        return -1;
    if (srclen < 0 || scratchlen < srclen + 3 || dstlen <= 0)
        return -1;

    /* base64url -> standard base64, character by character. */
    for (i = 0; i < srclen; i++)
    {
        char c = src[i];

        if (c == '-')
            scratch[i] = '+';
        else if (c == '_')
            scratch[i] = '/';
        else
            scratch[i] = c;
    }

    /* Pad to a multiple of 4 with '=' so any strict base64 decoder
     * would accept it (we don't need it, pg_base64_decode is lenient
     * about padding, but keeping it RFC-correct simplifies debugging
     * if we ever want to print the normalised form). */
    padded_len = srclen;
    while (padded_len % 4 != 0)
    {
        scratch[padded_len] = '=';
        padded_len++;
        if (padded_len >= scratchlen)
            return -1;
    }

    return pg_base64_decode(scratch, padded_len, dst, dstlen);
}
