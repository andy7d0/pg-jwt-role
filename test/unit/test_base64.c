/*
 * test_base64.c — unit tests for pg_base64_decode() and
 * pg_base64url_decode().
 *
 * The base64 decoders sit on the JWT signature path: the PL/pgSQL
 * wrapper hands the base64url signature segment to the C function,
 * which normalises it and decodes it before the constant-time
 * CRYPTO_memcmp. Bugs here (wrong padding, wrong alphabet
 * substitution, off-by-one overflow) directly weaken signature
 * verification, so the tests pin:
 *   - RFC 4648 reference vectors,
 *   - 1/2/3-byte tail cases (the qi==2 / qi==3 branches),
 *   - embedded whitespace handling,
 *   - base64url '-'/'_' -> '+'/'/' substitution + auto-padding,
 *   - buffer-overflow rejection,
 *   - malformed-input rejection.
 *
 * Test vectors are cross-checked against Python's base64 module.
 */
#include <string.h>

#include "test_common.h"

/* pg_jwt_base64.c includes "postgres.h"; the stub provides bool/size_t.
 * The decode prototypes are not in any shipped header (the functions are
 * declared extern inside pg_jwt_role.c), so redeclare the minimal set
 * here for this unit-test translation unit. */
int pg_base64_decode(const char *src, int srclen, char *dst, int dstlen);
int pg_base64url_decode(const char *src, int srclen,
                        char *scratch, int scratchlen,
                        char *dst, int dstlen);

/* Helper: compare a decoded buffer to an expected byte string. */
static bool bytes_eq(const char *got, int gotlen, const char *want, int wantlen)
{
    if (gotlen != wantlen) return false;
    if (gotlen == 0) return true;
    return memcmp(got, want, gotlen) == 0;
}

#define CHECK_BYTES(label, got, gotlen, want, wantlen)                       \
    do {                                                                      \
        g_checks++;                                                           \
        if (bytes_eq(got, gotlen, want, wantlen)) {                           \
            printf("  [OK] %s: %d bytes\n", label, (int)gotlen);             \
        } else {                                                              \
            g_failed++;                                                       \
            printf("  [FAIL] %s:%d: %s: got %d bytes, want %d\n",            \
                   __FILE__, __LINE__, label, (int)gotlen, (int)wantlen);     \
        }                                                                     \
    } while (0)

int main(void)
{
    char out[64];

    printf("== pg_base64_decode (standard) ==\n");

    /* RFC 4648 reference vectors. */
    {
        int n = pg_base64_decode("", 0, out, sizeof(out));
        CHECK_INT("empty input -> 0 bytes", n, 0);
    }
    {
        int n = pg_base64_decode("TQ==", 4, out, sizeof(out));   /* "M" */
        CHECK_BYTES("1 char value", out, n, "M", 1);
    }
    {
        int n = pg_base64_decode("TWE=", 4, out, sizeof(out));   /* "Ma" */
        CHECK_BYTES("2 char value", out, n, "Ma", 2);
    }
    {
        int n = pg_base64_decode("TWFu", 4, out, sizeof(out));   /* "Man" */
        CHECK_BYTES("3 char value (full quad)", out, n, "Man", 3);
    }
    {
        int n = pg_base64_decode("Zm9vYmFy", 8, out, sizeof(out)); /* "foobar" */
        CHECK_BYTES("multi-quad", out, n, "foobar", 6);
    }

    /* Embedded whitespace is skipped (space/tab/CR/LF). */
    {
        int n = pg_base64_decode("TW Fu", 5, out, sizeof(out));  /* "Man" */
        CHECK_BYTES("embedded space", out, n, "Man", 3);
    }
    {
        int n = pg_base64_decode("TW\nFu", 5, out, sizeof(out));
        CHECK_BYTES("embedded newline", out, n, "Man", 3);
    }

    /* Padding is optional: the decoder stops at '=' but also accepts a
     * trailing quad without it. */
    {
        int n = pg_base64_decode("TWE", 3, out, sizeof(out));    /* "Ma" w/o pad */
        CHECK_BYTES("no padding (qi==2)", out, n, "Ma", 2);
    }

    /* Malformed input -> -1. */
    {
        int n = pg_base64_decode("T", 1, out, sizeof(out));      /* lone char */
        CHECK_INT("lone char -> -1", n, -1);
    }
    {
        int n = pg_base64_decode("TWF$u", 5, out, sizeof(out));  /* bad char '$' */
        CHECK_INT("invalid char -> -1", n, -1);
    }

    /* Buffer overflow -> -1. */
    {
        char small[2];
        int n = pg_base64_decode("TWFu", 4, small, sizeof(small)); /* needs 3 */
        CHECK_INT("dst overflow -> -1", n, -1);
    }

    printf("== pg_base64url_decode (JWT signature path) ==\n");

    /* Use distinct scratch/raw buffers per case to avoid aliasing
     * surprises (pg_base64url_decode writes the normalised form into
     * `scratch` and the decoded bytes into `dst`). */
    {
        char scratch[16];
        char raw[16];
        int n = pg_base64url_decode("TWFu", 4, scratch, sizeof(scratch),
                                    raw, sizeof(raw));
        CHECK_BYTES("plain url (no -/_)", raw, n, "Man", 3);
    }

    /* base64url '-' / '_' substitution: "3q2+78r+" -> "3q2-78r-",
     * decodes to 6 bytes \xde\xad\xbe\xef\xca\xfe. */
    {
        char scratch[16];
        char raw[16];
        const unsigned char want[] = {0xde,0xad,0xbe,0xef,0xca,0xfe};
        int n = pg_base64url_decode("3q2-78r-", 8, scratch, sizeof(scratch),
                                    raw, sizeof(raw));
        CHECK_BYTES("url -/_ substitution", raw, n, (const char *)want, 6);
    }

    /* Auto-padding: a 3-char url segment ("AgE", decodes to 2 bytes)
     * must be padded to "AgE=" internally. */
    {
        char scratch[8];
        char raw[8];
        const unsigned char want[] = {0x02, 0x01};
        int n = pg_base64url_decode("AgE", 3, scratch, sizeof(scratch),
                                    raw, sizeof(raw));
        CHECK_BYTES("url auto-pad 3->4 (qi==2)", raw, n, (const char *)want, 2);
    }

    /* Auto-padding: a 2-char url segment ("AQ", decodes to 1 byte)
     * must be padded to "AQ==". */
    {
        char scratch[8];
        char raw[8];
        const unsigned char want[] = {0x01};
        int n = pg_base64url_decode("AQ", 2, scratch, sizeof(scratch),
                                    raw, sizeof(raw));
        CHECK_BYTES("url auto-pad 2->4", raw, n, (const char *)want, 1);
    }

    /* NULL / range guards. */
    {
        char scratch[8];
        CHECK_INT("null src", pg_base64url_decode(NULL, 0, scratch, 8, out, 4), -1);
        CHECK_INT("null scratch", pg_base64url_decode("AQ", 2, NULL, 8, out, 4), -1);
        CHECK_INT("null dst", pg_base64url_decode("AQ", 2, scratch, 8, NULL, 4), -1);
        CHECK_INT("negative srclen", pg_base64url_decode("AQ", -1, scratch, 8, out, 4), -1);
        CHECK_INT("scratch too small", pg_base64url_decode("AQ", 2, scratch, 3, out, 4), -1);
        CHECK_INT("dstlen <= 0", pg_base64url_decode("AQ", 2, scratch, 8, out, 0), -1);
    }

    /* The entry guard `scratchlen >= srclen + 3` guarantees the padding
     * loop can never write out of bounds (max write index is srclen+2),
     * so a too-small scratch is rejected up front rather than mid-pad.
     * Verify that guard fires for a scratch that can't hold the input
     * plus its worst-case 3 pad bytes. */
    {
        char scratch[8];  /* srclen=7 needs scratchlen >= 10 */
        char raw[8];
        int n = pg_base64url_decode("BQQDAgE", 7, scratch, sizeof(scratch),
                                    raw, sizeof(raw));
        CHECK_INT("scratch too small (entry guard) -> -1", n, -1);
    }

    TEST_SUMMARY();
}
