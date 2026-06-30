/*
 * test_json.c — unit tests for pg_json_extract_value().
 *
 * pg_json_extract_value() is the hand-rolled scanner the atomic C
 * function uses to pull the role claim, the exp claim, and each extra
 * claim out of the JWT payload. Its contract has several non-obvious
 * edges that matter for security:
 *   - It matches the literal pattern "<key>": with no internal spaces,
 *     so a key like "userrole" must NOT be confused with "role".
 *   - Empty quoted values ("k":"") return false (the scanner treats a
 *     zero-length extracted string as "not found").
 *   - Bare literals are terminated by comma/brace/whitespace.
 *   - Both branches truncate to outlen-1.
 *
 * These tests pin each of those behaviours against the real production
 * source in pg_jwt_json.c.
 */
#include "pg_jwt_json.h"

#include "test_common.h"

int main(void)
{
    char out[64];
    bool r;

    printf("== pg_json_extract_value ==\n");

    /* --- NULL / degenerate-buffer guards ------------------------------ */
    CHECK(pg_json_extract_value(NULL, "k", out, sizeof(out)) == false);
    CHECK(pg_json_extract_value("{}", NULL, out, sizeof(out)) == false);
    CHECK(pg_json_extract_value("{}", "k", NULL, sizeof(out)) == false);
    CHECK(pg_json_extract_value("{}", "k", out, 1) == false);   /* outlen < 2 */
    CHECK(pg_json_extract_value("{}", "", out, sizeof(out)) == false);  /* empty key */

    /* --- quoted string value ------------------------------------------ */
    r = pg_json_extract_value("{\"role\":\"admin\"}", "role", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("quoted role", out, "admin");

    /* --- multiple keys, pick the right one ---------------------------- */
    r = pg_json_extract_value("{\"sub\":\"alice\",\"role\":\"dba\",\"email\":\"x@y\"}",
                              "role", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("mid key", out, "dba");

    /* --- numeric (exp) literal ---------------------------------------- */
    r = pg_json_extract_value("{\"exp\":1700000000}", "exp", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("numeric exp", out, "1700000000");

    /* --- bool / null bare literals ------------------------------------ */
    r = pg_json_extract_value("{\"active\":true}", "active", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("bool true", out, "true");
    r = pg_json_extract_value("{\"n\":null}", "n", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("null literal", out, "null");

    /* --- whitespace after the colon is tolerated ---------------------- */
    r = pg_json_extract_value("{\"role\": \"spaced\"}", "role", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("space after colon", out, "spaced");

    /* --- bare literal terminated by comma / brace / space ------------- */
    r = pg_json_extract_value("{\"exp\":123,\"x\":1}", "exp", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("bare terminated by comma", out, "123");
    r = pg_json_extract_value("{\"exp\":456}", "exp", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("bare terminated by brace", out, "456");

    /* --- escape handling inside quoted strings ------------------------ */
    r = pg_json_extract_value("{\"sub\":\"a\\\"b\"}", "sub", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("escaped quote", out, "a\"b");
    r = pg_json_extract_value("{\"sub\":\"a\\\\b\"}", "sub", out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("escaped backslash", out, "a\\b");

    /* --- prefix-key safety: "userrole" must NOT match "role" ---------- */
    /* The pattern is "role": (quote-key-quote-colon), so a longer key
     * whose suffix is "role" has no leading quote there and won't match. */
    r = pg_json_extract_value("{\"userrole\":\"x\",\"role\":\"y\"}", "role",
                              out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("prefix-key does not steal match", out, "y");
    r = pg_json_extract_value("{\"userrole\":\"x\"}", "role", out, sizeof(out));
    CHECK(r == false);

    /* --- key-not-found ------------------------------------------------ */
    r = pg_json_extract_value("{\"sub\":\"alice\"}", "role", out, sizeof(out));
    CHECK(r == false);

    /* --- first occurrence wins ---------------------------------------- */
    r = pg_json_extract_value("{\"role\":\"first\",\"role\":\"second\"}", "role",
                              out, sizeof(out));
    CHECK(r == true);
    CHECK_STREQ("first occurrence wins", out, "first");

    /* --- empty quoted value returns false (i == 0) -------------------- */
    r = pg_json_extract_value("{\"role\":\"\"}", "role", out, sizeof(out));
    CHECK(r == false);

    /* --- truncation of a quoted value to outlen-1 --------------------- */
    {
        char small[5];
        r = pg_json_extract_value("{\"role\":\"abcdefg\"}", "role", small, sizeof(small));
        CHECK(r == true);
        CHECK_STREQ("quoted truncation", small, "abcd");
    }

    /* --- truncation of a bare literal to outlen-1 --------------------- */
    {
        char small[5];
        r = pg_json_extract_value("{\"exp\":123456789}", "exp", small, sizeof(small));
        CHECK(r == true);
        CHECK_STREQ("bare truncation", small, "1234");
    }

    TEST_SUMMARY();
}
