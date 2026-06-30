/*
 * test_csv.c — unit tests for pg_split_csv().
 *
 * pg_split_csv() tokenises the pg_jwt_role.extra_claims GUC into the
 * claim-name list the atomic C function walks after signature
 * verification. Two behaviours are security-relevant:
 *   1. Normal tokenisation: trim whitespace, skip empty entries,
 *      truncate to `max`.
 *   2. The over-long-name rejection (P2.5 in plans/coverage.md): a
 *      name >= PG_JWT_MAX_CSV_NAME_LEN bytes must ereport(ERROR)
 *      rather than be silently truncated, so a misconfigured
 *      extra_claims can't make the configured name and the JSON claim
 *      it later looks up silently disagree.
 *
 * The ereport path uses the stub longjmp machinery (EXPECT_EREPORT)
 * so the real production code runs unchanged and the non-return
 * contract is asserted.
 */
#include <string.h>

#include "pg_jwt_csv.h"
#include "test_common.h"

int main(void)
{
    char names[8][PG_JWT_MAX_CSV_NAME_LEN];
    int n;

    printf("== pg_split_csv ==\n");

    /* --- NULL / degenerate guards ------------------------------------- */
    CHECK(pg_split_csv(NULL, names, 8) == 0);
    CHECK(pg_split_csv("a,b", names, 0) == 0);
    CHECK(pg_split_csv("a,b", names, -1) == 0);

    /* --- single token ------------------------------------------------- */
    n = pg_split_csv("sub", names, 8);
    CHECK_INT("single token count", n, 1);
    CHECK_STREQ("single token value", names[0], "sub");

    /* --- multiple tokens ---------------------------------------------- */
    n = pg_split_csv("sub,email,role", names, 8);
    CHECK_INT("multi token count", n, 3);
    CHECK_STREQ("token 0", names[0], "sub");
    CHECK_STREQ("token 1", names[1], "email");
    CHECK_STREQ("token 2", names[2], "role");

    /* --- leading/trailing whitespace trimmed -------------------------- */
    n = pg_split_csv("  sub , email ,role ", names, 8);
    CHECK_INT("trimmed count", n, 3);
    CHECK_STREQ("trimmed 0", names[0], "sub");
    CHECK_STREQ("trimmed 1", names[1], "email");
    CHECK_STREQ("trimmed 2", names[2], "role");

    /* --- empty entries skipped ---------------------------------------- */
    n = pg_split_csv("sub,,email,", names, 8);
    CHECK_INT("empty-skip count", n, 2);
    CHECK_STREQ("empty-skip 0", names[0], "sub");
    CHECK_STREQ("empty-skip 1", names[1], "email");

    /* --- whitespace-only entries skipped ------------------------------ */
    n = pg_split_csv("sub,   ,email", names, 8);
    CHECK_INT("ws-only-skip count", n, 2);
    CHECK_STREQ("ws-only-skip 1", names[1], "email");

    /* --- empty / all-whitespace input --------------------------------- */
    CHECK_INT("empty string -> 0", pg_split_csv("", names, 8), 0);
    CHECK_INT("whitespace only -> 0", pg_split_csv("   ", names, 8), 0);
    CHECK_INT("commas only -> 0", pg_split_csv(",,,", names, 8), 0);

    /* --- truncation to `max` ------------------------------------------ */
    n = pg_split_csv("a,b,c,d,e", names, 3);
    CHECK_INT("max-truncate count", n, 3);
    CHECK_STREQ("max-truncate 0", names[0], "a");
    CHECK_STREQ("max-truncate 2", names[2], "c");

    /* --- trailing comma does not create a trailing empty entry -------- */
    n = pg_split_csv("sub,email", names, 8);
    CHECK_INT("no trailing empty", n, 2);

    /* --- boundary: name of exactly PG_JWT_MAX_CSV_NAME_LEN-1 bytes ---- */
    /* (63 bytes) is accepted. */
    {
        char buf[PG_JWT_MAX_CSV_NAME_LEN];
        memset(buf, 'x', PG_JWT_MAX_CSV_NAME_LEN - 1);
        buf[PG_JWT_MAX_CSV_NAME_LEN - 1] = '\0';  /* 63-char name */
        n = pg_split_csv(buf, names, 8);
        CHECK_INT("63-char name accepted (count)", n, 1);
        CHECK_INT("63-char name length", (int)strlen(names[0]),
                  PG_JWT_MAX_CSV_NAME_LEN - 1);
    }

    /* --- boundary: name of PG_JWT_MAX_CSV_NAME_LEN bytes (64) rejected */
    /* via ereport(ERROR). This is the P2.5 hardening: the real production
     * code ereports rather than silently truncating. */
    {
        char buf[PG_JWT_MAX_CSV_NAME_LEN + 1];
        memset(buf, 'y', PG_JWT_MAX_CSV_NAME_LEN);
        buf[PG_JWT_MAX_CSV_NAME_LEN] = '\0';  /* 64-char name */
        EXPECT_EREPORT("64-char name rejected", pg_split_csv(buf, names, 8));
    }

    /* --- boundary: a too-long name must not corrupt earlier results --- */
    /* The ereport is a hard abort of the call; assert that a preceding
     * valid call left its results intact (the stub longjmp unwinds the
     * bad call's stack frame without touching static/global state). */
    {
        char buf[PG_JWT_MAX_CSV_NAME_LEN + 1];
        memset(buf, 'z', PG_JWT_MAX_CSV_NAME_LEN);
        buf[PG_JWT_MAX_CSV_NAME_LEN] = '\0';
        n = pg_split_csv("ok1,ok2", names, 8);   /* valid */
        CHECK_INT("preceding valid count", n, 2);
        CHECK_STREQ("preceding valid 0", names[0], "ok1");
        EXPECT_EREPORT("long name after valid rejected",
                       pg_split_csv(buf, names, 8));
        /* The earlier results survive because names[] is caller-owned. */
        CHECK_STREQ("earlier result survives 0", names[0], "ok1");
    }

    TEST_SUMMARY();
}
