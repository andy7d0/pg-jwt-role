/*
 * test_strlist.c — unit tests for pg_jwt_strlist_contains().
 *
 * pg_jwt_strlist_contains() is the ProcessUtility_hook's membership
 * test: it decides whether the current session_user is in the
 * restricted list. Whitespace-trimming, case sensitivity, and
 * substring handling all affect that security decision, so each branch
 * gets a dedicated assertion.
 *
 * pg_jwt_strlist.c is intentionally dependency-free (no postgres.h),
 * so this translation unit links against it directly with no stubs.
 */
#include "pg_jwt_strlist.h"

#include "test_common.h"

int main(void)
{
    printf("== pg_jwt_strlist_contains ==\n");

    /* --- NULL / empty guards ------------------------------------------ */
    CHECK(pg_jwt_strlist_contains(NULL, "x") == false);
    CHECK(pg_jwt_strlist_contains("a,b", NULL) == false);
    CHECK(pg_jwt_strlist_contains("", "a") == false);     /* empty list */
    CHECK(pg_jwt_strlist_contains("a,b", "") == false);   /* empty target */

    /* --- single + multiple tokens ------------------------------------- */
    CHECK(pg_jwt_strlist_contains("app_user", "app_user") == true);
    CHECK(pg_jwt_strlist_contains("app_user", "dba_user") == false);
    CHECK(pg_jwt_strlist_contains("app_user,dba_user", "dba_user") == true);
    CHECK(pg_jwt_strlist_contains("app_user,dba_user", "app_user") == true);
    CHECK(pg_jwt_strlist_contains("app_user,dba_user", "target_role") == false);

    /* --- leading/trailing whitespace trimmed per token ---------------- */
    CHECK(pg_jwt_strlist_contains(" app_user , dba_user ", "app_user") == true);
    CHECK(pg_jwt_strlist_contains(" app_user , dba_user ", "dba_user") == true);
    CHECK(pg_jwt_strlist_contains("  app_user\t,\tdba_user", "app_user") == true);

    /* --- case sensitivity (PG role names are case-sensitive) ---------- */
    CHECK(pg_jwt_strlist_contains("App_User", "app_user") == false);
    CHECK(pg_jwt_strlist_contains("app_user", "APP_USER") == false);

    /* --- substring is NOT a match (byte-for-byte equality) ------------ */
    CHECK(pg_jwt_strlist_contains("app_user_extra", "app_user") == false);
    CHECK(pg_jwt_strlist_contains("app_user", "app_user_extra") == false);
    CHECK(pg_jwt_strlist_contains("pre_app_user", "app_user") == false);

    /* --- empty / whitespace-only tokens skipped ----------------------- */
    CHECK(pg_jwt_strlist_contains("app_user,,dba_user", "dba_user") == true);
    CHECK(pg_jwt_strlist_contains("app_user,,dba_user", "") == false);
    CHECK(pg_jwt_strlist_contains("   ,   ", "x") == false);
    CHECK(pg_jwt_strlist_contains(",", "x") == false);

    /* --- target appearing only as a substring of a longer token ------- */
    CHECK(pg_jwt_strlist_contains("user,app_user", "user") == true);
    CHECK(pg_jwt_strlist_contains("user,app_user", "app_user") == true);

    /* --- trailing comma ----------------------------------------------- */
    CHECK(pg_jwt_strlist_contains("app_user,dba_user,", "dba_user") == true);
    CHECK(pg_jwt_strlist_contains("app_user,dba_user,", "x") == false);

    TEST_SUMMARY();
}
