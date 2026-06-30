/*
 * test_common.h — tiny assert + tally framework for the C unit tests.
 *
 * Each test binary is standalone: it links the production helper .c
 * file(s) it exercises plus stub_pg.c. A test calls CHECK_* / ASSERT_*
 * macros that print a per-check PASS/FAIL line and bump the global
 * counters; main() prints a summary and returns non-zero if any check
 * failed.
 *
 * Intentionally dependency-free (only stdio/stdbool/string) so the
 * harness stays portable across the GCC toolchain available in CI and
 * on developer machines without a PostgreSQL install.
 */
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>   /* EXPECT_EREPORT uses setjmp */

static int g_checks = 0;
static int g_failed = 0;

/*
 * Declarations for the ereport longjmp machinery defined in stub_pg.c.
 * Only tests that use EXPECT_EREPORT (currently test_csv.c) reference
 * them, but declaring them here keeps test_common.h self-contained so
 * the macros expand correctly regardless of include order.
 */
extern jmp_buf pg_ereport_buf;
extern int      pg_ereport_armed;

#define TEST_COUNT() do { g_checks++; } while (0)

#define TEST_FAIL(cond_str, file, line)                                       \
    do {                                                                      \
        g_failed++;                                                           \
        printf("  [FAIL] %s:%d: %s\n", file, line, cond_str);                \
    } while (0)

/* Boolean check: expression must be true. */
#define CHECK(cond)                                                           \
    do {                                                                      \
        g_checks++;                                                           \
        if (cond) {                                                           \
            printf("  [OK] %s\n", #cond);                                    \
        } else {                                                              \
            g_failed++;                                                       \
            printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
        }                                                                     \
    } while (0)

/* String equality check with a descriptive label. */
#define CHECK_STREQ(label, got, want)                                         \
    do {                                                                      \
        const char *_g = (got);                                               \
        const char *_w = (want);                                              \
        g_checks++;                                                           \
        if (_g == NULL) _g = "(null)";                                        \
        if (_w == NULL) _w = "(null)";                                        \
        if (strcmp(_g, _w) == 0) {                                            \
            printf("  [OK] %s: \"%s\"\n", label, _g);                        \
        } else {                                                              \
            g_failed++;                                                       \
            printf("  [FAIL] %s:%d: %s: got \"%s\", want \"%s\"\n",          \
                   __FILE__, __LINE__, label, _g, _w);                        \
        }                                                                     \
    } while (0)

/* Integer equality check with a descriptive label. */
#define CHECK_INT(label, got, want)                                           \
    do {                                                                      \
        long _g = (long)(got);                                                \
        long _w = (long)(want);                                               \
        g_checks++;                                                           \
        if (_g == _w) {                                                       \
            printf("  [OK] %s: %ld\n", label, _g);                           \
        } else {                                                              \
            g_failed++;                                                       \
            printf("  [FAIL] %s:%d: %s: got %ld, want %ld\n",                \
                   __FILE__, __LINE__, label, _g, _w);                        \
        }                                                                     \
    } while (0)

/* Expect that a call ereports(ERROR) instead of returning. The body
 * must be a single statement/expression (typically a function call).
 * Arms the stub longjmp target before invoking the body; on success
 * (ereport fired) the setjmp branch returns non-zero. */
#define EXPECT_EREPORT(label, body)                                           \
    do {                                                                      \
        g_checks++;                                                           \
        pg_ereport_armed = 1;                                                 \
        if (setjmp(pg_ereport_buf) == 0) {                                    \
            body;                                                             \
            g_failed++;                                                       \
            printf("  [FAIL] %s:%d: %s: expected ereport, returned\n",       \
                   __FILE__, __LINE__, label);                                \
        } else {                                                              \
            printf("  [OK] %s: ereport fired\n", label);                     \
        }                                                                     \
        pg_ereport_armed = 0;                                                 \
    } while (0)

#define TEST_SUMMARY()                                                        \
    do {                                                                      \
        printf("  --- %d checks, %d failed ---\n", g_checks, g_failed);      \
        return g_failed ? 1 : 0;                                              \
    } while (0)

#endif /* TEST_COMMON_H */
