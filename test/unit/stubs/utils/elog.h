/*
 * utils/elog.h — minimal test-only stub for ereport().
 *
 * The real PostgreSQL ereport() is a macro that, for severity ERROR,
 * formats a message and longjmps out via PG_RE_THROW() so the caller
 * never returns. pg_split_csv() relies on exactly that non-return
 * semantics: its over-long-name branch does ereport(ERROR, ...) and
 * expects control to leave the function.
 *
 * This stub reproduces the essential behaviour for unit tests:
 *   - ereport(elevel, ...) is a statement expression that calls
 *     stub_ereport(elevel), which longjmps through a global jmp_buf
 *     when a test has armed one, or aborts otherwise.
 *   - errcode() and errmsg() become no-op helper functions so the
 *     (errcode(...), errmsg(...)) tuple inside the ereport parens is a
 *     valid comma expression.
 *
 * The production call site in pg_jwt_csv.c compiles unchanged; only
 * the underlying machinery is swapped.
 */
#ifndef STUB_UTILS_ELOG_H
#define STUB_UTILS_ELOG_H

#include <setjmp.h>
#include <stdlib.h>

/* Severity levels. Only ERROR is used by the helpers under test. */
#define DEBUG5   10
#define DEBUG4   11
#define DEBUG3   12
#define DEBUG2   13
#define DEBUG1   14
#define INFO     17
#define NOTICE   18
#define WARNING  19
#define ERROR    20

/*
 * Global jump target armed by a test before calling a function that is
 * expected to ereport(ERROR). pg_ereport_trampoline() in stub_pg.c
 * longjmps here. A test does:
 *
 *   if (setjmp(pg_ereport_buf) == 0) {
 *       pg_split_csv(...);           // expected to ereport
 *       FAIL("expected ereport, returned instead");
 *   } else {
 *       PASS("ereport fired");
 *   }
 */
extern jmp_buf pg_ereport_buf;
extern int      pg_ereport_armed;

/* Defined in stub_pg.c. */
void pg_ereport_trampoline(int elevel);

/*
 * errcode() / errmsg() collapse to no-op int producers so the
 * "(errcode(...), errmsg(...))" tuple is a valid comma expression
 * whose overall type is int. ereport() discards that int.
 */
static inline int stub_errcode(int sqlstate) { (void)sqlstate; return 0; }
static inline int stub_errmsg(const char *fmt, ...) { (void)fmt; return 0; }

#define errcode    stub_errcode
#define errmsg     stub_errmsg

/*
 * ereport(elevel, ...) — statement expression. Mirrors PG's
 * non-return contract for ERROR: control does not continue past the
 * call. For non-ERROR levels we fall through (no test path uses them).
 */
#define ereport(elevel, ...)                       \
    do {                                           \
        if (elevel >= ERROR)                       \
            pg_ereport_trampoline(elevel);         \
    } while (0)

#endif /* STUB_UTILS_ELOG_H */
