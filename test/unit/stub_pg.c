/*
 * stub_pg.c — backing implementation for the test-only elog stub.
 *
 * pg_ereport_buf / pg_ereport_armed are the global longjmp target that
 * tests arm before invoking a helper expected to ereport(ERROR).
 * pg_ereport_trampoline() is the single point the ereport() macro in
 * stubs/utils/elog.h routes to.
 *
 * Keeping the definitions here (rather than inline in the header) avoids
 * multiple-definition link errors when several test + helper translation
 * units all include the elog stub.
 */
#include "utils/elog.h"

jmp_buf pg_ereport_buf;
int     pg_ereport_armed = 0;

void pg_ereport_trampoline(int elevel)
{
    (void)elevel; /* only ERROR-and-above reach here, per the macro */
    if (pg_ereport_armed)
        longjmp(pg_ereport_buf, 1);
    /* No test armed a jump target: a real ERROR is fatal, so mirror that
     * by aborting rather than silently returning (which would let the
     * helper keep running past an error it never expected to survive). */
    abort();
}
