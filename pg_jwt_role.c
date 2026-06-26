/*
 * pg_jwt_role.c
 *
 * PostgreSQL extension that performs JWT signature verification and
 * SET LOCAL ROLE based on a configurable JWT claim. See plans/plan.md.
 *
 * Architecture:
 *   - PL/pgSQL wrapper (in pg_jwt_role--1.0.sql) does only mechanical
 *     split + base64url decode.
 *   - This single C function pg_jwt_verify_and_set_role is the ONLY
 *     code path that calls SetCurrentRoleId(), and it does so ONLY
 *     after successful OpenSSL signature verification.
 *   - ProcessUtility_hook intercepts SET ROLE for restricted session users.
 *
 * Step 1 (project skeleton): the C function body is a placeholder
 * (always returns ERROR). Subsequent steps replace it with the full
 * implementation: signature verify + JSON scan + role switch + GUC writes.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/errcodes.h"

PG_MODULE_MAGIC;

/*
 * verify_and_set_role(alg, signing_input, signature_b64, payload_decoded)
 *   -> text
 *
 * Atomic single-call entry point. NEVER call SetCurrentRoleId without
 * first verifying the JWT signature inside this function.
 *
 * Step 1 stub: always errors out. Step 3 replaces this body with the
 * full atomic implementation.
 */
PG_FUNCTION_INFO_V1(pg_jwt_verify_and_set_role);

Datum pg_jwt_verify_and_set_role(PG_FUNCTION_ARGS)
{
    ereport(ERROR,
            (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
             errmsg("pg_jwt_role: verify_and_set_role is not yet implemented "
                    "(see Step 3 of plans/plan.md)")));
    PG_RETURN_NULL();
}

/*
 * _PG_init — shared_preload_libraries entry point.
 *
 * Step 1: minimal stub. Steps 2 and 4 populate GUC registration
 * and install ProcessUtility_hook here.
 */
void _PG_init(void)
{
    /* Step 1: nothing to do yet. Step 2: DefineCustom*Variable() calls. */
}