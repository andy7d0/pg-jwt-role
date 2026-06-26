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
 * Step 2 (GUC registration): _PG_init now calls DefineCustom*Variable()
 * for all configuration and output GUCs. Output GUCs are PGC_SUSET so
 * non-superusers cannot tamper with them via set_config(); only the C
 * function (with temporary privilege elevation) writes them.
 *
 * Steps still pending in this file:
 *   - Step 3 - replace the placeholder body of pg_jwt_verify_and_set_role
 *     with the full atomic implementation (verify + JSON parse + role
 *     switch + GUC writes).
 *   - Step 4 - install the ProcessUtility_hook and its helper.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/errcodes.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

/*
 * Upper bound on the number of extra-claim GUCs that
 * pg_jwt_verify_and_set_role will write per call. The pool of registered
 * pg_jwt_role.<name> GUCs is sized to match - extra_claims may only
 * reference names from this pool.
 */
#define PG_JWT_MAX_CLAIMS 16

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
 * Check hook: reject non-positive values for size-bound GUCs so the
 * bounds remain meaningful. Used for max_jwt_len and max_claim_len.
 */
static bool
pg_jwt_positive_int_check(int *newval, void **extra, GucSource source)
{
    if (*newval < 1)
    {
        GUC_check_errdetail("Value must be at least 1.");
        return false;
    }
    return true;
}

/*
 * _PG_init - shared_preload_libraries entry point.
 *
 * Step 2: register all GUCs. Steps 3 and 4 replace the placeholder
 * pg_jwt_verify_and_set_role and install the ProcessUtility_hook.
 */
void _PG_init(void)
{
    /* ----------------------------------------------------------------
     * Configuration GUCs (input from admin).
     *
     * The defaults documented in plans/plan.md ("role", "sub,email",
     * 8192, 256) are not set programmatically by DefineCustom*Variable
     * - those functions always initialise string GUCs to the empty
     * string and int GUCs to 0. Step 3 (verify_and_set_role) applies
     * the documented defaults at read time when the GUC is empty.
     * ---------------------------------------------------------------- */

    /* Key material for JWT signature verification.
     *   - HS algorithms : raw key bytes (any string)
     *   - RS algorithms : PEM-encoded public key or certificate
     *   - ES algorithms : PEM-encoded public key or certificate
     * PGC_SIGHUP - only settable from postgresql.conf / ALTER SYSTEM by
     * a superuser. Cannot be changed mid-session, which is the right
     * semantics for the trust anchor of the JWT verifier. */
    DefineCustomStringVariable(
        "pg_jwt_role.verify_key",
        "Key material for JWT signature verification.",
        "Raw key bytes for HS256/384/512, or a PEM-encoded public key "
        "or certificate for RS*/ES* algorithms.",
        PGC_SIGHUP, 0,
        NULL, NULL, NULL);

    /* JWT claim name that names the target DB role. */
    DefineCustomStringVariable(
        "pg_jwt_role.role_claim",
        "JWT claim name containing the target database role.",
        "Default \"role\" is applied when this GUC is empty.",
        PGC_SUSET, 0,
        NULL, NULL, NULL);

    /* Comma-separated list of JWT claims to expose as transaction-local
     * pg_jwt_role.<name> GUCs after successful verification. Each name
     * must be one of the registered output GUCs in the pool below. */
    DefineCustomStringVariable(
        "pg_jwt_role.extra_claims",
        "Comma-separated JWT claims to expose as GUCs.",
        "Each name must match one of the registered pg_jwt_role.<name> "
        "output GUCs. Default \"sub,email\" is applied when empty.",
        PGC_SUSET, 0,
        NULL, NULL, NULL);

    /* Comma-separated list of session users whose SET ROLE is restricted
     * to the JWT-claimed role only. Comparison is against session_user
     * (not current_user), so the restriction persists across role
     * switches within the session. */
    DefineCustomStringVariable(
        "pg_jwt_role.restricted_session_users",
        "Session users whose SET ROLE is restricted to the JWT-claimed role.",
        "Comma-separated PostgreSQL role names, compared to session_user.",
        PGC_SIGHUP, 0,
        NULL, NULL, NULL);

    /* Defensive upper bound on accepted JWT length (in bytes). */
    DefineCustomIntVariable(
        "pg_jwt_role.max_jwt_len",
        "Maximum accepted JWT length in bytes.",
        "Defensive upper bound on input length. Default: 8192.",
        PGC_SUSET, 0,
        pg_jwt_positive_int_check, NULL, NULL);

    /* Defensive upper bound on the length of any single extracted claim
     * value. */
    DefineCustomIntVariable(
        "pg_jwt_role.max_claim_len",
        "Maximum length of any single claim value.",
        "Defensive upper bound on extracted claim length. Default: 256.",
        PGC_SUSET, 0,
        pg_jwt_positive_int_check, NULL, NULL);

    /* ----------------------------------------------------------------
     * Output GUCs (PGC_SUSET to prevent direct SQL tampering).
     *
     * These GUCs can only be written by pg_jwt_verify_and_set_role after
     * OpenSSL signature verification passes. Non-superusers attempting
     * SELECT set_config('pg_jwt_role.sub', 'fake', true) will be denied
     * because PGC_SUSET requires SECURITY_SUPERUSER. The C function
     * temporarily elevates with SetUserIdAndSecContext() before writing
     * them.
     * ---------------------------------------------------------------- */

    /* The role name resolved from the JWT. Used by ProcessUtility_hook
     * (Step 4) to compare against SET ROLE targets for restricted
     * session users. */
    DefineCustomStringVariable(
        "pg_jwt_role.role",
        "Resolved DB role from the current JWT.",
        "Written by pg_jwt_verify_and_set_role after signature "
        "verification; transaction-local via GUC_ACTION_LOCAL.",
        PGC_SUSET, 0,
        NULL, NULL, NULL);

    /* Fixed pool of pg_jwt_role.<name> GUCs, one per common JWT claim
     * that admins might want to expose. extra_claims may only reference
     * names registered here; anything else is rejected by the C function
     * (Step 3). The pool is fixed because GUCs can only be registered
     * during _PG_init - there is no supported API to add custom GUCs
     * at runtime. */
    static const char *const claim_guc_names[PG_JWT_MAX_CLAIMS] = {
        "pg_jwt_role.sub",
        "pg_jwt_role.email",
        "pg_jwt_role.name",
        "pg_jwt_role.preferred_username",
        "pg_jwt_role.iss",
        "pg_jwt_role.aud",
        "pg_jwt_role.iat",
        "pg_jwt_role.exp",
        "pg_jwt_role.nbf",
        "pg_jwt_role.jti",
        "pg_jwt_role.scope",
        "pg_jwt_role.roles",
        "pg_jwt_role.groups",
        "pg_jwt_role.tenant",
        "pg_jwt_role.org",
        "pg_jwt_role.client_id"};

    for (int i = 0; i < PG_JWT_MAX_CLAIMS; i++)
    {
        DefineCustomStringVariable(
            claim_guc_names[i],
            "JWT claim value exposed as a transaction-local GUC.",
            "Written by pg_jwt_verify_and_set_role after signature "
            "verification; PGC_SUSET prevents direct SQL tampering.",
            PGC_SUSET, 0,
            NULL, NULL, NULL);
    }
}
