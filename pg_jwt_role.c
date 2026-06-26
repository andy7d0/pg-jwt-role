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
 * for all configuration GUCs and for two flavours of output GUC:
 *
 *   1) pg_jwt_role.role
 *      Holds the resolved role name from the most recent successful
 *      verify_and_set_role() call in the current transaction. Used by
 *      the ProcessUtility_hook (Step 4) to compare against SET ROLE
 *      targets for restricted session users.
 *
 *   2) pg_jwt_role.claim_0 ... pg_jwt_role.claim_N-1
 *      A fixed pool of N = PG_JWT_MAX_CLAIMS (16) scratch slots that the
 *      C function writes claim values into. Each slot is dynamically
 *      bound at runtime to one of the user-facing claim names listed in
 *      the pg_jwt_role.extra_claims GUC. SQL callers read claim values
 *      through the helper function pgjwt.claim(name text), which looks
 *      up the slot bound to `name` and returns its value.
 *
 *      The binding is per-backend (a static C array), stable for the
 *      lifetime of the session, and persists across BEGIN/COMMIT. The
 *      VALUES themselves are transaction-local via GUC_ACTION_LOCAL
 *      and revert at COMMIT/ROLLBACK, just like SET LOCAL.
 *
 * Why a fixed slot pool rather than a DefineCustom*Variable call per
 * name: DefineCustom*Variable() can only be called from _PG_init. We
 * have no way to register "pg_jwt_role.<claim_name>" for an arbitrary
 * claim name that the admin picks via extra_claims. So we register N
 * fixed-name slots up-front and the C function writes through whichever
 * slot is currently bound to the requested claim name. New claim names
 * (not already in the pool) get the next free slot.
 *
 * All output GUCs (pg_jwt_role.role and the slot pool) are PGC_SUSET so
 * non-superusers cannot tamper with them via set_config(). The C function
 * (Step 3) temporarily elevates to superuser via SetUserIdAndSecContext()
 * before calling set_config_option().
 *
 * Steps still pending in this file:
 *   - Step 3 - replace the placeholder body of pg_jwt_verify_and_set_role
 *     with the full atomic implementation (verify + JSON parse + role
 *     switch + GUC writes through the slot pool).
 *   - Step 4 - install the ProcessUtility_hook and its helper.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/errcodes.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "limits.h"
#include "string.h"

PG_MODULE_MAGIC;

/* Internal helpers used by the C entry points. Defined further down. */
extern int  pg_jwt_claim_slot(const char *name);
extern int  pg_jwt_claim_slot_lookup(const char *name);
extern bool pg_jwt_claim_slot_guc_name(int slot, char *buf, int buflen);

/*
 * Pool size for the extra-claim GUC slot table. Caps the number of
 * distinct claim names that verify_and_set_role can bind at once.
 * Matches PG_JWT_MAX_CLAIMS in plans/plan.md §8.
 */
#define PG_JWT_MAX_CLAIMS 16

/*
 * Maximum length (in bytes, including NUL) of a single user-facing
 * claim name. PostgreSQL's NAMEDATALEN is 64; we use the same limit so
 * "pg_jwt_role." + name + slot suffix all fit comfortably in the
 * sizeof claim slot GUC name buffer (PG_JWT_MAX_CLAIM_NAME_LEN + 32).
 */
#define PG_JWT_MAX_CLAIM_NAME_LEN 64

/*
 * Per-backend slot binding table. claim_slot_name[i] holds the
 * user-facing claim name currently bound to slot i (e.g. "sub",
 * "email"), or the empty string if slot i is free. The array is
 * zero-initialised at backend startup; static storage means the binding
 * persists for the lifetime of the connection.
 *
 * The maximum index is PG_JWT_MAX_CLAIMS-1.
 */
static char claim_slot_name[PG_JWT_MAX_CLAIMS][PG_JWT_MAX_CLAIM_NAME_LEN];

/*
 * Backing storage for every claim-slot GUC we register. PostgreSQL 18
 * declares the valueAddr parameter as `pg_attribute_nonnull(1, 4)` -
 * passing NULL for either of the first 4 args (name, short_desc,
 * long_desc, valueAddr) is a runtime crash, not just a warning.
 *
 * The pointers stay valid for the lifetime of the backend process
 * because both the pointer and the buffer are static.
 */
static char cfg_claim_slot_buf[PG_JWT_MAX_CLAIMS][PG_JWT_MAX_CLAIM_NAME_LEN];
static char *cfg_claim_slot[PG_JWT_MAX_CLAIMS];

/*
 * Backing storage for the resolved-role output GUC and the
 * configuration GUCs registered in _PG_init. Static so PostgreSQL's
 * GUC system can read/write through the pointers for the lifetime of
 * the backend.
 */
static char cfg_role_buf[PG_JWT_MAX_CLAIM_NAME_LEN] = "";
static char cfg_verify_key_buf[4096] = "";
static char cfg_role_claim_buf[PG_JWT_MAX_CLAIM_NAME_LEN] = "";
static char cfg_extra_claims_buf[256] = "";
static char cfg_restricted_session_users_buf[1024] = "";
static int cfg_max_jwt_len = 8192;
static int cfg_max_claim_len = 256;

static char *cfg_verify_key = cfg_verify_key_buf;
static char *cfg_role_claim = cfg_role_claim_buf;
static char *cfg_extra_claims = cfg_extra_claims_buf;
static char *cfg_restricted_session_users = cfg_restricted_session_users_buf;
static char *cfg_role = cfg_role_buf;

/*
 * verify_and_set_role(alg, signing_input, signature_b64, payload_decoded)
 *   -> text
 *
 * Atomic single-call entry point. NEVER call SetCurrentRoleId without
 * first verifying the JWT signature inside this function.
 *
 * Step 2 stub: always errors out. Step 3 replaces this body with the
 * full atomic implementation (HMAC/EVP_DigestVerify, JSON scan, exp
 * check, SetCurrentRoleId, set_config_option through the slot pool).
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
 * pg_jwt_claim_slot - look up (or allocate) the slot index bound to a
 * given claim name. Returns the slot index in [0, PG_JWT_MAX_CLAIMS)
 * on success, or -1 if every slot is bound to a different name and no
 * room is left.
 *
 * Binding semantics:
 *   - If `name` is already bound to a slot, return that slot.
 *   - Otherwise, find the first slot whose binding is the empty string
 *     (free), bind `name` there, and return the slot index.
 *   - If all slots are bound to other names, return -1.
 *
 * This function is called from verify_and_set_role (Step 3) and from
 * the SQL helper pgjwt.claim() (defined in pg_jwt_role--1.0.sql).
 * Both call sites run under the caller's user id, but the slot table
 * is a static C array and therefore per-backend - no locking needed.
 *
 * `name` must be a NUL-terminated string of length at most
 * PG_JWT_MAX_CLAIM_NAME_LEN - 1 bytes. Longer names are rejected with
 * -1 so verify_and_set_role (Step 3) can ereport() with a clear
 * message.
 */
int pg_jwt_claim_slot(const char *name)
{
    int name_len;
    int free_slot;
    int i;

    if (name == NULL)
        return -1;

    name_len = strlen(name);
    if (name_len == 0 || name_len >= PG_JWT_MAX_CLAIM_NAME_LEN)
        return -1;

    free_slot = -1;

    for (i = 0; i < PG_JWT_MAX_CLAIMS; i++)
    {
        if (claim_slot_name[i][0] == '\0')
        {
            /* Remember the lowest free slot for the alloc path. */
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (strcmp(claim_slot_name[i], name) == 0)
            return i;
    }

    if (free_slot < 0)
        return -1; /* pool is full of distinct names */

    /* Bind `name` to the first free slot. The slot buffer is sized to
     * PG_JWT_MAX_CLAIM_NAME_LEN, and name_len was bounded above, so
     * this memcpy is always in-bounds. */
    memcpy(claim_slot_name[free_slot], name, name_len);
    claim_slot_name[free_slot][name_len] = '\0';
    return free_slot;
}

/*
 * pg_jwt_claim_slot_lookup - read-only variant used by the SQL helper
 * pgjwt.claim(). Returns the slot index bound to `name`, or -1 if no
 * slot is currently bound. Does not allocate a slot.
 */
int pg_jwt_claim_slot_lookup(const char *name)
{
    int i;

    if (name == NULL)
        return -1;

    for (i = 0; i < PG_JWT_MAX_CLAIMS; i++)
    {
        if (claim_slot_name[i][0] != '\0' &&
            strcmp(claim_slot_name[i], name) == 0)
            return i;
    }
    return -1;
}

/*
 * pg_jwt_claim_slot_guc_name - compose the full GUC name
 * "pg_jwt_role.claim_<slot>" for a given slot index into the supplied
 * buffer. The buffer must be at least PG_JWT_MAX_CLAIM_NAME_LEN + 32
 * bytes; we use PG_JWT_MAX_CLAIM_NAME_LEN here as a conservative lower
 * bound that comfortably fits "pg_jwt_role.claim_<two-digit-index>".
 *
 * Returns true on success, false if `slot` is out of range.
 */
bool pg_jwt_claim_slot_guc_name(int slot, char *buf, int buflen)
{
    if (slot < 0 || slot >= PG_JWT_MAX_CLAIMS)
        return false;
    if (buflen < 32)
        return false;

    snprintf(buf, (size_t)buflen, "pg_jwt_role.claim_%d", slot);
    return true;
}


/*
 * pg_jwt_claim_value - SQL-callable lookup of the value bound to a
 * claim name. The PL/pgSQL function pgjwt.claim(name text) calls this
 * to resolve `name` to its slot and return the current value of
 * pg_jwt_role.claim_<slot>. Returns NULL when `name` has no slot
 * bound yet, so SQL's COALESCE / IS NULL checks behave naturally.
 *
 * This is the read side of the slot pool: the write side is
 * pg_jwt_verify_and_set_role (Step 3), which calls
 * pg_jwt_claim_slot() to bind a name to a slot and
 * set_config_option() to write the value transaction-locally.
 */
PG_FUNCTION_INFO_V1(pg_jwt_claim_value);

Datum
pg_jwt_claim_value(PG_FUNCTION_ARGS)
{
    text       *name_arg;
    char       *name_cstr;
    int         slot;
    char        guc_name[32];
    const char *value;

    if (PG_ARGISNULL(0))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("pg_jwt_role: claim name must not be NULL")));

    name_arg = PG_GETARG_TEXT_PP(0);
    name_cstr = text_to_cstring(name_arg);
    pfree(name_arg);

    slot = pg_jwt_claim_slot_lookup(name_cstr);
    pfree(name_cstr);

    if (slot < 0)
        PG_RETURN_NULL();

    if (!pg_jwt_claim_slot_guc_name(slot, guc_name, sizeof(guc_name)))
        elog(ERROR, "pg_jwt_role: internal slot %d out of range", slot);

    /* missing_ok = true so that the very first read (before any JWT
     * has been verified) returns NULL instead of erroring. */
    value = GetConfigOptionByName(guc_name, NULL, true);
    if (value == NULL)
        PG_RETURN_NULL();

    PG_RETURN_TEXT_P(cstring_to_text(value));
}

/*
 * _PG_init - shared_preload_libraries entry point.
 *
 * Step 2: register all configuration GUCs, the resolved-role output
 * GUC, and the fixed-size pool of claim-slot GUCs. Steps 3 and 4
 * replace the placeholder pg_jwt_verify_and_set_role and install the
 * ProcessUtility_hook.
 */
void _PG_init(void)
{
    int i;

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
        &cfg_verify_key, "",
        PGC_SIGHUP, 0,
        NULL, NULL, NULL);

    /* JWT claim name that names the target DB role. */
    DefineCustomStringVariable(
        "pg_jwt_role.role_claim",
        "JWT claim name containing the target database role.",
        "Default \"role\" is applied when this GUC is empty.",
        &cfg_role_claim, "",
        PGC_SUSET, 0,
        NULL, NULL, NULL);

    /* Comma-separated list of JWT claims to expose as transaction-local
     * pg_jwt_role.<name> values after successful verification. Each
     * name is bound (lazily, at first use) to one of the slot GUCs
     * registered below; SQL callers read them via pgjwt.claim(name). */
    DefineCustomStringVariable(
        "pg_jwt_role.extra_claims",
        "Comma-separated JWT claims to expose via pgjwt.claim().",
        "Each name is bound to a claim_<N> slot GUC on first use; "
        "default \"sub,email\" is applied when empty.",
        &cfg_extra_claims, "",
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
        &cfg_restricted_session_users, "",
        PGC_SIGHUP, 0,
        NULL, NULL, NULL);

    /* Defensive upper bound on accepted JWT length (in bytes). */
    DefineCustomIntVariable(
        "pg_jwt_role.max_jwt_len",
        "Maximum accepted JWT length in bytes.",
        "Defensive upper bound on input length. Default: 8192.",
        &cfg_max_jwt_len, 8192, 1, INT_MAX,
        PGC_SUSET, 0,
        pg_jwt_positive_int_check, NULL, NULL);

    /* Defensive upper bound on the length of any single extracted claim
     * value. */
    DefineCustomIntVariable(
        "pg_jwt_role.max_claim_len",
        "Maximum length of any single claim value.",
        "Defensive upper bound on extracted claim length. Default: 256.",
        &cfg_max_claim_len, 256, 1, INT_MAX,
        PGC_SUSET, 0,
        pg_jwt_positive_int_check, NULL, NULL);

    /* ----------------------------------------------------------------
     * Output GUCs (PGC_SUSET to prevent direct SQL tampering).
     *
     * These GUCs can only be written by pg_jwt_verify_and_set_role after
     * OpenSSL signature verification passes. Non-superusers attempting
     * SELECT set_config('pg_jwt_role.role', 'fake', true) will be
     * denied because PGC_SUSET requires SECURITY_SUPERUSER. The C
     * function temporarily elevates with SetUserIdAndSecContext()
     * before writing them.
     * ---------------------------------------------------------------- */

    /* The role name resolved from the JWT. Used by ProcessUtility_hook
     * (Step 4) to compare against SET ROLE targets for restricted
     * session users. */
    DefineCustomStringVariable(
        "pg_jwt_role.role",
        "Resolved DB role from the current JWT.",
        "Written by pg_jwt_verify_and_set_role after signature "
        "verification; transaction-local via GUC_ACTION_LOCAL.",
        &cfg_role, "",
        PGC_SUSET, 0,
        NULL, NULL, NULL);

    /* Fixed pool of pg_jwt_role.claim_<N> slot GUCs. Each slot holds
     * the value of one user-facing claim name (sub, email, tenant,
     * whatever the admin lists in extra_claims). The C function binds
     * claim names to slots via pg_jwt_claim_slot() and writes values
     * via set_config_option("pg_jwt_role.claim_N", ...,
     * GUC_ACTION_LOCAL). SQL callers read the current value through
     * the helper pgjwt.claim(name).
     *
     * The pool size is fixed at PG_JWT_MAX_CLAIMS because GUCs can
     * only be registered during _PG_init - there is no supported API
     * to add custom GUCs at runtime. Each slot is PGC_SUSET so direct
     * SQL tampering (SELECT set_config('pg_jwt_role.claim_0', ...))
     * is blocked for non-superusers. */
    for (i = 0; i < PG_JWT_MAX_CLAIMS; i++)
    {
        char guc_name[32];

        /* Zero the slot backing buffer and the cfg_*_claim_slot
         * pointer. cfg_claim_slot[i] stays valid for the lifetime of
         * the backend (static storage) so PostgreSQL can swap the
         * pointer through it whenever the GUC value changes. */
        cfg_claim_slot_buf[i][0] = '\0';
        cfg_claim_slot[i] = cfg_claim_slot_buf[i];

        snprintf(guc_name, sizeof(guc_name), "pg_jwt_role.claim_%d", i);

        DefineCustomStringVariable(
            guc_name,
            "JWT claim value slot (read via pgjwt.claim).",
            "One of the pg_jwt_role.claim_<N> scratch slots. The C "
            "function binds a user-facing claim name to a slot at "
            "first use and writes its value here transaction-locally. "
            "PGC_SUSET prevents direct SQL tampering.",
            &cfg_claim_slot[i], "",
            PGC_SUSET, 0,
            NULL, NULL, NULL);
    }
}
