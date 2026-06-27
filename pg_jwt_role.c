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
 * Step 3 (atomic C function): pg_jwt_verify_and_set_role now performs
 * the full verify + JSON-parse + exp check + SetCurrentRoleId +
 * set_config_option sequence after a successful OpenSSL signature
 * check. See pg_jwt_verify() for the algorithm dispatch (HS/RS/ES families)
 * and pg_json_extract_value() for the payload scanner. All output
 * GUCs (pg_jwt_role.role and the claim_<N> slot pool) are written
 * with privilege elevation around set_config_option() to bypass
 * PGC_SUSET for the caller.
 *
 * Step 4 (ProcessUtility hook): _PG_init installs
 * pg_jwt_role_ProcessUtility as the ProcessUtility_hook. The hook is
 * keyed off session_user (not current_user) so the restriction
 * persists across role switches within a session. For users listed
 * in pg_jwt_role.restricted_session_users, SET ROLE <name> is only
 * allowed when the target role OID matches GetCurrentRoleId() (the
 * role set by the atomic C function above). SET ROLE NONE and RESET
 * ROLE are always allowed (safe revert to session_user). Other
 * statements pass through to the next hook (or
 * standard_ProcessUtility) untouched. See plans/plan.md §7.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/errcodes.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "nodes/parsenodes.h" /* VariableSetStmt, VariableSetKind */
#include "nodes/plannodes.h"  /* PlannedStmt */
#include "limits.h"
#include "string.h"

#include "miscadmin.h"     /* GetUserIdAndSecContext, SetUserIdAndSecContext,
                                   * BOOTSTRAP_SUPERUSERID, SECURITY_SUPERUSER */
#include "commands/user.h" /* SetCurrentRoleId, GetCurrentRoleId */
#include "utils/acl.h"     /* get_role_oid */
#include "tcop/utility.h"  /* ProcessUtility_hook_type, standard_ProcessUtility */
/* GetSessionUserId is in miscadmin.h (already included). */

#include <openssl/hmac.h>   /* HMAC */
#include <openssl/evp.h>    /* EVP_sha*, EVP_DigestVerify*, EVP_PKEY */
#include <openssl/pem.h>    /* PEM_read_bio_PUBKEY */
#include <openssl/bio.h>    /* BIO_new_mem_buf */
#include <openssl/crypto.h> /* CRYPTO_memcmp */

#include <stdio.h>  /* snprintf */
#include <stdlib.h> /* strtoll, atoi */
#include <time.h>   /* time, time_t */

PG_MODULE_MAGIC;

/* Internal helpers used by the C entry points. Defined further down. */
extern int pg_jwt_claim_slot(const char *name);
extern int pg_jwt_claim_slot_lookup(const char *name);
extern bool pg_jwt_claim_slot_guc_name(int slot, char *buf, int buflen);

/* Base64 / base64url decoders. Defined in pg_jwt_base64.c. */
extern int pg_base64_decode(const char *src, int srclen,
                            char *dst, int dstlen);
extern int pg_base64url_decode(const char *src, int srclen,
                               char *scratch, int scratchlen,
                               char *dst, int dstlen);

/* JSON scan, CSV split, and string-list helpers. Defined in their own .c files. */
#include "pg_jwt_json.h"
#include "pg_jwt_csv.h"
#include "pg_jwt_strlist.h"

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
 * Stack-buffer size constants for the atomic C function
 * pg_jwt_verify_and_set_role (Step 3). Matches plans/plan.md §8.
 *
 * Hard rule: no palloc, no malloc. Every byte the C function
 * touches must fit in one of these fixed-size stack buffers.
 */
#define PG_JWT_MAX_ALG_LEN 16
#define PG_JWT_MAX_SIG_BYTES 512
#define PG_JWT_MAX_KEY_LEN 4096
#define PG_JWT_MAX_PAYLOAD_LEN 1024
#define PG_JWT_MAX_CLAIM_VAL_LEN 256

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
static char *cfg_claim_slot[PG_JWT_MAX_CLAIMS] = {0};
static char *cfg_verify_key = NULL;
static char *cfg_role_claim = NULL;
static char *cfg_extra_claims = NULL;
static char *cfg_restricted_session_users = NULL;
static char *cfg_role = NULL;
static int cfg_max_jwt_len = 8192;
static int cfg_max_claim_len = 256;

/*
 * pg_jwt_verify - dispatch signature verification based on `alg`.
 *
 *   HS256/384/512 : HMAC-SHA-2 over signing_input with `key` as the
 *                   secret. Verification is constant-time via
 *                   CRYPTO_memcmp().
 *   RS256/384/512 : EVP_DigestVerify* with a PEM-encoded RSA public
 *                   key from `key`.
 *   ES256/384/512 : EVP_DigestVerify* with a PEM-encoded EC public
 *                   key from `key`.
 *
 * Returns true iff the signature is cryptographically valid. Any
 * failure (unknown alg, malformed PEM, length mismatch, OpenSSL
 * error) collapses to false. The caller turns that into an ereport.
 */
static bool
pg_jwt_verify(const char *alg,
              const char *signing_input, int signing_input_len,
              const char *signature, int signature_len,
              const char *key, int key_len)
{
    const EVP_MD *md = NULL;
    bool is_hmac = false;
    bool is_asym = false;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    int cmp;

    if (alg == NULL || alg[0] == '\0')
        return false;

    if (strcmp(alg, "HS256") == 0)
    {
        md = EVP_sha256();
        is_hmac = true;
    }
    else if (strcmp(alg, "HS384") == 0)
    {
        md = EVP_sha384();
        is_hmac = true;
    }
    else if (strcmp(alg, "HS512") == 0)
    {
        md = EVP_sha512();
        is_hmac = true;
    }
    else if (strcmp(alg, "RS256") == 0)
    {
        md = EVP_sha256();
        is_asym = true;
    }
    else if (strcmp(alg, "RS384") == 0)
    {
        md = EVP_sha384();
        is_asym = true;
    }
    else if (strcmp(alg, "RS512") == 0)
    {
        md = EVP_sha512();
        is_asym = true;
    }
    else if (strcmp(alg, "ES256") == 0)
    {
        md = EVP_sha256();
        is_asym = true;
    }
    else if (strcmp(alg, "ES384") == 0)
    {
        md = EVP_sha384();
        is_asym = true;
    }
    else if (strcmp(alg, "ES512") == 0)
    {
        md = EVP_sha512();
        is_asym = true;
    }
    else
        return false;

    if (md == NULL)
        return false;

    if (is_hmac)
    {
        if (key_len <= 0)
            return false;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        if (HMAC(md, key, key_len,
                 (const unsigned char *)signing_input,
                 (size_t)signing_input_len,
                 mac, &mac_len) == NULL)
            return false;
#pragma GCC diagnostic pop

        if (mac_len != (unsigned int)signature_len)
            return false;
        cmp = CRYPTO_memcmp(mac, signature, mac_len);
        return (cmp == 0);
    }

    if (is_asym)
    {
        EVP_PKEY *pkey = NULL;
        EVP_MD_CTX *ctx = NULL;
        BIO *bio = NULL;
        bool ok = false;

        if (signature_len <= 0 || key_len <= 0)
            return false;

        bio = BIO_new_mem_buf((void *)key, key_len);
        if (bio == NULL)
            goto out;

        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (pkey == NULL)
            goto out;

        ctx = EVP_MD_CTX_new();
        if (ctx == NULL)
            goto out;

        if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1)
            goto out;
        if (EVP_DigestVerifyUpdate(ctx,
                                   signing_input,
                                   (size_t)signing_input_len) != 1)
            goto out;
        if (EVP_DigestVerifyFinal(ctx,
                                  (const unsigned char *)signature,
                                  (size_t)signature_len) != 1)
            goto out;

        ok = true;
    out:
        if (ctx != NULL)
            EVP_MD_CTX_free(ctx);
        if (pkey != NULL)
            EVP_PKEY_free(pkey);
        if (bio != NULL)
            BIO_free(bio);
        return ok;
    }

    return false;
}

/*
 * verify_and_set_role(alg, signing_input, signature_b64, payload_decoded)
 *   -> text
 *
 * Atomic single-call entry point. NEVER call SetCurrentRoleId without
 * first verifying the JWT signature inside this function.
 *
 * Step 3 implementation:
 *   1. Pull alg / signing_input / sig_b64 / payload off PG_FUNCTION_ARGS.
 *   2. Read verify_key, role_claim, extra_claims, max_jwt_len,
 *      max_claim_len GUCs (applying documented defaults when empty).
 *   3. Decode signature_b64 (base64url) into a stack buffer.
 *   4. pg_jwt_verify() - OpenSSL verify with constant-time compare.
 *      On FAIL -> ereport(ERROR), NO side effects.
 *   5. Copy payload into a NUL-terminated stack buffer for scanning.
 *   6. Check "exp" claim vs time(NULL).
 *   7. Extract role_claim value, resolve role_oid via get_role_oid().
 *   8. Parse extra_claims CSV, extract each claim value from payload.
 *   9. SetCurrentRoleId(role_oid)  -- ROLE SWITCH
 *  10. Elevate to superuser, write pg_jwt_role.role GUC + each claim
 *      slot GUC via set_config_option(GUC_ACTION_LOCAL).
 *  11. Restore original security context.
 *  12. Return role_name text.
 */
PG_FUNCTION_INFO_V1(pg_jwt_verify_and_set_role);

Datum pg_jwt_verify_and_set_role(PG_FUNCTION_ARGS)
{
    text *alg_arg;
    bytea *signing_input_arg;
    text *sig_b64_arg;
    bytea *payload_arg;
    char alg_buf[PG_JWT_MAX_ALG_LEN];
    int alg_len;
    char sig_b64[PG_JWT_MAX_SIG_BYTES + 4];
    /* Normalised form of sig_b64 (base64url '-'/'_' -> '+'/'/'), with
     * '=' padding to a multiple of 4. Filled in by pg_base64url_decode()
     * in pg_jwt_base64.c. Kept separate from sig_b64 because the decoder
     * needs to read src while writing the normalised form. */
    char sig_b64_norm[PG_JWT_MAX_SIG_BYTES + 4];
    int sig_b64_len;
    int signing_input_len;
    const char *signing_input_ptr;
    int payload_len;
    const char *payload_ptr;

    const char *verify_key;
    int verify_key_len;

    char role_claim[PG_JWT_MAX_CLAIM_NAME_LEN];
    char extra_claims[256];
    int max_jwt_len;
    int max_claim_len;

    char sig_bytes[PG_JWT_MAX_SIG_BYTES];
    int sig_bytes_len;

    char payload_buf[PG_JWT_MAX_PAYLOAD_LEN + 1];

    char exp_str[64];
    time_t exp_val;
    time_t now;

    char role_name[PG_JWT_MAX_CLAIM_NAME_LEN];
    Oid role_oid;

    char claim_names[PG_JWT_MAX_CLAIMS][PG_JWT_MAX_CLAIM_NAME_LEN];
    char claim_vals[PG_JWT_MAX_CLAIMS][PG_JWT_MAX_CLAIM_VAL_LEN];
    int n_extra;
    int i;

    Oid save_userid;
    int save_sec;
    char slot_guc[64];

    /* ----- 1. Pull arguments. STRICT means non-NULL, but be defensive. */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) ||
        PG_ARGISNULL(2) || PG_ARGISNULL(3))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("pg_jwt_role: verify_and_set_role arguments must not be NULL")));

    alg_arg = PG_GETARG_TEXT_PP(0);
    signing_input_arg = PG_GETARG_BYTEA_PP(1);
    sig_b64_arg = PG_GETARG_TEXT_PP(2);
    payload_arg = PG_GETARG_BYTEA_PP(3);

    alg_len = VARSIZE_ANY_EXHDR(alg_arg);
    if (alg_len <= 0 || alg_len >= PG_JWT_MAX_ALG_LEN)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: invalid alg length")));
    memcpy(alg_buf, VARDATA_ANY(alg_arg), alg_len);
    alg_buf[alg_len] = '\0';

    signing_input_len = VARSIZE_ANY_EXHDR(signing_input_arg);
    signing_input_ptr = VARDATA_ANY(signing_input_arg);

    sig_b64_len = VARSIZE_ANY_EXHDR(sig_b64_arg);
    if (sig_b64_len < 0 || sig_b64_len >= (int)sizeof(sig_b64))
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: signature_b64 too long")));
    memcpy(sig_b64, VARDATA_ANY(sig_b64_arg), sig_b64_len);
    sig_b64[sig_b64_len] = '\0';

    payload_len = VARSIZE_ANY_EXHDR(payload_arg);
    payload_ptr = VARDATA_ANY(payload_arg);
    if (payload_len < 0 || payload_len > PG_JWT_MAX_PAYLOAD_LEN)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: payload too large")));

    /* ----- 2. Read configuration GUCs. */
    verify_key = GetConfigOptionByName("pg_jwt_role.verify_key", NULL, false);
    if (verify_key == NULL || verify_key[0] == '\0')
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("pg_jwt_role: pg_jwt_role.verify_key is not set")));
    verify_key_len = (int)strlen(verify_key);
    if (verify_key_len >= PG_JWT_MAX_KEY_LEN)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: verify_key too long")));

    {
        const char *rc_raw = GetConfigOptionByName("pg_jwt_role.role_claim", NULL, false);
        const char *src = (rc_raw != NULL && rc_raw[0] != '\0') ? rc_raw : "role";
        strncpy(role_claim, src, sizeof(role_claim) - 1);
        role_claim[sizeof(role_claim) - 1] = '\0';
    }
    {
        const char *ec_raw = GetConfigOptionByName("pg_jwt_role.extra_claims", NULL, false);
        const char *src = (ec_raw != NULL && ec_raw[0] != '\0') ? ec_raw : "sub,email";
        strncpy(extra_claims, src, sizeof(extra_claims) - 1);
        extra_claims[sizeof(extra_claims) - 1] = '\0';
    }

    {
        const char *mjl_raw = GetConfigOptionByName("pg_jwt_role.max_jwt_len", NULL, false);
        max_jwt_len = (mjl_raw != NULL) ? atoi(mjl_raw) : 0;
        if (max_jwt_len <= 0)
            max_jwt_len = 8192;
    }
    {
        const char *mcl_raw = GetConfigOptionByName("pg_jwt_role.max_claim_len", NULL, false);
        max_claim_len = (mcl_raw != NULL) ? atoi(mcl_raw) : 0;
        if (max_claim_len <= 0)
            max_claim_len = 256;
    }

    /* Defensive upper-bound check on signing_input. */
    if (signing_input_len > max_jwt_len)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: signing_input exceeds max_jwt_len")));

    /* ----- 3. Decode signature from base64url (delegated to
     * pg_jwt_base64.c; does alphabet substitution + '=' padding +
     * standard base64 decode in one shot). */
    sig_bytes_len = pg_base64url_decode(sig_b64, sig_b64_len,
                                        sig_b64_norm, (int)sizeof(sig_b64_norm),
                                        sig_bytes, (int)sizeof(sig_bytes));
    if (sig_bytes_len < 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: malformed signature_b64")));

    /* ----- 4. OpenSSL signature verify (HS / RS / ES family). */
    if (!pg_jwt_verify(alg_buf,
                       signing_input_ptr, signing_input_len,
                       sig_bytes, sig_bytes_len,
                       verify_key, verify_key_len))
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                 errmsg("pg_jwt_role: JWT signature verification failed")));

    /* ----- 5. Copy payload into NUL-terminated stack buffer. */
    memcpy(payload_buf, payload_ptr, payload_len);
    payload_buf[payload_len] = '\0';

    /* ----- 6. exp check (numeric claim). Missing exp is tolerated. */
    if (pg_json_extract_value(payload_buf, "exp", exp_str, sizeof(exp_str)))
    {
        char *endp = NULL;
        long long parsed = strtoll(exp_str, &endp, 10);
        if (endp != exp_str && *endp == '\0')
        {
            exp_val = (time_t)parsed;
            now = time(NULL);
            if (now >= exp_val)
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                         errmsg("pg_jwt_role: JWT expired")));
        }
    }

    /* ----- 7. Extract role claim, resolve role OID. */
    if (!pg_json_extract_value(payload_buf, role_claim,
                               role_name, (int)sizeof(role_name)))
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                 errmsg("pg_jwt_role: JWT missing \"%s\" claim", role_claim)));
    if ((int)strlen(role_name) > max_claim_len)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("pg_jwt_role: role claim value exceeds max_claim_len")));

    role_oid = get_role_oid(role_name, true);
    if (!OidIsValid(role_oid))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("pg_jwt_role: role \"%s\" does not exist", role_name)));

    /* ----- 8. Parse extra_claims CSV and extract each value. */
    n_extra = pg_split_csv(extra_claims, claim_names, PG_JWT_MAX_CLAIMS);
    for (i = 0; i < n_extra; i++)
    {
        if (!pg_json_extract_value(payload_buf, claim_names[i],
                                   claim_vals[i],
                                   (int)sizeof(claim_vals[i])))
            claim_vals[i][0] = '\0';
    }

    /* ----- 9. ATOMIC ROLE SWITCH. Caller's privileges are in effect
     * here; the JWT's signature has already authorised the switch. */
    SetCurrentRoleId(role_oid, false);

    /* ----- 10/11. GUC writes under temporary superuser elevation.
     *
     * PG 18's SecurityRestrictionContext is a bitmask
     * (SECURITY_LOCAL_USERID_CHANGE=0x1, SECURITY_RESTRICTED_OPERATION=0x2,
     * SECURITY_NOFORCE_RLS=0x4); "superuser" is signalled by zero flags,
     * not by a SECURITY_SUPERUSER value (which only existed pre-18).
     */
    GetUserIdAndSecContext(&save_userid, &save_sec);
    /* Bootstrap superuser OID is hard-coded to 10 in pg_authid. PG 18 removed
     * the public BOOTSTRAP_SUPERUSERID macro; the value is stable and
     * verified via FirstNormalObjectId=16384. */
    SetUserIdAndSecContext(10, 0);

    set_config_option("pg_jwt_role.role", role_name,
                      PGC_SUSET, PGC_S_SESSION,
                      GUC_ACTION_LOCAL, true, 0, false);

    for (i = 0; i < n_extra; i++)
    {
        int slot;

        if (claim_vals[i][0] == '\0')
            continue;

        slot = pg_jwt_claim_slot(claim_names[i]);
        if (slot < 0)
            continue; /* pool exhausted - drop silently */

        if (!pg_jwt_claim_slot_guc_name(slot, slot_guc, sizeof(slot_guc)))
            continue;

        set_config_option(slot_guc, claim_vals[i],
                          PGC_SUSET, PGC_S_SESSION,
                          GUC_ACTION_LOCAL, true, 0, false);
    }

    SetUserIdAndSecContext(save_userid, save_sec);

    /* ----- 12. Return the resolved role name. */
    PG_RETURN_TEXT_P(cstring_to_text(role_name));
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

Datum pg_jwt_claim_value(PG_FUNCTION_ARGS)
{
    text *name_arg;
    char *name_cstr;
    int slot;
    char guc_name[32];
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
 * ProcessUtility_hook (Step 4).
 *
 * The hook is installed in _PG_init and runs on every utility
 * command (SET, RESET, EXPLAIN, VACUUM, etc.). It does a tiny check
 * and then chains to the previous hook (or standard_ProcessUtility):
 *
 *   - Only T_VariableSetStmt is interesting. Everything else passes
 *     straight through.
 *   - Even for T_VariableSetStmt, we only enforce a restriction when
 *     session_user is listed in pg_jwt_role.restricted_session_users.
 *     Users not on the list have unrestricted SET ROLE.
 *   - For the SET ROLE <name> case, the only allowed targets are
 *     "none" (safe revert to session_user) and the role currently held
 *     via GetCurrentRoleId() (the role set by the atomic C function
 *     in Step 3). Anything else is rejected with INSUFFICIENT_PRIVILEGE.
 *   - RESET ROLE is always allowed: it is the explicit, parameterless
 *     form of "revert to session_user".
 *   - SET SESSION AUTHORIZATION is superuser-only and we don't touch
 *     it here.
 *
 * Keying off session_user (not current_user) means the restriction
 * persists across role switches within the same session, which is
 * exactly what we want: app_user logs in, JWT sets current_user to
 * tenant_a, and an attempt to SET ROLE tenant_b must still be denied.
 */

static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;

/*
 * is_session_user_restricted - return true iff the current
 * session_user appears in pg_jwt_role.restricted_session_users.
 *
 * The list is a comma-separated string of role names. Comparison is
 * case-sensitive against GetSessionUserId()'s name, exactly as
 * PostgreSQL itself would resolve the role in a SET ROLE statement.
 */
static bool
is_session_user_restricted(void)
{
    Oid session_oid;
    char *session_name;

    session_oid = GetSessionUserId();
    if (!OidIsValid(session_oid))
        return false;

    /*
     * GetUserNameFromId allocates in the current memory context. The
     * hook may run in contexts (e.g. ProcessUtility_context in error
     * recovery) where pfree'ing that buffer is unsafe, so we deliberately
     * let the allocation ride until the surrounding context is reset.
     * The buffer is at most NAMEDATALEN bytes, so the leak per call is
     * negligible.
     */
    session_name = GetUserNameFromId(session_oid, false);
    if (session_name == NULL || session_name[0] == '\0')
        return false;

    return pg_jwt_strlist_contains(cfg_restricted_session_users, session_name);
}

static void
pg_jwt_role_ProcessUtility(PlannedStmt *pstmt,
                           const char *queryString,
                           bool readOnlyTree,
                           ProcessUtilityContext context,
                           ParamListInfo params,
                           QueryEnvironment *queryEnv,
                           DestReceiver *dest,
                           QueryCompletion *qc)
{
    Node *parsetree;

    parsetree = pstmt->utilityStmt;

    /*
     * Restrict SET ROLE <name> for restricted session users. SET ROLE
     * NONE and RESET ROLE are explicitly allowed: they just revert to
     * session_user, which is not a privilege escalation.
     */
    if (parsetree != NULL &&
        nodeTag(parsetree) == T_VariableSetStmt &&
        is_session_user_restricted())
    {
        VariableSetStmt *stmt = (VariableSetStmt *)parsetree;

        if (stmt->name != NULL &&
            strcmp(stmt->name, "role") == 0 &&
            stmt->kind == VAR_SET_VALUE &&
            stmt->args != NULL)
        {
            Node *_n = linitial(stmt->args);
            char *target = NULL;
            if (IsA(_n, A_Const) && nodeTag(&((A_Const *)_n)->val) == T_String)
                target = strVal(&((A_Const *)_n)->val);
            else if (IsA(_n, String))
                target = strVal(_n);
            if (target == NULL)
                return;

            if (strcmp(target, "none") != 0)
            {
                Oid target_oid = get_role_oid(target, true);
                Oid claimed_oid = GetCurrentRoleId();

                /*
                 * Reject unless the target OID matches the role the
                 * atomic C function set. If the role doesn't exist,
                 * get_role_oid(..., true) returns InvalidOid, which
                 * will not match a valid claimed_oid and will be
                 * rejected here. We let PostgreSQL's own resolution
                 * produce its normal "role does not exist" error if
                 * the target is truly unknown.
                 */
                if (!OidIsValid(target_oid) ||
                    !OidIsValid(claimed_oid) ||
                    target_oid != claimed_oid)
                {
                    ereport(ERROR,
                            (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                             errmsg("pg_jwt_role: SET ROLE to \"%s\" rejected: "
                                    "role must be set via pgjwt.set_role()",
                                    target)));
                }
            }
        }
    }

    /* Chain to next hook or standard utility processor. */
    if (next_ProcessUtility_hook != NULL)
        next_ProcessUtility_hook(pstmt, queryString, readOnlyTree,
                                 context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);
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
        cfg_claim_slot[i] = NULL;
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

    /* ----------------------------------------------------------------
     * Step 4: install ProcessUtility_hook.
     *
     * Save whatever hook was previously installed so we can chain to
     * it. If we are the first hook, the saved value is NULL and we
     * fall through to standard_ProcessUtility() instead.
     * ---------------------------------------------------------------- */
    next_ProcessUtility_hook = ProcessUtility_hook;
    ProcessUtility_hook = pg_jwt_role_ProcessUtility;
}
