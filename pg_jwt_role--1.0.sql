-- pg_jwt_role extension: SQL and PL/pgSQL definitions
-- See plans/plan.md for full architecture.
--
-- The extension's objects are installed into the dedicated 'pgjwt' schema
-- (see pg_jwt_role.control). PostgreSQL reserves the 'pg_' prefix for
-- system catalogs, so the extension cannot install into a 'pg_jwt_role'
-- schema itself; call sites refer to the functions as pgjwt.set_role()
-- and pgjwt.verify_and_set_role(). The canonical plan (§6) writes them as
-- pg_jwt_role.set_role / pg_jwt_role.verify_and_set_role — the schema is
-- the only deviation, agreed in AGENTS.md and reflected in pg_jwt_role.control.

-- ============================================================================
-- Step 5 (PL/pgSQL set_role orchestration) — LANDED.
--
-- This file implements pgjwt.set_role(jwt_token text) in PL/pgSQL. It is
-- INTENTIONALLY LIMITED to mechanical operations:
--   * split JWT by '.'
--   * base64url -> base64 character substitution + '=' padding for the
--     PG-strict base64 decoder
--   * decode(..., 'base64') for header + payload
--   * extract `alg` from the header JSON (used only as an input to the C
--     function; if the header has been tampered with, the signature check
--     inside the C function will fail)
--   * delegate EVERYTHING trust-requiring (signature verify, JSON-parse of
--     payload, exp check, role extraction, extra-claim GUC writes) to the
--     single atomic C function pgjwt.verify_and_set_role
--   * on signature failure inside the C function: ereport(ERROR) with NO
--     side effects on role / GUC state.
--
-- Step 2 (GUC registration) — LANDED in _PG_init. This file also declares
-- the read-side helper pgjwt.claim(name text), which wraps the C entry point
-- pg_jwt_claim_value. The C function looks up the per-backend slot bound to
-- `name` (see pg_jwt_claim_slot_lookup in pg_jwt_role.c) and returns the
-- current transaction-local value of the matching pg_jwt_role.claim_<N>
-- GUC, or NULL if no slot is bound.
--
-- Step 3 (atomic C function) — LANDED in pg_jwt_role.c as
-- pg_jwt_verify_and_set_role. The signature (alg text, signing_input bytea,
-- signature_b64 text, payload_decoded bytea) -> text matches this wrapper
-- 1:1. If you change the C function signature, this wrapper must change in
-- lock-step — there are no other callers.
--
-- Step 4 (ProcessUtility_hook) — LANDED in pg_jwt_role.c. Independent of
-- this file; the hook intercepts SET ROLE at the utility-statement level
-- and is invisible to PL/pgSQL orchestration here.
--
-- Schema note: the extension installs into the dedicated `pgjwt` schema
-- (see pg_jwt_role.control). PostgreSQL reserves `pg_` for system catalogs,
-- so the extension cannot install into a `pg_jwt_role` schema itself.
-- Call sites therefore refer to the functions as pgjwt.set_role() and
-- pgjwt.verify_and_set_role(). The plan §6 writes them as
-- pg_jwt_role.set_role / pg_jwt_role.verify_and_set_role — the schema is
-- the only deviation, agreed in AGENTS.md.
-- ============================================================================

-- Single atomic C function: verify + parse + set role + set extra claims.
-- This is the ONLY SQL-callable C function that touches SetCurrentRoleId.
-- It is IMPOSSIBLE to call SetCurrentRoleId without successful signature
-- verification.
CREATE FUNCTION pgjwt.verify_and_set_role(
    alg text,
    signing_input bytea,
    signature_b64 text,
    payload_decoded bytea
) RETURNS text
  LANGUAGE C
  STRICT
  VOLATILE
  SET search_path = pg_catalog
  AS 'MODULE_PATHNAME', 'pg_jwt_verify_and_set_role';

-- Read-side helper: lookup the current value bound to a user-facing
-- claim name. The C entry point pg_jwt_claim_value resolves `name` to
-- the per-backend claim slot and reads the value of pg_jwt_role.claim_<N>.
-- Returns NULL when no slot is currently bound to `name`.
--
-- The pgjwt.claim(name text) PL/pgSQL wrapper below turns NULL into
-- the empty string for friendlier use in COALESCE-free SQL contexts.
CREATE FUNCTION pgjwt.claim_value(name text)
  RETURNS text
  LANGUAGE C
  -- NOT STRICT: we want a NULL name argument to reach the C code and
  -- produce our own NULL_VALUE_NOT_ALLOWED error rather than a generic
  -- "function ... does not exist for type text[]" from the planner.
  VOLATILE
  SET search_path = pg_catalog
  AS 'MODULE_PATHNAME', 'pg_jwt_claim_value';

CREATE FUNCTION pgjwt.claim(name text)
  RETURNS text
  LANGUAGE plpgsql
  STABLE
  SET search_path = pg_catalog
  AS $$
BEGIN
    -- COALESCE turns "no slot bound" (NULL) into the empty string,
    -- which is what SQL callers usually want when comparing to ''.
    RETURN COALESCE(pgjwt.claim_value(name), '');
END;
$$;

-- PL/pgSQL orchestration: split + base64url decode only.
-- All trust-requiring operations (JSON parse, exp check, role switch,
-- extra-claim GUC writes) are delegated to the atomic C function.
CREATE FUNCTION pgjwt.set_role(jwt_token text)
  RETURNS text
  LANGUAGE plpgsql
  VOLATILE
  SET search_path = pg_catalog
  AS $$
DECLARE
  header_raw    text;
  payload_raw   text;
  signature_b64 text;
  header_b64    text;
  payload_b64   text;
  alg           text;
  signing_input bytea;
  payload_bytes bytea;
BEGIN
  -- 1. Split JWT by '.'  (mechanical — no trust)
  header_raw    := split_part(jwt_token, '.', 1);
  payload_raw   := split_part(jwt_token, '.', 2);
  signature_b64 := split_part(jwt_token, '.', 3);

  IF header_raw = '' OR payload_raw = '' OR signature_b64 = '' THEN
    RAISE EXCEPTION 'pg_jwt_role: malformed JWT (expected three dot-separated parts)';
  END IF;

  -- 2. base64url -> base64 for header  (mechanical — no trust).
  -- base64url omits padding; pad to a multiple of 4 for PG's strict decoder.
  header_b64 := replace(replace(header_raw, '-', '+'), '_', '/')
             || repeat('=', (4 - length(replace(replace(header_raw, '-', '+'), '_', '/')) % 4) % 4);

  -- 3. Extract alg from header (used only as C input; if tampered, sig will fail)
  alg := json_extract_path_text(
    convert_from(decode(header_b64, 'base64'), 'utf8')::json,
    'alg'
  );

  IF alg IS NULL OR alg = '' THEN
    RAISE EXCEPTION 'pg_jwt_role: JWT header missing "alg"';
  END IF;

  -- 4. base64url -> base64 for payload  (mechanical — no trust).
  -- base64url omits padding; PostgreSQL's decode(..., 'base64') is strict
  -- and rejects un-padded input. Pad to a multiple of 4 with '='.
  payload_b64 := replace(replace(payload_raw, '-', '+'), '_', '/')
              || repeat('=', (4 - length(replace(replace(payload_raw, '-', '+'), '_', '/')) % 4) % 4);
  payload_bytes := decode(payload_b64, 'base64');

  -- signing_input is the ASCII base64url(header).base64url(payload) — this is
  -- what the C function feeds to OpenSSL for the HMAC / DigestVerify call.
  signing_input := convert_to(header_raw || '.' || payload_raw, 'utf8');

  -- 5. Delegate EVERYTHING atomic to C:
  --    verify signature -> JSON-parse payload -> extract role_claim
  --    -> check exp -> extract extra_claims -> SetCurrentRoleId
  --    -> set_config_option for each extra claim GUC_ACTION_LOCAL.
  --    On verification failure, NO side effects occur.
  RETURN pgjwt.verify_and_set_role(
    alg              => alg,
    signing_input    => signing_input,
    signature_b64    => signature_b64,
    payload_decoded  => payload_bytes
  );
END;
$$;

-- Grant EXECUTE to PUBLIC by default; admin can REVOKE later.
GRANT EXECUTE ON FUNCTION pgjwt.set_role(text)   TO PUBLIC;
GRANT EXECUTE ON FUNCTION pgjwt.claim(text)     TO PUBLIC;
GRANT EXECUTE ON FUNCTION pgjwt.claim_value(text) TO PUBLIC;