-- pg_jwt_role extension: SQL and PL/pgSQL definitions
-- See plans/plan.md for full architecture.

-- ============================================================================
-- Step 1 (project skeleton): only the PL/pgSQL wrapper is registered here.
-- The C function pg_jwt_role.verify_and_set_role is declared in C file
-- pg_jwt_role.c and made available via CREATE FUNCTION below.
--
-- Step 2 also declares the read-side helper pgjwt.claim(name text), which
-- wraps the C entry point pg_jwt_claim_value. The C function looks up the
-- per-backend slot bound to `name` (see pg_jwt_claim_slot_lookup in
-- pg_jwt_role.c) and returns the current transaction-local value of the
-- matching pg_jwt_role.claim_<N> GUC, or NULL if no slot is bound.
-- ============================================================================

-- This stub will be replaced once the C function is implemented.
-- For Step 1, we register a placeholder so the extension loads.
-- The extension's objects are installed in the 'public' schema (see
-- pg_jwt_role.control). The function names are unprefixed so they
-- resolve via the default search_path; callers can refer to them as
-- 'set_role' and 'verify_and_set_role'.

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
BEGIN
  -- 1. Split JWT by '.'
  header_raw    := split_part(jwt_token, '.', 1);
  payload_raw   := split_part(jwt_token, '.', 2);
  signature_b64 := split_part(jwt_token, '.', 3);

  IF header_raw = '' OR payload_raw = '' OR signature_b64 = '' THEN
    RAISE EXCEPTION 'pg_jwt_role: malformed JWT (expected three dot-separated parts)';
  END IF;

  -- 2. base64url -> base64 for header (mechanical, no trust)
  header_b64 := replace(replace(header_raw, '-', '+'), '_', '/');

  -- 3. Extract alg from header (used only as C input; if tampered, sig will fail)
  alg := json_extract_path_text(
    convert_from(decode(header_b64, 'base64'), 'utf8')::json,
    'alg'
  );

  IF alg IS NULL OR alg = '' THEN
    RAISE EXCEPTION 'pg_jwt_role: JWT header missing "alg"';
  END IF;

  -- 4. base64url -> base64 for payload (mechanical, no trust)
  payload_b64 := replace(replace(payload_raw, '-', '+'), '_', '/');

  -- 5. Delegate everything atomic to C:
  --    signature verify -> JSON-parse payload -> extract role_claim
  --    -> check exp -> extract extra_claims -> SetCurrentRoleId
  --    -> set_config_option GUC_ACTION_LOCAL for each extra claim.
  --    On verification failure, NO side effects occur.
  RETURN pgjwt.verify_and_set_role(
    alg,
    convert_to(header_raw || '.' || payload_raw, 'utf8'),
    signature_b64,
    decode(payload_b64, 'base64')
  );
END;
$$;

-- Grant EXECUTE to PUBLIC by default; admin can REVOKE later.
GRANT EXECUTE ON FUNCTION pgjwt.set_role(text)   TO PUBLIC;
GRANT EXECUTE ON FUNCTION pgjwt.claim(text)     TO PUBLIC;
GRANT EXECUTE ON FUNCTION pgjwt.claim_value(text) TO PUBLIC;