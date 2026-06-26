-- pg_jwt_role extension: SQL and PL/pgSQL definitions
-- See plans/plan.md for full architecture.

-- ============================================================================
-- Step 1 (project skeleton): only the PL/pgSQL wrapper is registered here.
-- The C function pg_jwt_role.verify_and_set_role is declared in C file
-- pg_jwt_role.c and made available via CREATE FUNCTION below.
-- ============================================================================

-- This stub will be replaced once the C function is implemented.
-- For Step 1, we register a placeholder so the extension loads.
CREATE FUNCTION pg_jwt_role.verify_and_set_role(
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

-- PL/pgSQL orchestration: split + base64url decode only.
-- All trust-requiring operations (JSON parse, exp check, role switch,
-- extra-claim GUC writes) are delegated to the atomic C function.
CREATE FUNCTION pg_jwt_role.set_role(jwt_token text)
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
  RETURN pg_jwt_role.verify_and_set_role(
    alg,
    convert_to(header_raw || '.' || payload_raw, 'utf8'),
    signature_b64,
    decode(payload_b64, 'base64')
  );
END;
$$;

-- Grant EXECUTE to PUBLIC by default; admin can REVOKE later.
GRANT EXECUTE ON FUNCTION pg_jwt_role.set_role(text) TO PUBLIC;