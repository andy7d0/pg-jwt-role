#!/usr/bin/env python3
"""
test_jwt_helper.py — generate test JWTs for pg_jwt_role regression tests.

Usage:
    test_jwt_helper.py --secret KEY --role ROLE [--exp EPOCH]
                       [--sub VAL] [--email VAL] [--alg ALG]
                       [--tamper-sig] [--b64url-sig]
                       [--no-exp]

Algorithms:
    HS256, HS384, HS512  HMAC with --secret as the symmetric key.

Flags:
    --exp EPOCH        Absolute exp claim (defaults to now+3600).
    --alg ALG          JWS alg field (default HS256).
    --no-exp           Omit the exp claim entirely.
    --tamper-sig       Flip a byte in the signature segment so verify() must fail.
    --b64url-sig       Rewrite the signature segment to use base64url characters
                       (-, _) instead of standard base64 (+, /). Exercises the
                       pg_jwt_role base64url -> base64 normalisation in the C
                       function. The signature itself remains a valid HMAC, so
                       this isolates the normalisation path from the verify path.

All `--key=value` extras become payload['key'] = 'value' claims.

Output is the raw compact JWS to stdout. Errors go to stderr with exit 2.
"""
import argparse
import base64
import sys
import time

import jwt  # PyJWT

# Algorithms the C function knows how to verify (HS family only — RS/ES need
# PEM keys which are not in scope for this single-cluster harness).
SUPPORTED_ALGS = ("HS256", "HS384", "HS512")


def b64url_decode(data: str) -> bytes:
    """PyJWT already handles base64url; this is only used for tamper mode."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def std_b64url_mix(s: str) -> str:
    """Rewrite a base64url string so that, when interpreted as standard
    base64 by the C function, every '+' becomes '-' and every '/' becomes '_'
    of the *base64url alphabet*. We achieve this by remapping characters in
    the raw signature bytes that decode to '+' or '/' in base64.

    Concretely: pick the last full quartet of the signature, decode its
    3 bytes, set the low 6 bits of the third byte so that, re-encoded,
    one of the output chars is '-' or '_' in base64url. This produces a
    signature that is a *valid* HMAC over the same input but whose textual
    encoding uses base64url characters.

    The C function must normalise these back to '+' / '/' before decoding.
    """
    pad = "=" * (-len(s) % 4)
    raw = bytearray(base64.urlsafe_b64decode(s + pad))
    # Find the last index whose base64url char is '+' or '/'. We flip a bit
    # in raw bytes 2..end until we get one. Cheap and bounded.
    for i in range(len(raw) - 1, 1, -1):
        raw[i] ^= 0x10  # perturb middle bits; usually produces a different
                        # base64url char. Keep perturbing until we land on
                        # '-' or '_'.
        for _ in range(256):
            out = b64url_encode(bytes(raw))
            if "-" in out or "_" in out:
                return out
            raw[i] ^= 0x01
    # Couldn't get a base64url char — return original.
    return s


def tamper_signature(token: str) -> str:
    """Flip the first byte of the signature segment so verify() must fail."""
    head, payload, sig = token.split(".")
    raw = bytearray(b64url_decode(sig))
    raw[0] ^= 0x01
    return f"{head}.{payload}.{b64url_encode(bytes(raw))}"


def b64urlify_signature(token: str) -> str:
    """Rewrite the signature segment so it contains base64url-only chars."""
    head, payload, sig = token.split(".")
    return f"{head}.{payload}.{std_b64url_mix(sig)}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--secret", required=True)
    p.add_argument("--role", default="")
    p.add_argument("--exp", type=int, default=None,
                   help="epoch seconds; default now+3600")
    p.add_argument("--alg", default="HS256", choices=SUPPORTED_ALGS)
    p.add_argument("--sub", default=None)
    p.add_argument("--email", default=None)
    p.add_argument("--tamper-sig", action="store_true",
                   help="Flip a byte in the signature before printing.")
    p.add_argument("--b64url-sig", action="store_true",
                   help="Rewrite the signature to use base64url chars (-, _).")
    p.add_argument("--no-exp", action="store_true",
                   help="Omit the exp claim entirely.")
    args, extra = p.parse_known_args()

    payload: dict = {}
    if args.role != "":
        payload["role"] = args.role
    if args.sub is not None:
        payload["sub"] = args.sub
    if args.email is not None:
        payload["email"] = args.email
    if not args.no_exp:
        payload["exp"] = args.exp if args.exp is not None else int(time.time()) + 3600

    for arg in extra:
        if not arg.startswith("--") or "=" not in arg:
            print(f"unexpected extra arg: {arg}", file=sys.stderr)
            return 2
        k, v = arg[2:].split("=", 1)
        payload[k] = v

    token = jwt.encode(payload, args.secret, algorithm=args.alg)
    if args.tamper_sig:
        token = tamper_signature(token)
    if args.b64url_sig:
        token = b64urlify_signature(token)

    sys.stdout.write(token)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
