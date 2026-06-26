#!/usr/bin/env python3
"""
test_jwt_helper.py — generate HS256 JWTs for pg_jwt_role regression tests.

Usage:
    test_jwt_helper.py --secret KEY --role ROLE [--exp EPOCH]
                       [--sub VAL] [--email VAL] [--alg ALG]
                       [--tamper-sig]

    --exp defaults to current epoch + 3600 seconds.
    --sub / --email / --* all become extra JWT claims (string values).
    --tamper-sig flips a byte in the signature segment so verification fails
       while keeping the payload well-formed.

Output is the raw compact JWS to stdout. Errors go to stderr with exit 2.
"""
import argparse
import base64
import json
import sys
import time

import jwt  # PyJWT


def b64url_decode(data: str) -> bytes:
    """PyJWT already handles base64url; this is only used for tamper mode."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def tamper_signature(token: str) -> str:
    """Flip the first byte of the signature segment so verify() must fail."""
    head, payload, sig = token.split(".")
    raw = bytearray(b64url_decode(sig))
    raw[0] ^= 0x01
    return f"{head}.{payload}.{b64url_encode(bytes(raw))}"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--secret", required=True)
    p.add_argument("--role", default="")
    p.add_argument("--exp", type=int, default=None,
                   help="epoch seconds; default now+3600")
    p.add_argument("--alg", default="HS256")
    # Dynamic extra claims. We pre-declare a handful so help text is useful,
    # but anything of the form --foo=bar becomes payload['foo'] = 'bar'.
    p.add_argument("--sub", default=None)
    p.add_argument("--email", default=None)
    p.add_argument("--tamper-sig", action="store_true",
                   help="Flip a byte in the signature before printing.")
    p.add_argument("--no-exp", action="store_true",
                   help="Omit the exp claim entirely (tests that want it absent).")
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

    sys.stdout.write(token)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
