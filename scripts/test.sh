#!/bin/bash
# scripts/test.sh — convenience wrapper that runs the pg_jwt_role test
# harness in Docker with the host user's UID/GID passed through to the
# container.
#
# Usage:
#   scripts/test.sh                # build + run the tests (IMPLEMENTED=1)
#   scripts/test.sh --no-build     # run without rebuilding
#   scripts/test.sh --rebuild      # force a clean rebuild
#   scripts/test.sh --stub         # pass PG_JWT_ROLE_IMPLEMENTED=0
#   scripts/test.sh --implemented  # pass PG_JWT_ROLE_IMPLEMENTED=1
#
# Why this wrapper exists:
#   docker compose supports `user: "${HOST_UID}:${HOST_GID}"` natively,
#   but the variables only resolve if they are exported in the *same*
#   shell that runs `docker compose`. Typing
#     HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run ...
#   every time is friction-prone, so this script does it once.
#
# Note: we don't reuse UID/GID directly — both are readonly bash builtins.

set -euo pipefail

cd "$(dirname "$0")/.."

BUILD_FLAGS=""
# Steps 3 & 4 (atomic C function + ProcessUtility hook) have landed in
# pg_jwt_role.c, so the default run now expects the success-path
# assertions. The flag is kept for backwards compatibility / future
# stub-only runs.
ENV_FLAGS=(PG_JWT_ROLE_IMPLEMENTED=1)

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)    BUILD_FLAGS="--no-build"; shift ;;
        --rebuild)     BUILD_FLAGS="--build --force-recreate --no-cache"; shift ;;
        --stub)        ENV_FLAGS=(PG_JWT_ROLE_IMPLEMENTED=0); shift ;;
        --implemented) ENV_FLAGS=(PG_JWT_ROLE_IMPLEMENTED=1); shift ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0 ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2 ;;
    esac
done

# Export the host user identity so docker compose's `${HOST_UID}` /
# `${HOST_GID}` substitution produces a matching in-container user.
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

echo ">>> running as host uid=${HOST_UID} gid=${HOST_GID}"
echo ">>> env: ${ENV_FLAGS[*]}"
echo

case "$BUILD_FLAGS" in
    --build*)
        docker compose build test
        ;;
esac

# Pass the env vars individually; "${ENV_FLAGS[@]}" can't be used here
# because `docker compose run` parses the first non-flag arg as the
# service name.
docker compose run --rm \
    -e "${ENV_FLAGS[0]}" \
    test
