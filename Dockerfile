# pg_jwt_role — Alpine + PostgreSQL 18 build & test container.
#
# Multi-stage:
#   1) builder : compiles pg_jwt_role.so with PGXS + openssl-dev
#   2) runtime : minimal postgres:18-alpine with the .so + SQL installed
#                and a self-contained test harness that spins up a temp
#                cluster and runs psql-based smoke tests.
#
# Privilege model
# ---------------
# The container runs as a single unprivileged user whose UID/GID match
# the host's current user (passed via --build-arg, defaults to 1000:1000).
# No setuid gymnastics inside the container — no setpriv, su-exec, gosu,
# or /etc/passwd mutation. Files written under /tmp land on tmpfs and
# are owned by the host user, just as if the host had run them directly.
#
# If the host UID already exists in the image (e.g. the stock `postgres`
# user is UID 70) the build re-uses that account under a matching name;
# otherwise it creates a brand-new `runner` account with adduser.
#
# See plans/plan.md §10 for the build layout and §11 for the test plan.

# Build-time identity. Override on the docker compose / build command:
#   docker compose build --build-arg HOST_UID=$(id -u) --build-arg HOST_GID=$(id -g)
ARG HOST_UID=1000
ARG HOST_GID=1000
ARG HOST_USER=runner

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM postgres:18-alpine AS builder

ARG HOST_UID
ARG HOST_GID
ARG HOST_USER

# PGXS + PostgreSQL headers are already present in postgres:18-alpine, but
# we still need a C toolchain and the OpenSSL development headers so the
# extension can link against libssl/libcrypto.
#
# PostgreSQL 18 on Alpine is built with ThinLTO and the PGXS Makefile
# hardcodes CLANG=clang-21 / LLVM=21 — install those exact major versions
# rather than the generic `clang` / `llvm` packages.
RUN apk add --no-cache \
        build-base \
        clang21 \
        llvm21 \
        openssl-dev \
        pkgconf \
        postgresql-dev \
        python3 \
        py3-pip \
        git \
        bash \
        coreutils \
        make

# Build the extension. PG_CONFIG is provided by the postgres:18-alpine image.
WORKDIR /usr/src/pg_jwt_role
COPY Makefile                 ./Makefile
COPY pg_jwt_role.control      ./pg_jwt_role.control
COPY pg_jwt_role--1.0.sql     ./pg_jwt_role--1.0.sql
COPY pg_jwt_role.c            ./pg_jwt_role.c
COPY pg_jwt_base64.c          ./pg_jwt_base64.c
COPY pg_jwt_json.c            ./pg_jwt_json.c
COPY pg_jwt_json.h            ./pg_jwt_json.h
COPY pg_jwt_csv.c             ./pg_jwt_csv.c
COPY pg_jwt_csv.h             ./pg_jwt_csv.h
COPY plans                    ./plans

# pg_jwt_role.h is planned (see plans/plan.md §4) but not yet present.
# Create an empty placeholder so future `COPY pg_jwt_role.h` over it works.
RUN : > pg_jwt_role.h

# Sanity build + install into the image's PG install dirs so we can copy
# them out cleanly in stage 2.
RUN make \
    && make install \
    && ls -la "$(pg_config --pkglibdir)/pg_jwt_role.so" \
    && ls -la "$(pg_config --sharedir)/extension/pg_jwt_role"*

# ---------------------------------------------------------------------------
# Stage 2 — runtime / test runner
# ---------------------------------------------------------------------------
FROM postgres:18-alpine

ARG HOST_UID=1000
ARG HOST_GID=1000
ARG HOST_USER=runner

# Runtime packages: python + PyJWT for JWT generation, bash for the
# entrypoint, tini for signal forwarding.
RUN apk add --no-cache \
        python3 \
        py3-pip \
        openssl \
        bash \
        coreutils \
        tini

# Install pyjwt for the JWT helper used by the SQL tests.
RUN pip3 install --no-cache-dir --break-system-packages pyjwt==2.9.0 \
    || pip3 install --no-cache-dir pyjwt==2.9.0

# Bring the compiled extension + SQL/control files into the image.
COPY --from=builder /usr/local/lib/postgresql/pg_jwt_role.so \
                    /usr/local/lib/postgresql/pg_jwt_role.so
COPY --from=builder /usr/local/share/postgresql/extension/pg_jwt_role.control \
                    /usr/local/share/postgresql/extension/pg_jwt_role.control
COPY --from=builder /usr/local/share/postgresql/extension/pg_jwt_role--1.0.sql \
                    /usr/local/share/postgresql/extension/pg_jwt_role--1.0.sql

# Tests and helpers.
COPY test/ /test/
RUN chmod -R a+rxX /test

# Ensure a non-root account with HOST_UID/GID exists inside the image,
# so `docker run --user $HOST_UID:$HOST_GID` works (initdb performs a
# getpwnam() on the effective UID).
#
# If a user with the desired UID already exists (e.g. the image's
# stock `postgres` user is UID 70 and we asked for 70), we leave it
# alone. Otherwise we create a new account named $HOST_USER.
RUN set -eux; \
    if ! getent passwd "${HOST_UID}" >/dev/null; then \
        addgroup -g "${HOST_GID}" -S "${HOST_USER}"; \
        adduser  -u "${HOST_UID}" -G "${HOST_USER}" -D -s /bin/bash "${HOST_USER}"; \
    fi; \
    # Make sure /test stays readable to whoever ends up running it. \
    chmod -R a+rxX /test

# Default to running as the host-matched user. Override at run-time
# with `docker run --user …` if you need a different identity.
USER ${HOST_UID}:${HOST_GID}

# tini forwards signals; the test harness runs as whatever user
# compose handed us.
ENTRYPOINT ["/sbin/tini", "--", "/test/run_tests.sh"]
