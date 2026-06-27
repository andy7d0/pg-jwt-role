EXTENSION = pg_jwt_role
EXTVERSION = 1.0

MODULE_big = pg_jwt_role
OBJS = pg_jwt_role.o pg_jwt_base64.o

DATA = pg_jwt_role--1.0.sql
PGFILEDESC = "pg_jwt_role - JWT-based role management"

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Link OpenSSL for JWT signature verification
SHLIB_LINK += -lssl -lcrypto

# Warnings: keep reasonable defaults; this is C, not C++
CFLAGS += -Wall -Wno-unused-parameter -std=c11