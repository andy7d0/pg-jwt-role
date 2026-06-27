/*
 * pg_jwt_csv.h
 *
 * Small CSV tokeniser used by pg_jwt_role. Extracted from
 * pg_jwt_role.c so the main translation unit stays focused on the
 * security-critical verify-and-set-role flow.
 */
#ifndef PG_JWT_CSV_H
#define PG_JWT_CSV_H

/*
 * Maximum length (in bytes, including NUL) of a single comma-separated
 * name returned by pg_split_csv(). Matches the claim-name buffer size
 * used elsewhere in pg_jwt_role, keeping the interface self-contained.
 */
#define PG_JWT_MAX_CSV_NAME_LEN 64

int pg_split_csv(const char *csv,
                 char names[][PG_JWT_MAX_CSV_NAME_LEN], int max);

#endif /* PG_JWT_CSV_H */
