# pgutil: Technical Requirements

## Packages

| Package | Contents |
|---|---|
| `pgutil` | `ValidIdent`, `QuoteIdent`, `QuoteLiteral`; `DSN`, `ParseDSN`, `WithDatabase`, `WithHost`; `SQLState` and code helpers through an interface any driver's error satisfies |
| `scram` | `Verifier`, `VerifierWithSalt`, `IsVerifier`: PBKDF2-HMAC-SHA-256 with 4096 iterations and a 16-byte salt, as PostgreSQL stores them |
| `provision` | `Plan`, `Database`, `Role`; `Plan.Script` and `Plan.VerifySQL` |
| `gopg` | The earlier go-pg helpers, deprecated |

## Provisioning Script

- Starts with `\set ON_ERROR_STOP on`.
- Creates each role in a `DO` block when missing, then sets its login,
  `CREATEDB`, `CREATEROLE`, connection limit and password with `ALTER ROLE`.
  `SUPERUSER`, `REPLICATION` and `BYPASSRLS` are never named: a non-superuser
  may not change them, even to off.
- Grants each owner to the admin with `SET TRUE`, so the admin can create a
  database owned by it; creates the database with `\gexec` when missing.
- Revokes `PUBLIC`'s database privileges and grants `CONNECT` to the app
  role as the owner (`SET ROLE`), since only the grantor's grants can be
  revoked.
- Gives an owner with an app role `CREATEROLE` and `ADMIN OPTION` on it, so
  a migration can reset the app role's password (PostgreSQL 16 rules).
- Redacts verifiers on request.

## Verification

One query, a `UNION ALL` of checks, each returning its problem's text when
the server differs, including a scan of every database on the server a
planned role could connect to other than its own.

## Testing

Unit tests on the script and query text. An opt-in integration test runs
`initdb` and `pg_ctl`, creates a non-superuser admin, provisions two
applications, runs the script twice, and checks isolation, the password
reset a migration makes, and that drift is reported.
