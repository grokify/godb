# pgutil: Roadmap

Phase status is derived from its items.

## Phase 1: Shared Server Provisioning

- [x] `RMI-PGUTIL-001` Module path `github.com/grokify/pgutil`; go-pg helpers moved to the deprecated `gopg` package
- [x] `RMI-PGUTIL-002` Identifiers, literals, `postgres://` URLs and SQLSTATE helpers, with no driver dependency
- [x] `RMI-PGUTIL-003` SCRAM-SHA-256 verifiers
- [x] `RMI-PGUTIL-004` Provisioning script and verification query for databases, owner and app roles, limits, timeouts and isolation, run as a non-superuser admin
- [x] `RMI-PGUTIL-005` Integration test against a throwaway server
- [x] `RMI-PGUTIL-006` Release v0.2.0

## Phase 2: Application Migrations

- [ ] `RMI-PGUTIL-007` App-role helpers for migrations: ensure the database and the app role, refuse a superuser or `BYPASSRLS` role, and grant the app role rows in the owner's tables
- [ ] `RMI-PGUTIL-008` Guide to replacing an application's own role setup with the helpers
