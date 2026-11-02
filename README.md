# pgutil

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/grokify/pgutil/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/grokify/pgutil/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/grokify/pgutil/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/grokify/pgutil/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/grokify/pgutil/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/grokify/pgutil/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/pgutil
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/pgutil
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/pgutil/blob/main/LICENSE

PostgreSQL helpers for Go that need no database driver: provisioning
databases and roles on a server several applications share, SCRAM-SHA-256
password verifiers, identifiers and connection URLs.

```bash
go get github.com/grokify/pgutil
```

| Package | What it does |
|---|---|
| `pgutil` | Check and quote identifiers and literals; build, parse and edit `postgres://` URLs; read a driver's SQLSTATE codes |
| `pgutil/scram` | SCRAM-SHA-256 verifiers, so a password set with `ALTER ROLE … PASSWORD` never reaches the server in plain text |
| `pgutil/provision` | An idempotent `psql` script that provisions databases, owner and app roles, connection limits and timeouts, and keeps each application out of the others' databases; and a query that checks the server against the plan |
| `pgutil/gopg` | Earlier helpers built on go-pg. Deprecated |

## Provision a Shared Server

Each database gets an owner role, which owns it and runs migrations, and
optionally an app role, which the running application connects as.
`CONNECT` is revoked from `PUBLIC`, so each role reaches only its own
database. On a managed server, where `pg_hba.conf` cannot be edited, these
grants are the boundary between applications.

```go
import (
    "github.com/grokify/pgutil/provision"
    "github.com/grokify/pgutil/scram"
)

ownerV, err := scram.Verifier(ownerPassword)  // the plain password stays here
appV, err := scram.Verifier(appPassword)

plan := provision.Plan{
    Databases: []provision.Database{{
        Name:  "shop",
        Owner: provision.Role{Name: "shop_owner", Verifier: ownerV},
        App: &provision.Role{Name: "shop_app", Verifier: appV,
            ConnectionLimit: 20, StatementTimeout: "30s", IdleInTransactionTimeout: "60s"},
    }},
    Lockdown:  []string{"admin_db"},              // other databases no role should reach
    Reachable: []string{"postgres", "template1"}, // owned by a managed server's provider: CONNECT stays, no data
}

script, err := plan.Script(provision.ScriptOptions{})  // run with psql as the server's admin
check, err := plan.VerifySQL()                         // one row per problem; none means it matches
```

The script is idempotent, stops at the first error, and runs as a managed
server's admin user, which is not a superuser: it never sets `SUPERUSER`,
`REPLICATION` or `BYPASSRLS`, and `VerifySQL` checks them instead. It needs
PostgreSQL 16 or later. With `ScriptOptions{Redact: true}` it shows the
plan without the verifiers.

## Testing

Unit tests need nothing. The integration test starts a throwaway server
with PostgreSQL's own programs and provisions it as a non-superuser admin:

```bash
PGUTIL_INTEGRATION=1 PGUTIL_PG_BIN=/usr/local/opt/postgresql@17/bin go test ./...
```

## Changes

See [CHANGELOG.md](CHANGELOG.md) and the [release notes](docs/releases/).
Upgrading from `github.com/grokify/godb`: [v0.2.0](docs/releases/v0.2.0.md).

## License

MIT
