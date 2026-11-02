# pgutil: Product Requirements

## Problem

Applications that share one PostgreSQL server each need their own
databases and roles, kept apart by grants, since a managed server's
`pg_hba.conf` cannot be edited. Each application's tooling tends to write
its own role setup: identifier checks, `CREATE ROLE`, grants and limits,
copied from project to project and drifting apart. Passwords often travel
to the server in plain text and can land in its logs.

## Goal

One small, tested Go module for PostgreSQL work that needs no driver:
provisioning a shared server's databases and roles, checking it, password
verifiers, identifiers and connection URLs.

## Users

- Operators provisioning a shared server from a deploy tool.
- Applications whose migrations create and maintain their own app role.

## Requirements

- Provision databases with an owner and an optional app role, connection
  limits and timeouts, and `CONNECT` limited to the database's own roles.
- Run as a managed server's admin user, which is not a superuser.
- Idempotent: running again changes nothing that already matches.
- Passwords reach the server only as SCRAM-SHA-256 verifiers.
- A check that reports every difference between the server and the plan.
- No database driver required; callers run the SQL with `psql`, pgx or
  `database/sql`.

## Non-Goals

- Schema migrations, query building or an ORM.
- Other databases: MySQL and others live in their own modules.
