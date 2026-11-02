// Package provision provisions databases and their roles on a PostgreSQL
// server that several applications share, and checks the result.
//
// Each database has an owner role, which owns it and runs migrations, and
// optionally an app role, which the running application connects as. CONNECT
// is revoked from PUBLIC, so a role reaches only the databases granted to it:
// on a managed server, where pg_hba.conf cannot be edited, these grants are
// the boundary between applications.
//
// Plan.Script writes an idempotent psql script that creates what is missing
// and resets what exists; Plan.VerifySQL writes a query that returns one row
// per problem, so no rows means the server matches the plan.
//
// Both are written for a managed server's admin user, which is not a
// superuser: the script never sets SUPERUSER, REPLICATION or BYPASSRLS,
// which only a superuser may change, and VerifySQL checks them instead. It
// needs PostgreSQL 16 or later, for GRANT … WITH INHERIT, SET options.
package provision

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/grokify/pgutil"
	"github.com/grokify/pgutil/scram"
)

// Role is a login role.
type Role struct {
	// Name is the role's name; it passes pgutil.ValidIdent.
	Name string
	// Verifier is the role's password as a SCRAM-SHA-256 verifier (see
	// package scram), so the plain password never reaches the server.
	// Required.
	Verifier string
	// ConnectionLimit is the role's CONNECTION LIMIT; 0 means no limit.
	ConnectionLimit int
	// StatementTimeout and IdleInTransactionTimeout, such as "30s", are
	// set on the role; empty leaves each as it is.
	StatementTimeout         string
	IdleInTransactionTimeout string
}

// Database is a database and its roles.
type Database struct {
	// Name is the database's name; it passes pgutil.ValidIdent.
	Name string
	// Owner owns the database and its schema, and runs migrations. With an
	// App role, it is given CREATEROLE and ADMIN OPTION on the app role, so
	// a migration can reset the app role's password.
	Owner Role
	// App, when set, is the role the running application connects as. It
	// owns nothing, cannot create roles or databases, and gets CONNECT;
	// the application's migration grants it rows in the owner's tables.
	App *Role
}

// Plan is the databases to provision on one server.
type Plan struct {
	Databases []Database
	// Lockdown are other databases on the server, such as postgres,
	// template1 or the admin user's database, whose CONNECT is revoked from
	// PUBLIC, so the plan's roles cannot reach them either. Revoking needs
	// the admin to own them; one it does not own is left as it is, and
	// VerifySQL reports any the roles can still reach.
	Lockdown []string
	// Reachable are databases any role may connect to, which VerifySQL
	// does not report: on a managed server, template1 is owned by the
	// provider and its PUBLIC CONNECT cannot be revoked. Connecting to it
	// reaches no application's data.
	Reachable []string
}

var durationPattern = regexp.MustCompile(`^[0-9]+(us|ms|s|min|h|d)?$`)

// Validate checks names, verifiers and settings, returning every problem.
func (p Plan) Validate() error {
	var errs []error
	if len(p.Databases) == 0 {
		errs = append(errs, errors.New("provision: the plan has no databases"))
	}
	seen := map[string]bool{}
	name := func(kind, n string) {
		if err := pgutil.ValidIdent(n); err != nil {
			errs = append(errs, fmt.Errorf("provision: %s: %w", kind, err))
		}
		if seen[n] {
			errs = append(errs, fmt.Errorf("provision: %s %s appears twice", kind, n))
		}
		seen[n] = true
	}
	for _, d := range p.Databases {
		name("database", d.Name)
		for _, r := range d.roles() {
			name("role", r.Name)
			if !scram.IsVerifier(r.Verifier) {
				errs = append(errs, fmt.Errorf("provision: role %s: the password must be a SCRAM-SHA-256 verifier, never plain", r.Name))
			}
			if r.ConnectionLimit < 0 {
				errs = append(errs, fmt.Errorf("provision: role %s: a connection limit is 0 (none) or more", r.Name))
			}
			for _, t := range []string{r.StatementTimeout, r.IdleInTransactionTimeout} {
				if t != "" && !durationPattern.MatchString(t) {
					errs = append(errs, fmt.Errorf("provision: role %s: timeout %q is not a duration such as 30s", r.Name, t))
				}
			}
		}
	}
	for _, l := range p.Lockdown {
		if err := pgutil.ValidIdent(l); err != nil {
			errs = append(errs, fmt.Errorf("provision: lockdown database: %w", err))
		}
		if slices.ContainsFunc(p.Databases, func(d Database) bool { return d.Name == l }) {
			errs = append(errs, fmt.Errorf("provision: %s is both provisioned and locked down", l))
		}
	}
	for _, r := range p.Reachable {
		if err := pgutil.ValidIdent(r); err != nil {
			errs = append(errs, fmt.Errorf("provision: reachable database: %w", err))
		}
		if slices.Contains(p.Lockdown, r) || slices.ContainsFunc(p.Databases, func(d Database) bool { return d.Name == r }) {
			errs = append(errs, fmt.Errorf("provision: %s cannot be reachable and also provisioned or locked down", r))
		}
	}
	return errors.Join(errs...)
}

func (d Database) roles() []Role {
	if d.App == nil {
		return []Role{d.Owner}
	}
	return []Role{d.Owner, *d.App}
}

// RedactedVerifier replaces each verifier in a script written with
// ScriptOptions.Redact.
const RedactedVerifier = "SCRAM-SHA-256$<redacted>"

// ScriptOptions configure Script.
type ScriptOptions struct {
	// Redact writes RedactedVerifier in place of each password, for a
	// script shown to a person rather than run.
	Redact bool
}

// Script writes the plan as a psql script, which stops at the first error.
// It is idempotent: run again, it creates nothing new and resets each
// role's password, limit and timeouts, and each database's owner and
// grants, to the plan's.
func (p Plan) Script(o ScriptOptions) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	q, lit := pgutil.QuoteIdent, pgutil.QuoteLiteral
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	line(`\set ON_ERROR_STOP on`)
	line(`-- Written by github.com/grokify/pgutil/provision. Idempotent; run as the`)
	line(`-- server's admin user. Needs PostgreSQL 16 or later.`)
	role := func(r Role, createRole bool) {
		line(`DO $pgutil$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = %s) THEN CREATE ROLE %s LOGIN; END IF; END $pgutil$;`, lit(r.Name), q(r.Name))
		cr := "NOCREATEROLE"
		if createRole {
			cr = "CREATEROLE"
		}
		limit := r.ConnectionLimit
		if limit == 0 {
			limit = -1
		}
		verifier := r.Verifier
		if o.Redact {
			verifier = RedactedVerifier
		}
		line(`ALTER ROLE %s LOGIN NOCREATEDB %s CONNECTION LIMIT %d PASSWORD %s;`, q(r.Name), cr, limit, lit(verifier))
		if r.StatementTimeout != "" {
			line(`ALTER ROLE %s SET statement_timeout = %s;`, q(r.Name), lit(r.StatementTimeout))
		}
		if r.IdleInTransactionTimeout != "" {
			line(`ALTER ROLE %s SET idle_in_transaction_session_timeout = %s;`, q(r.Name), lit(r.IdleInTransactionTimeout))
		}
	}
	for _, d := range p.Databases {
		line("")
		line(`-- %s`, d.Name)
		role(d.Owner, d.App != nil)
		// The admin may give a database to a role only if it can SET ROLE to it.
		line(`GRANT %s TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;`, q(d.Owner.Name))
		if d.App != nil {
			role(*d.App, false)
			// The owner's migration resets the app role's password.
			line(`GRANT %s TO %s WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;`, q(d.App.Name), q(d.Owner.Name))
		}
		line(`SELECT %s WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = %s) \gexec`,
			lit(fmt.Sprintf("CREATE DATABASE %s OWNER %s", q(d.Name), q(d.Owner.Name))), lit(d.Name))
		line(`ALTER DATABASE %s OWNER TO %s;`, q(d.Name), q(d.Owner.Name))
		// Only the owner's grants can be revoked, PUBLIC's default included,
		// so the admin acts as the owner for them.
		line(`SET ROLE %s;`, q(d.Owner.Name))
		line(`REVOKE ALL ON DATABASE %s FROM PUBLIC;`, q(d.Name))
		if d.App != nil {
			line(`GRANT CONNECT ON DATABASE %s TO %s;`, q(d.Name), q(d.App.Name))
		}
		line(`RESET ROLE;`)
	}
	if len(p.Lockdown) > 0 {
		line("")
		line(`-- Other databases: no role reaches them by default.`)
		for _, l := range p.Lockdown {
			line(`REVOKE CONNECT, TEMPORARY ON DATABASE %s FROM PUBLIC;`, q(l))
		}
	}
	return b.String(), nil
}

// VerifySQL writes a query returning one text row per way the server
// differs from the plan, and no rows when it matches. It checks that each
// database exists and is owned by its owner; that each role exists, can
// log in, and is not a superuser and cannot replicate or bypass row-level
// security; that app roles cannot create roles or databases; each role's
// connection limit and timeouts; that PUBLIC cannot connect to a planned
// database; and that no planned role can connect to any database on the
// server but its own, other than the plan's Reachable ones.
func (p Plan) VerifySQL() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	lit := pgutil.QuoteLiteral
	var parts []string
	check := func(problem, cond string) {
		parts = append(parts, fmt.Sprintf("SELECT %s WHERE NOT (%s)", lit(problem), cond))
	}
	var pairs []string
	for _, d := range p.Databases {
		db := lit(d.Name)
		check("database "+d.Name+" does not exist", "EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = "+db+")")
		check("database "+d.Name+" is not owned by "+d.Owner.Name,
			"NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = "+db+") OR (SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname = "+db+") = "+lit(d.Owner.Name))
		check("PUBLIC can connect to database "+d.Name,
			"NOT EXISTS (SELECT FROM pg_catalog.pg_database x, pg_catalog.aclexplode(COALESCE(x.datacl, pg_catalog.acldefault('d', x.datdba))) a WHERE x.datname = "+db+" AND a.grantee = 0 AND a.privilege_type = 'CONNECT')")
		for i, r := range d.roles() {
			app := d.App != nil && i == 1
			n := lit(r.Name)
			cond := "rolcanlogin AND NOT rolsuper AND NOT rolreplication AND NOT rolbypassrls AND NOT rolcreatedb"
			if app {
				cond += " AND NOT rolcreaterole"
			}
			check("role "+r.Name+" is missing, cannot log in, or has a privilege it must not",
				"EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = "+n+" AND "+cond+")")
			limit := r.ConnectionLimit
			if limit == 0 {
				limit = -1
			}
			check(fmt.Sprintf("role %s's connection limit is not %d", r.Name, limit),
				fmt.Sprintf("NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = %s) OR (SELECT rolconnlimit FROM pg_catalog.pg_roles WHERE rolname = %s) = %d", n, n, limit))
			for _, sv := range [][2]string{{"statement_timeout", r.StatementTimeout}, {"idle_in_transaction_session_timeout", r.IdleInTransactionTimeout}} {
				setting, value := sv[0], sv[1]
				if value == "" {
					continue
				}
				check(fmt.Sprintf("role %s's %s is not %s", r.Name, setting, value),
					"EXISTS (SELECT FROM pg_catalog.pg_db_role_setting s JOIN pg_catalog.pg_roles x ON x.oid = s.setrole WHERE x.rolname = "+n+" AND s.setdatabase = 0 AND "+lit(setting+"="+value)+" = ANY (s.setconfig))")
			}
			check("role "+r.Name+" cannot connect to database "+d.Name,
				"NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = "+n+") OR NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = "+db+") OR pg_catalog.has_database_privilege("+n+", "+db+", 'CONNECT')")
			pairs = append(pairs, "("+n+", "+db+")")
		}
	}
	// Every database on the server a role could connect to, but its own.
	reach := "SELECT pg_catalog.format('role %s can connect to database %s, which is not its own', w.role, d.datname) " +
		"FROM (VALUES " + strings.Join(pairs, ", ") + ") AS w(role, db) " +
		"JOIN pg_catalog.pg_roles r ON r.rolname = w.role " +
		"CROSS JOIN pg_catalog.pg_database d " +
		"WHERE d.datallowconn AND d.datname <> w.db AND pg_catalog.has_database_privilege(r.oid, d.oid, 'CONNECT')"
	if len(p.Reachable) > 0 {
		quoted := make([]string, len(p.Reachable))
		for i, r := range p.Reachable {
			quoted[i] = lit(r)
		}
		reach += " AND d.datname NOT IN (" + strings.Join(quoted, ", ") + ")"
	}
	parts = append(parts, reach)
	return strings.Join(parts, "\nUNION ALL\n") + ";\n", nil
}
