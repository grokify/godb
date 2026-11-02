package provision

import (
	"strings"
	"testing"

	"github.com/grokify/pgutil/scram"
)

func plan(t *testing.T) Plan {
	t.Helper()
	v, err := scram.Verifier("secret")
	if err != nil {
		t.Fatal(err)
	}
	return Plan{
		Databases: []Database{
			{Name: "shop_auth", Owner: Role{Name: "shop_auth_owner", Verifier: v, ConnectionLimit: 10}},
			{Name: "shop", Owner: Role{Name: "shop_owner", Verifier: v},
				App: &Role{Name: "shop_app", Verifier: v, ConnectionLimit: 20, StatementTimeout: "30s", IdleInTransactionTimeout: "60s"}},
		},
		Lockdown: []string{"postgres"},
	}
}

func TestScript(t *testing.T) {
	p := plan(t)
	s, err := p.Script(ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`\set ON_ERROR_STOP on`,
		`CREATE ROLE "shop_app" LOGIN`,
		`ALTER ROLE "shop_app" LOGIN NOCREATEDB NOCREATEROLE CONNECTION LIMIT 20 PASSWORD 'SCRAM-SHA-256$4096:`,
		`ALTER ROLE "shop_owner" LOGIN NOCREATEDB CREATEROLE CONNECTION LIMIT -1 PASSWORD`,
		`ALTER ROLE "shop_auth_owner" LOGIN NOCREATEDB NOCREATEROLE CONNECTION LIMIT 10 PASSWORD`,
		`ALTER ROLE "shop_app" SET statement_timeout = '30s';`,
		`ALTER ROLE "shop_app" SET idle_in_transaction_session_timeout = '60s';`,
		`GRANT "shop_app" TO "shop_owner" WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;`,
		`SELECT 'CREATE DATABASE "shop" OWNER "shop_owner"' WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = 'shop') \gexec`,
		"SET ROLE \"shop_owner\";\nREVOKE ALL ON DATABASE \"shop\" FROM PUBLIC;\nGRANT CONNECT ON DATABASE \"shop\" TO \"shop_app\";\nRESET ROLE;",
		`REVOKE CONNECT, TEMPORARY ON DATABASE "postgres" FROM PUBLIC;`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	for _, never := range []string{"SUPERUSER", "BYPASSRLS", "REPLICATION", "secret"} {
		if strings.Contains(s, never) {
			t.Errorf("the script contains %q", never)
		}
	}
	red, err := p.Script(ScriptOptions{Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(red, "SCRAM-SHA-256$4096:") || strings.Count(red, RedactedVerifier) != 3 {
		t.Errorf("redaction left a verifier:\n%s", red)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(*Plan){
		"no databases":       func(p *Plan) { p.Databases = nil },
		"plain password":     func(p *Plan) { p.Databases[0].Owner.Verifier = "secret" },
		"bad name":           func(p *Plan) { p.Databases[0].Name = "Shop-DB" },
		"duplicate role":     func(p *Plan) { p.Databases[1].App.Name = "shop_owner" },
		"bad timeout":        func(p *Plan) { p.Databases[1].App.StatementTimeout = "30 seconds" },
		"negative limit":     func(p *Plan) { p.Databases[1].App.ConnectionLimit = -2 },
		"locked and planned": func(p *Plan) { p.Lockdown = []string{"shop"} },
	}
	for name, change := range cases {
		p := plan(t)
		change(&p)
		if _, err := p.Script(ScriptOptions{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := p.VerifySQL(); err == nil {
			t.Errorf("%s: VerifySQL accepted", name)
		}
	}
}

func TestVerifySQL(t *testing.T) {
	p := plan(t)
	a, err := p.VerifySQL()
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.VerifySQL()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("VerifySQL is not deterministic")
	}
	for _, want := range []string{
		"PUBLIC can connect to database shop",
		// In SQL literals, so each apostrophe is doubled.
		"role shop_app''s connection limit is not 20",
		"role shop_owner''s connection limit is not -1",
		"role shop_app''s statement_timeout is not 30s",
		"AND NOT rolcreaterole",
		"can connect to database %s, which is not its own",
		"('shop_app', 'shop')",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("VerifySQL lacks %q", want)
		}
	}
	if strings.Contains(a, "SCRAM") {
		t.Error("VerifySQL contains a verifier")
	}
}
