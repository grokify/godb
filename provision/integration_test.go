package provision

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grokify/pgutil/scram"
)

// server is a throwaway PostgreSQL server, started by initdb and pg_ctl,
// with an admin role that, like a managed server's, is not a superuser.
type server struct {
	bin, data, sock string
	port            int
}

// newServer needs PGUTIL_INTEGRATION=1, and PostgreSQL's programs in
// PGUTIL_PG_BIN or on PATH.
func newServer(t *testing.T) *server {
	t.Helper()
	if os.Getenv("PGUTIL_INTEGRATION") != "1" {
		t.Skip("set PGUTIL_INTEGRATION=1, and PGUTIL_PG_BIN to PostgreSQL's bin directory, to run against a real server")
	}
	bin := os.Getenv("PGUTIL_PG_BIN")
	if bin == "" {
		p, err := exec.LookPath("initdb")
		if err != nil {
			t.Skip("initdb not found; set PGUTIL_PG_BIN")
		}
		bin = filepath.Dir(p)
	}
	// A Unix socket's path is limited to about 100 bytes, so it goes in a
	// short directory of its own.
	sock, err := os.MkdirTemp("/tmp", "pgutil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(sock); err != nil {
			t.Errorf("removing %s: %v", sock, err)
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	s := &server{bin: bin, data: t.TempDir(), sock: sock, port: port}
	s.run(t, "initdb", "-D", s.data, "-U", "boot", "--auth=trust", "-E", "UTF8", "--locale=C")
	s.run(t, "pg_ctl", "-D", s.data, "-w", "-l", filepath.Join(s.data, "log"), "-o",
		fmt.Sprintf("-p %d -k %s -c listen_addresses=''", port, sock), "start")
	t.Cleanup(func() { s.run(t, "pg_ctl", "-D", s.data, "-w", "-m", "fast", "stop") })
	s.psql(t, "boot", "postgres", "CREATE ROLE admin LOGIN CREATEROLE CREATEDB; CREATE DATABASE fleet OWNER admin;")
	return s
}

func (s *server) run(t *testing.T, prog string, args ...string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(s.bin, prog), args...) //nolint:gosec // G204: PostgreSQL's own programs, from PGUTIL_PG_BIN or PATH
	// The server refuses to start on macOS without a valid locale.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", prog, err, out.String())
	}
}

// psql runs sql as user on db, failing the test on an error.
func (s *server) psql(t *testing.T, user, db, sql string) string {
	t.Helper()
	out, err := s.try(user, db, sql)
	if err != nil {
		t.Fatalf("psql as %s on %s: %v\n%s", user, db, err, out)
	}
	return out
}

// try runs sql as user on db and returns the output and the error.
func (s *server) try(user, db, sql string) (string, error) {
	cmd := exec.Command(filepath.Join(s.bin, "psql"), "-X", //nolint:gosec // G204: PostgreSQL's psql, from PGUTIL_PG_BIN or PATH "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
		"-h", s.sock, "-p", fmt.Sprint(s.port), "-U", user, "-d", db)
	cmd.Stdin = strings.NewReader(sql)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func verifier(t *testing.T) string {
	t.Helper()
	v, err := scram.Verifier(fmt.Sprintf("pw%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sitePlan(t *testing.T, prefix string) Plan {
	t.Helper()
	return Plan{Databases: []Database{
		{Name: prefix + "_auth", Owner: Role{Name: prefix + "_auth_owner", Verifier: verifier(t), ConnectionLimit: 10, StatementTimeout: "30s"}},
		{Name: prefix, Owner: Role{Name: prefix + "_owner", Verifier: verifier(t)},
			App: &Role{Name: prefix + "_app", Verifier: verifier(t), ConnectionLimit: 20, StatementTimeout: "30s", IdleInTransactionTimeout: "60s"}},
	}, Lockdown: []string{"fleet"}, Reachable: []string{"postgres", "template1"}}
}

func TestProvisionAgainstAServer(t *testing.T) {
	s := newServer(t)
	a, b := sitePlan(t, "alpha"), sitePlan(t, "beta")
	for _, p := range []Plan{a, b, a} { // a twice: the script is idempotent
		script, err := p.Script(ScriptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		s.psql(t, "admin", "fleet", script)
	}
	for _, p := range []Plan{a, b} {
		q, err := p.VerifySQL()
		if err != nil {
			t.Fatal(err)
		}
		// The server's own postgres and template1 are owned by the bootstrap
		// superuser here, as a managed server's are by its provider, so the
		// admin cannot lock them down: they are declared reachable.
		if out := strings.TrimSpace(s.psql(t, "admin", "fleet", q)); out != "" {
			t.Errorf("verify:\n%s", out)
		}
	}
	// The boundary: a role reaches its own database only.
	s.psql(t, "boot", "postgres", "ALTER ROLE alpha_app PASSWORD NULL; ALTER ROLE alpha_app WITH LOGIN;")
	if out, err := s.try("alpha_app", "beta", "SELECT 1"); err == nil || !strings.Contains(out, "permission denied") {
		t.Errorf("alpha_app reached beta: %v %s", err, out)
	}
	if out, err := s.try("alpha_app", "fleet", "SELECT 1"); err == nil {
		t.Errorf("alpha_app reached the admin's database: %s", out)
	}
	if out := s.psql(t, "alpha_app", "alpha", "SELECT current_user"); strings.TrimSpace(out) != "alpha_app" {
		t.Errorf("alpha_app on alpha: %q", out)
	}
	// A migration, as the owner, resets the app role's password.
	s.psql(t, "alpha_owner", "alpha", "ALTER ROLE alpha_app PASSWORD 'new'; CREATE TABLE t (id int);")
	// And verify notices drift: a limit changed by hand.
	s.psql(t, "admin", "fleet", "ALTER ROLE beta_app CONNECTION LIMIT 5;")
	q, err := b.VerifySQL()
	if err != nil {
		t.Fatal(err)
	}
	if out := s.psql(t, "admin", "fleet", q); !strings.Contains(out, "role beta_app's connection limit is not 20") {
		t.Errorf("verify missed a changed limit:\n%s", out)
	}
}
