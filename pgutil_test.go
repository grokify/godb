package pgutil

import (
	"errors"
	"fmt"
	"testing"
)

func TestIdentAndQuote(t *testing.T) {
	for _, ok := range []string{"shop", "shop_app", "_x1"} {
		if err := ValidIdent(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	long := make([]byte, MaxIdentLen+1)
	for i := range long {
		long[i] = 'a'
	}
	for _, bad := range []string{"", "Shop", "1shop", "shop-app", `x"y`, string(long)} {
		if err := ValidIdent(bad); !errors.Is(err, ErrInvalidIdent) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if got := QuoteIdent(`a"b`); got != `"a""b"` {
		t.Errorf("QuoteIdent = %s", got)
	}
	if got := QuoteLiteral(`it's`); got != `'it''s'` {
		t.Errorf("QuoteLiteral = %s", got)
	}
}

func TestDSN(t *testing.T) {
	d := DSN{User: "shop_app", Password: "p@ss/w:rd", Host: "db.example.com", Database: "shop", SSLMode: "require"}
	s := d.String()
	if s != "postgres://shop_app:p%40ss%2Fw%3Ard@db.example.com:5432/shop?sslmode=require" { //nolint:gosec // G101: a made-up password in a test URL
		t.Errorf("String = %s", s)
	}
	back, err := ParseDSN(s)
	if err != nil || back != d.withPort(5432) {
		t.Errorf("ParseDSN = %+v, %v", back, err)
	}
	moved, err := WithHost(s, "db2.example.com", 0)
	if err != nil || moved != "postgres://shop_app:p%40ss%2Fw%3Ard@db2.example.com:5432/shop?sslmode=require" { //nolint:gosec // G101: a made-up password in a test URL
		t.Errorf("WithHost = %s, %v", moved, err)
	}
	other, err := WithDatabase(s, "shop_auth")
	if err != nil || other != "postgres://shop_app:p%40ss%2Fw%3Ard@db.example.com:5432/shop_auth?sslmode=require" { //nolint:gosec // G101: a made-up password in a test URL
		t.Errorf("WithDatabase = %s, %v", other, err)
	}
	for _, f := range []func() error{
		func() error { _, err := ParseDSN("mysql://x"); return err },
		func() error { _, err := WithHost("http://x", "y", 1); return err },
		func() error { _, err := WithDatabase("::", "y"); return err },
	} {
		if f() == nil {
			t.Error("a non-postgres URL was accepted")
		}
	}
}

func (d DSN) withPort(p int) DSN { d.Port = p; return d }

type pgErr struct{ code string }

func (e pgErr) Error() string    { return "pg: " + e.code }
func (e pgErr) SQLState() string { return e.code }

func TestSQLState(t *testing.T) {
	err := fmt.Errorf("insert: %w", pgErr{CodeUniqueViolation})
	if !IsUniqueViolation(err) || IsInsufficientPrivilege(err) || SQLState(errors.New("x")) != "" {
		t.Error("SQLState helpers")
	}
}
