package pgutil

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxIdentLen is PostgreSQL's identifier length limit, in bytes (NAMEDATALEN
// minus one); a longer name is silently truncated by the server.
const MaxIdentLen = 63

var identPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// ErrInvalidIdent is returned for a name ValidIdent refuses.
var ErrInvalidIdent = errors.New("pgutil: invalid identifier")

// ValidIdent reports whether s is a lower-case identifier that needs no
// quoting: a letter or underscore, then letters, digits and underscores, at
// most MaxIdentLen bytes. Names for databases and roles made by tools are
// kept to this form, so they read the same quoted or not.
func ValidIdent(s string) error {
	if !identPattern.MatchString(s) || len(s) > MaxIdentLen {
		return fmt.Errorf("%w: %q: use lower-case letters, digits and underscores, starting with a letter or underscore, at most %d bytes", ErrInvalidIdent, s, MaxIdentLen)
	}
	return nil
}

// QuoteIdent quotes an identifier for SQL: "name", with any double quote
// doubled. It quotes any string; check names with ValidIdent first.
func QuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// QuoteLiteral quotes a string literal for SQL: 'text', with any single
// quote doubled. With standard_conforming_strings on, PostgreSQL's default,
// backslashes need no escaping.
func QuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
