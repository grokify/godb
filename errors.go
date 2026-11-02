package pgutil

import "errors"

// SQLSTATE codes the helpers below test for.
const (
	CodeUniqueViolation       = "23505"
	CodeForeignKeyViolation   = "23503"
	CodeDuplicateDatabase     = "42P04"
	CodeDuplicateObject       = "42710"
	CodeInsufficientPrivilege = "42501"
)

// sqlStater is an error carrying a SQLSTATE code, as pgx's *pgconn.PgError
// and lib/pq's *pq.Error do.
type sqlStater interface{ SQLState() string }

// SQLState returns err's SQLSTATE code, from any error in its chain that
// has one, or "" when none does. It needs no driver import.
func SQLState(err error) string {
	var s sqlStater
	if errors.As(err, &s) {
		return s.SQLState()
	}
	return ""
}

// IsUniqueViolation reports whether err is a unique constraint violation.
func IsUniqueViolation(err error) bool { return SQLState(err) == CodeUniqueViolation }

// IsInsufficientPrivilege reports whether err is a permission refusal.
func IsInsufficientPrivilege(err error) bool { return SQLState(err) == CodeInsufficientPrivilege }
