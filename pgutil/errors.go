package pgutil

import "strings"

const DuplicateKeyErrorPrefix = "ERROR #23505 duplicate key value violates unique constraint"

func ErrIsDuplicateKey(err error) bool {
	return strings.Index(err.Error(), DuplicateKeyErrorPrefix) == 0
}

func NilifyErrDuplicateKey(err error) error {
	if err != nil && ErrIsDuplicateKey(err) {
		return nil
	}
	return err
}
