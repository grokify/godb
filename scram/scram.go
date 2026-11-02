// Package scram makes SCRAM-SHA-256 password verifiers in the form
// PostgreSQL stores them (RFC 5802, RFC 7677). Setting a role's password
// to a verifier, as in ALTER ROLE r PASSWORD 'SCRAM-SHA-256$…', means the
// plain password never reaches the server, its logs or its statistics.
package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Prefix begins every verifier this package makes.
const Prefix = "SCRAM-SHA-256$"

// DefaultIterations is PostgreSQL's default (scram_iterations).
const DefaultIterations = 4096

// SaltLen is the salt length PostgreSQL uses, in bytes.
const SaltLen = 16

// Verifier returns the SCRAM-SHA-256 verifier of password with a random
// salt and DefaultIterations.
//
// The password must be printable ASCII. PostgreSQL normalizes other
// passwords with SASLprep before hashing, which this package does not do,
// so it refuses them rather than make a verifier that would not match.
// Generated passwords, such as hexadecimal ones, are always ASCII.
func Verifier(password string) (string, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("scram: salt: %w", err)
	}
	return VerifierWithSalt(password, salt, DefaultIterations)
}

// VerifierWithSalt returns the verifier of password with the given salt
// and iteration count, for tests and for reproducing a known verifier.
func VerifierWithSalt(password string, salt []byte, iterations int) (string, error) {
	if password == "" {
		return "", errors.New("scram: empty password")
	}
	for _, r := range password {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return "", errors.New("scram: the password must be printable ASCII")
		}
	}
	if len(salt) == 0 || iterations < 1 {
		return "", errors.New("scram: a salt and at least one iteration are required")
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("scram: %w", err)
	}
	clientKey := mac(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("%s%d:%s$%s:%s", Prefix, iterations, enc(salt), enc(storedKey[:]), enc(serverKey)), nil
}

// IsVerifier reports whether s has the form of a SCRAM-SHA-256 verifier,
// so a plain password is never mistaken for one.
func IsVerifier(s string) bool {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return false
	}
	params, keys, ok := strings.Cut(rest, "$")
	if !ok || strings.Count(params, ":") != 1 || strings.Count(keys, ":") != 1 {
		return false
	}
	return !strings.ContainsAny(s, " '\n")
}

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg)) // hash.Hash's Write never returns an error
	return h.Sum(nil)
}
