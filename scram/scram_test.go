package scram

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The expected verifier was computed apart from this package, with
// Python's hashlib.pbkdf2_hmac and hmac, for RFC 7677's password and salt.
func TestVerifierWithSalt(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifierWithSalt("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	if got != want {
		t.Errorf("verifier\n got %s\nwant %s", got, want)
	}
}

func TestVerifier(t *testing.T) {
	a, err := Verifier("0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Verifier("0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !IsVerifier(a) || !strings.HasPrefix(a, "SCRAM-SHA-256$4096:") {
		t.Errorf("two verifiers of one password should differ by salt: %s %s", a, b)
	}
	for _, bad := range []string{"", "pässword", "tab\there"} {
		if _, err := Verifier(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	for _, s := range []string{"secret", "SCRAM-SHA-256$4096:abc", "md5abc", "SCRAM-SHA-256$1:a$b:c'"} {
		if IsVerifier(s) {
			t.Errorf("%q passed as a verifier", s)
		}
	}
}
