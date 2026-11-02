// Package pgutil holds small PostgreSQL helpers that need no database
// driver: checking and quoting identifiers and literals, building and
// editing connection URLs, and reading a driver's error codes.
//
// Its subpackages provision databases and roles on a shared server
// (provision), hash passwords as SCRAM-SHA-256 verifiers so a plain
// password never reaches the server (scram), and check a provisioned
// server (provision's Verify).
package pgutil
