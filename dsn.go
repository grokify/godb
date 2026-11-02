package pgutil

import (
	"errors"
	"net"
	"net/url"
	"strconv"
)

// DSN is the parts of a postgres:// connection URL.
type DSN struct {
	User     string
	Password string
	Host     string
	// Port is 5432 when zero.
	Port     int
	Database string
	// SSLMode is the sslmode parameter, such as "require"; empty omits it.
	SSLMode string
}

// String encodes the DSN as a postgres:// URL, escaping the user,
// password and database.
func (d DSN) String() string {
	port := d.Port
	if port == 0 {
		port = 5432
	}
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(d.Host, strconv.Itoa(port)), Path: "/" + d.Database}
	switch {
	case d.User != "" && d.Password != "":
		u.User = url.UserPassword(d.User, d.Password)
	case d.User != "":
		u.User = url.User(d.User)
	}
	if d.SSLMode != "" {
		u.RawQuery = url.Values{"sslmode": {d.SSLMode}}.Encode()
	}
	return u.String()
}

// ParseDSN reads a postgres:// or postgresql:// URL.
func ParseDSN(s string) (DSN, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return DSN{}, errors.New("pgutil: not a postgres:// URL")
	}
	d := DSN{Host: u.Hostname(), Database: trimSlash(u.Path), SSLMode: u.Query().Get("sslmode")}
	if p := u.Port(); p != "" {
		if d.Port, err = strconv.Atoi(p); err != nil {
			return DSN{}, errors.New("pgutil: the URL's port is not a number")
		}
	}
	if u.User != nil {
		d.User = u.User.Username()
		d.Password, _ = u.User.Password() // reports only whether one is set
	}
	return d, nil
}

// WithDatabase returns the postgres:// URL dsn naming database db instead,
// keeping everything else, its other parameters included.
func WithDatabase(dsn, db string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", errors.New("pgutil: not a postgres:// URL")
	}
	u.Path = "/" + db
	return u.String(), nil
}

// WithHost returns the postgres:// URL dsn with its host and port replaced,
// as when a database moves to another server with the same roles.
func WithHost(dsn, host string, port int) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", errors.New("pgutil: not a postgres:// URL")
	}
	if port == 0 {
		port = 5432
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	return u.String(), nil
}

func trimSlash(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return p[1:]
	}
	return p
}
