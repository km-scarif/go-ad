// Package ad is a small Active Directory client: browse the OU tree, search for
// objects, and create or edit users and organizational units.
//
// It wraps github.com/go-ldap/ldap/v3 with the AD-specific details that are
// easy to get wrong on the first attempt — the unicodePwd encoding, the
// userAccountControl bit field, the interaction between server-side size limits
// and paged searches, and escaping values that end up inside DNs and filters.
//
// Nothing here logs or reads the environment. Build a Config, hand it to New,
// and handle the returned errors however your service already does.
package ad

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config describes which directory to talk to and as whom. There are no
// defaults that point at a host: every field that names a target has to be
// supplied, so a misconfigured service fails at New rather than quietly
// connecting somewhere unintended.
type Config struct {
	// URL is the directory to connect to, e.g. "ldaps://dc1.example.com:636".
	//
	// Reads work fine over plain ldap://, and plenty of consumers only read.
	// Password writes do not: Active Directory refuses a write to unicodePwd on
	// an unencrypted connection, so those return ErrTLSRequired up front rather
	// than failing at the server as an opaque "unwilling to perform".
	URL string

	// BindDN and BindPassword are the service account, e.g.
	// "CN=directory-svc,OU=Service Accounts,DC=example,DC=com".
	//
	// Creating and modifying accounts needs more than a read-only account has;
	// on a real domain controller this wants delegated rights on the target
	// container (create/delete child objects, plus Reset Password) rather than
	// domain admin.
	BindDN       string
	BindPassword string

	// BaseDN is the search root for every read, normally the domain root
	// ("DC=example,DC=com").
	//
	// This should be the root and not a container, because accounts live all
	// over the OU tree. Scoping this to the container new users are created in
	// is a common mistake that hides most of the directory.
	//
	// Root-scoped searches also return referral continuation URLs for the
	// Configuration and DnsZones partitions. go-ldap collects those separately
	// and does not chase them, so they are ignored rather than being errors.
	BaseDN string

	// UsersDN is the container CreateUser puts an account in when the request
	// does not name one. Active Directory has no notion of a default, so a DN
	// has to be picked; "CN=Users,<BaseDN>" is the conventional choice.
	// Optional — without it, CreateUser requires an explicit ParentDN.
	UsersDN string

	// UPNSuffix builds userPrincipalName as <sAMAccountName>@<UPNSuffix>,
	// e.g. "example.com". Optional; without it userPrincipalName is not set.
	UPNSuffix string

	// TLSSkipVerify disables certificate verification. Needed against a
	// development directory with a self-signed certificate; leave it false
	// anywhere the certificate is real.
	TLSSkipVerify bool

	// Timeout bounds both the dial and each subsequent operation on the
	// connection. Zero means DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout is used when Config.Timeout is zero.
const DefaultTimeout = 10 * time.Second

// Client is safe for concurrent use. It holds no connection: each call dials,
// binds, does its work and closes.
//
// Binds are cheap on a LAN and this is built for interactive, low-rate traffic,
// so a pool would buy little and would add stale-connection handling to every
// operation.
//
// ponytail: connection-per-call. Add a pool if this ever fronts a batch job.
type Client struct {
	cfg    Config
	secure bool // URL scheme is ldaps:// — gates password writes
}

// New validates the config and returns a Client. It does not connect; call Ping
// if you want to prove the directory is reachable at boot.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" || cfg.BindDN == "" || cfg.BindPassword == "" || cfg.BaseDN == "" {
		return nil, ErrConfigIncomplete
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Client{
		cfg:    cfg,
		secure: strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://"),
	}, nil
}

// Config returns a copy of the client's configuration. The bind password is
// blanked, so this is safe to log or render.
func (c *Client) Config() Config {
	cfg := c.cfg
	cfg.BindPassword = ""
	return cfg
}

// BaseDN is the configured search root, which callers need in order to render
// or scope a tree.
func (c *Client) BaseDN() string { return c.cfg.BaseDN }

// Ping proves the directory is reachable and the service account still binds.
// Suitable for a health check.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// conn is an ldap.Conn that closes itself if the context is cancelled.
//
// go-ldap has no per-operation context, so a ctx argument would otherwise be
// decoration. Closing the socket is what actually aborts an in-flight search,
// and it makes the deadline a caller sets mean something.
type conn struct {
	*ldap.Conn
	stop func() bool
}

func (c *conn) Close() {
	c.stop() // cancel the watchdog; no-op if it already fired
	c.Conn.Close()
}

// connect dials, negotiates TLS and binds as the service account. The caller
// closes the returned connection.
func (c *Client) connect(ctx context.Context) (*conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l, err := ldap.DialURL(c.cfg.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: c.cfg.Timeout}),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: c.cfg.TLSSkipVerify}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrDirectoryUnavailable, c.cfg.URL, err)
	}
	l.SetTimeout(c.cfg.Timeout)

	if err := l.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		l.Close()
		return nil, fmt.Errorf("%w: bind as %s: %v", ErrDirectoryUnavailable, c.cfg.BindDN, err)
	}

	// context.AfterFunc fires the close on cancellation and hands back a stop
	// func for the normal path.
	wrapped := &conn{Conn: l}
	wrapped.stop = context.AfterFunc(ctx, func() { l.Close() })
	return wrapped, nil
}

// translateErr maps the LDAP result codes a caller can act on onto sentinels.
// op is included in the message so a failure names the operation that produced
// it; the raw directory error is preserved in the text but never as the
// sentinel, so errors.Is stays reliable.
func translateErr(err error, op string) error {
	switch {
	case err == nil:
		return nil
	case ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists):
		return fmt.Errorf("%s: %w", op, ErrAlreadyExists)
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights):
		return fmt.Errorf("%s: %w", op, ErrInsufficientAccess)
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNotAllowedOnNonLeaf):
		return fmt.Errorf("%s: %w", op, ErrNotEmpty)
	case ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation),
		ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform):
		// Active Directory reports "that password fails the policy" as either
		// of these, depending on which rule was broken.
		return fmt.Errorf("%s: %w: %v", op, ErrPasswordRejected, err)
	default:
		return fmt.Errorf("%s: %w: %v", op, ErrWriteFailed, err)
	}
}

// splitDN returns the leftmost RDN and the parent DN, e.g.
// "CN=Ada Lovelace,OU=Staff,DC=example,DC=com" ->
// ("CN=Ada Lovelace", "OU=Staff,DC=example,DC=com").
//
// This goes through ldap.ParseDN rather than splitting on the first comma,
// because a CN routinely contains an escaped comma ("Lovelace\, Ada") and
// cutting on it would produce two DNs that both point somewhere else.
//
// Note that ParseDN normalises attribute types to lower case, so the result is
// "cn=Ada Lovelace" rather than "CN=Ada Lovelace". Attribute types are
// case-insensitive in LDAP and ModifyDN accepts either, so this only shows up
// if the value is displayed. Attribute *values* keep their case and escaping.
func splitDN(dn string) (rdn, parent string, err error) {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return "", "", fmt.Errorf("parse DN %q: %w", dn, err)
	}
	if len(parsed.RDNs) == 0 {
		return "", "", fmt.Errorf("parse DN %q: no components", dn)
	}
	if len(parsed.RDNs) == 1 {
		return parsed.RDNs[0].String(), "", nil
	}

	parts := make([]string, 0, len(parsed.RDNs)-1)
	for _, r := range parsed.RDNs[1:] {
		parts = append(parts, r.String())
	}
	return parsed.RDNs[0].String(), strings.Join(parts, ","), nil
}
