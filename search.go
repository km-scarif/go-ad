package ad

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Object classes, as used in Query.Classes and reported in Object.Class.
const (
	ClassUser      = "user"
	ClassOU        = "ou"
	ClassGroup     = "group"
	ClassComputer  = "computer"
	ClassContainer = "container"
)

// classFilters maps a class name onto the filter that actually selects it.
//
// The user and computer entries are the two that are not guessable.
// objectClass=user matches computer accounts too, because a computer is a
// subclass of user; objectCategory is what separates them. Getting this wrong
// means a user list quietly includes every workstation in the domain.
var classFilters = map[string]string{
	ClassUser:      "(&(objectCategory=person)(objectClass=user))",
	ClassComputer:  "(objectCategory=computer)",
	ClassOU:        "(objectClass=organizationalUnit)",
	ClassGroup:     "(objectClass=group)",
	ClassContainer: containerFilter,
}

// containerFilter selects the things that hold child objects but are not OUs.
// There is no single class they share: AD's default layout puts CN=Builtin on
// builtinDomain, CN=LostAndFound on lostAndFound, CN=NTDS Quotas on
// msDS-QuotaContainer and CN=Infrastructure on infrastructureUpdate, so they
// get enumerated. Matching only objectClass=container drops those four, which
// is why they were missing from the tree and hidden as "system" objects in a
// listing.
//
// domainDNS is deliberately absent: it is the base DN's own class, and a
// subtree search matching it returns the base as a child of itself.
const containerFilter = "(|(objectClass=container)(objectClass=builtinDomain)" +
	"(objectClass=lostAndFound)(objectClass=msDS-QuotaContainer)" +
	"(objectClass=infrastructureUpdate))"

// Bitwise AND matching rule OID. Active Directory needs this to test a single
// bit of userAccountControl — there is no other way to ask "is this account
// disabled" in a filter, since UAC is one integer holding a dozen flags.
const bitwiseAnd = "1.2.840.113556.1.4.803"

// Query is the typed search. Every field is optional; a zero Query matches
// everything under BaseDN.
//
// Use this rather than hand-writing filters where it fits: values are escaped
// on the way in, so a search term typed into a box cannot rewrite the filter.
// When it does not fit, Search takes a raw filter instead.
type Query struct {
	// Term is matched as a substring against account name, display name, email
	// and object name.
	Term string

	// BaseDN scopes the search. Empty means the client's configured BaseDN.
	BaseDN string

	// Classes restricts results to these object classes (see the Class
	// constants). Empty means any class.
	Classes []string

	// Enabled filters user accounts on the disabled bit of
	// userAccountControl. Nil means either. Setting this on a search that also
	// matches non-user classes will exclude them, since only accounts carry
	// userAccountControl.
	Enabled *bool

	// Limit caps the number of entries returned. Zero or negative means no
	// limit, which against a large directory means every matching entry.
	Limit int

	// Filter is a raw LDAP filter, AND-ed with whatever the other fields
	// produce. Set it alone and it is the whole filter.
	//
	// This is the escape hatch for searches Query cannot express, while still
	// getting Objects back. Search returns raw *ldap.Entry instead, for when
	// you need attributes Object does not carry.
	//
	// It is sent as written: anything interpolated into it must be escaped by
	// the caller (ldap.EscapeFilter). A filter that does not parse comes back
	// as ErrBadFilter rather than being sent to the server.
	Filter string
}

// objectAttrs is what a browse or search asks for. A whitelist rather than
// "*": AD entries carry a long tail of operational attributes nothing here
// reads, and asking only for these keeps responses small.
var objectAttrs = []string{
	"distinguishedName", "objectClass", "name", "description",
	"sAMAccountName", "displayName", "mail",
}

// Find runs a typed search and returns the matching objects.
func (c *Client) Find(ctx context.Context, q Query) ([]Object, error) {
	filter := buildFilter(q)

	// Validate before connecting. A hand-written filter is the one part of a
	// Query that can be malformed, and "your filter has unbalanced parens" is a
	// far better answer than whatever the server says about it.
	if _, err := ldap.CompileFilter(filter); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadFilter, err)
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	base := q.BaseDN
	if base == "" {
		base = c.cfg.BaseDN
	}

	res, err := c.search(conn, base, ldap.ScopeWholeSubtree, filter, objectAttrs, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("Find: %w", err)
	}

	objects := make([]Object, 0, len(res.Entries))
	for _, e := range res.Entries {
		objects = append(objects, entryToObject(e))
	}
	return objects, nil
}

// Search is the escape hatch: you supply the filter, this runs it and returns
// raw entries. Use it for anything Query cannot express.
//
// The filter is sent as written. Any value interpolated into it must be passed
// through ldap.EscapeFilter first, or a value containing ")(" rewrites the
// query.
//
// baseDN empty means the client's configured BaseDN; attrs nil means the same
// attribute set the typed searches request; limit zero means no limit.
func (c *Client) Search(ctx context.Context, baseDN, filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	if strings.TrimSpace(filter) == "" {
		return nil, errors.New("Search: filter is empty")
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}
	if attrs == nil {
		attrs = objectAttrs
	}

	res, err := c.search(conn, baseDN, ldap.ScopeWholeSubtree, filter, attrs, limit)
	if err != nil {
		return nil, fmt.Errorf("Search: %w", err)
	}
	return res.Entries, nil
}

// buildFilter assembles the LDAP filter for a Query. Exported behaviour is
// covered by tests; the escaping here is the security-relevant part.
func buildFilter(q Query) string {
	var clauses []string

	switch len(q.Classes) {
	case 0:
	case 1:
		if f, ok := classFilters[q.Classes[0]]; ok {
			clauses = append(clauses, f)
		}
	default:
		var alts []string
		for _, class := range q.Classes {
			if f, ok := classFilters[class]; ok {
				alts = append(alts, f)
			}
		}
		if len(alts) > 0 {
			clauses = append(clauses, "(|"+strings.Join(alts, "")+")")
		}
	}

	// EscapeFilter, always: this value comes from a search box, and an
	// unescaped ( or * here would let the caller rewrite the filter.
	if term := strings.TrimSpace(q.Term); term != "" {
		e := ldap.EscapeFilter(term)
		clauses = append(clauses, fmt.Sprintf(
			"(|(sAMAccountName=*%s*)(displayName=*%s*)(mail=*%s*)(name=*%s*))", e, e, e, e))
	}

	if q.Enabled != nil {
		disabled := fmt.Sprintf("(userAccountControl:%s:=%d)", bitwiseAnd, uacAccountDisabled)
		if *q.Enabled {
			clauses = append(clauses, "(!"+disabled+")")
		} else {
			clauses = append(clauses, disabled)
		}
	}

	// The caller's own filter, last, sent as written. Wrapped in parens if it
	// is missing them so that "objectClass=group" works as well as the correct
	// "(objectClass=group)" — people type it both ways.
	if raw := strings.TrimSpace(q.Filter); raw != "" {
		if !strings.HasPrefix(raw, "(") {
			raw = "(" + raw + ")"
		}
		clauses = append(clauses, raw)
	}

	switch len(clauses) {
	case 0:
		return "(objectClass=*)"
	case 1:
		return clauses[0]
	default:
		return "(&" + strings.Join(clauses, "") + ")"
	}
}

// adPageSize is just under Active Directory's default MaxPageSize of 1000.
const adPageSize = 900

// search runs a search that honours limit without fetching more of the
// directory than it has to.
//
// The two branches exist because SearchWithPaging ignores SizeLimit — it loops
// until the server stops handing out cookies, so using it for a limit of 5
// would pull every matching entry across the wire and throw almost all of them
// away. A small limit therefore goes out as a real server-side SizeLimit and
// one round trip; only a limit bigger than a page needs the paging loop, which
// is also the path that stops an unbounded search from silently truncating at
// MaxPageSize as the directory grows.
func (c *Client) search(conn *conn, baseDN string, scope int, filter string, attrs []string, limit int) (*ldap.SearchResult, error) {
	timeLimit := int(c.cfg.Timeout.Seconds())

	req := ldap.NewSearchRequest(
		baseDN, scope, ldap.NeverDerefAliases,
		limit, timeLimit, false,
		filter, attrs, nil,
	)

	if limit > 0 && limit <= adPageSize {
		req.SizeLimit = limit
		req.EnforceSizeLimit = true // stop parsing at the limit even if more arrives

		res, err := conn.Search(req)
		// Hitting the limit is the expected outcome, not a failure: both the
		// client-side stop and AD's own sizeLimitExceeded reply come back as
		// errors, and both carry the entries that were asked for.
		if err != nil &&
			!errors.Is(err, ldap.ErrSizeLimitExceeded) &&
			!ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, searchErr(err, baseDN)
		}
		if res == nil {
			return &ldap.SearchResult{}, nil
		}
		return res, nil
	}

	res, err := conn.SearchWithPaging(req, adPageSize)
	if err != nil {
		return nil, searchErr(err, baseDN)
	}
	if limit > 0 && len(res.Entries) > limit {
		res.Entries = res.Entries[:limit]
	}
	return res, nil
}

// searchErr translates the one search failure worth distinguishing. A search
// against a base DN that does not exist is an error (result 32), not an empty
// result set — a distinction that reliably surprises people, because a typo in
// a container name looks identical to "nothing matched" until you check the
// code.
func searchErr(err error, baseDN string) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return fmt.Errorf("%w: %s", ErrNotFound, baseDN)
	}
	return err
}
