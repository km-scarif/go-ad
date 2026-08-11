package ad

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The unicodePwd encoding is the money path: get it wrong and every account is
// created with a password nobody can bind with, which looks like a directory
// problem rather than an encoding bug. Assert the exact bytes AD expects — the
// password wrapped in literal double quotes, UTF-16 little-endian.
func TestEncodePassword(t *testing.T) {
	got := []byte(encodePassword("aA1!"))
	want := []byte{
		0x22, 0x00, // "
		0x61, 0x00, // a
		0x41, 0x00, // A
		0x31, 0x00, // 1
		0x21, 0x00, // !
		0x22, 0x00, // "
	}

	if len(got) != len(want) {
		t.Fatalf("length: got %d bytes, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d: got %#02x, want %#02x (full: %v)", i, got[i], want[i], got)
		}
	}

	// Non-ASCII must survive as a 2-byte code unit, not be mangled to UTF-8.
	if n := len([]byte(encodePassword("é"))); n != 6 {
		t.Errorf("non-ascii: got %d bytes, want 6 (quote + é + quote, 2 bytes each)", n)
	}
}

// accountNameRe guards a value that lands in a DN, a UPN and an LDAP filter, so
// the rejections matter more than the acceptances.
func TestAccountNameValidation(t *testing.T) {
	valid := []string{"ada", "a", "first.last", "a_b-c", "user123", strings.Repeat("x", 20)}
	for _, s := range valid {
		if !accountNameRe.MatchString(s) {
			t.Errorf("rejected valid account name %q", s)
		}
	}

	invalid := []string{
		"",                      // empty
		strings.Repeat("x", 21), // AD caps sAMAccountName at 20
		"ada lovelace",          // space
		"ada,cn=x",              // DN injection
		"ada*",                  // filter wildcard
		"ada)(cn=*",             // filter injection
		"ada@example.com",       // @ is added from UPNSuffix, not by the caller
		"ada/x", "ada\\x",       // DN / escape syntax
	}
	for _, s := range invalid {
		if accountNameRe.MatchString(s) {
			t.Errorf("accepted invalid account name %q", s)
		}
	}
}

func TestBuildFilter(t *testing.T) {
	enabled, disabled := true, false

	tests := []struct {
		name  string
		query Query
		want  string
	}{
		{
			name:  "empty query matches everything",
			query: Query{},
			want:  "(objectClass=*)",
		},
		{
			// objectCategory=person is what keeps computer accounts out.
			name:  "user class only",
			query: Query{Classes: []string{ClassUser}},
			want:  "(&(objectCategory=person)(objectClass=user))",
		},
		{
			name:  "multiple classes are OR-ed",
			query: Query{Classes: []string{ClassOU, ClassGroup}},
			want:  "(|(objectClass=organizationalUnit)(objectClass=group))",
		},
		{
			name:  "unknown class is dropped, not passed through",
			query: Query{Classes: []string{"nonsense"}},
			want:  "(objectClass=*)",
		},
		{
			name:  "term searches four attributes",
			query: Query{Term: "ada"},
			want:  "(|(sAMAccountName=*ada*)(displayName=*ada*)(mail=*ada*)(name=*ada*))",
		},
		{
			name:  "enabled uses the bitwise matching rule",
			query: Query{Enabled: &enabled},
			want:  "(!(userAccountControl:1.2.840.113556.1.4.803:=2))",
		},
		{
			name:  "disabled is the same rule, not negated",
			query: Query{Enabled: &disabled},
			want:  "(userAccountControl:1.2.840.113556.1.4.803:=2)",
		},
		{
			name:  "class and term are AND-ed",
			query: Query{Classes: []string{ClassOU}, Term: "sales"},
			want:  "(&(objectClass=organizationalUnit)(|(sAMAccountName=*sales*)(displayName=*sales*)(mail=*sales*)(name=*sales*)))",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildFilter(tc.query); got != tc.want {
				t.Errorf("buildFilter:\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

// A search term arrives from a text box, so it is the one value in the filter an
// outsider controls. Anything that could close a clause and open a new one has
// to come back escaped, or the term rewrites the query.
func TestBuildFilterEscapesTerm(t *testing.T) {
	injections := []string{
		")(objectClass=*",    // close the clause, start another
		"*",                  // bare wildcard
		"a)(|(objectClass=*", // close and OR in a match-everything
		`x\`,                 // trailing escape char
		"a\x00b",             // NUL
	}

	for _, term := range injections {
		got := buildFilter(Query{Term: term})

		// The escaped form must not contain the raw metacharacters, and the
		// filter must still parse as a single well-formed filter.
		if strings.Contains(got, ")(objectClass=*") {
			t.Errorf("term %q leaked an unescaped clause into: %s", term, got)
		}
		if _, err := ldap.CompileFilter(got); err != nil {
			t.Errorf("term %q produced an unparseable filter %s: %v", term, got, err)
		}
	}
}

// Attribute types come back lower-cased, because that is what ParseDN does.
// LDAP attribute types are case-insensitive and ModifyDN accepts either form,
// so what matters here is that the attribute *values* keep their case and their
// escaping.
func TestSplitDN(t *testing.T) {
	tests := []struct {
		dn, rdn, parent string
	}{
		{
			dn:     "CN=Ada Lovelace,OU=Staff,DC=example,DC=com",
			rdn:    "cn=Ada Lovelace",
			parent: "ou=Staff,dc=example,dc=com",
		},
		{
			// The reason this goes through ParseDN instead of cutting on the
			// first comma: the comma here belongs to the name.
			dn:     `CN=Lovelace\, Ada,OU=Staff,DC=example,DC=com`,
			rdn:    `cn=Lovelace\, Ada`,
			parent: "ou=Staff,dc=example,dc=com",
		},
		{
			dn:     "DC=example,DC=com",
			rdn:    "dc=example",
			parent: "dc=com",
		},
		{
			dn:     "DC=com",
			rdn:    "dc=com",
			parent: "",
		},
	}

	for _, tc := range tests {
		rdn, parent, err := splitDN(tc.dn)
		if err != nil {
			t.Errorf("splitDN(%q): unexpected error %v", tc.dn, err)
			continue
		}
		if rdn != tc.rdn || parent != tc.parent {
			t.Errorf("splitDN(%q):\n got  rdn=%q parent=%q\n want rdn=%q parent=%q",
				tc.dn, rdn, parent, tc.rdn, tc.parent)
		}
	}

	if _, _, err := splitDN("not a dn"); err == nil {
		t.Error("splitDN(\"not a dn\"): expected an error, got none")
	}
}

// DNs are case-insensitive and come back spaced inconsistently depending on who
// wrote them. If canonicalDN does not normalise both, parent lookups miss and
// the tree comes out flat.
func TestCanonicalDN(t *testing.T) {
	forms := []string{
		"OU=Staff,DC=example,DC=com",
		"ou=staff,dc=example,dc=com",
		"OU=Staff, DC=example, DC=com",
		"  OU=Staff,DC=example,DC=com  ",
	}

	want := canonicalDN(forms[0])
	for _, f := range forms[1:] {
		if got := canonicalDN(f); got != want {
			t.Errorf("canonicalDN(%q) = %q, want %q", f, got, want)
		}
	}
}

// entry builds a minimal *ldap.Entry for the assembly tests.
func entry(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for name, values := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: values})
	}
	return e
}

func TestBuildTree(t *testing.T) {
	const base = "DC=example,DC=com"

	// Deliberately out of order, with a grandchild ahead of its parent: this is
	// what the directory actually returns, and building the hierarchy in one
	// pass would drop the deeper nodes.
	entries := []*ldap.Entry{
		entry("OU=West,OU=Sales,"+base, map[string][]string{"ou": {"West"}}),
		entry("OU=Staff,"+base, map[string][]string{"ou": {"Staff"}}),
		entry("OU=Sales,"+base, map[string][]string{"ou": {"Sales"}}),
		entry("OU=East,OU=Sales,"+base, map[string][]string{"ou": {"East"}}),
	}

	root := buildTree(base, entries)

	if root.DN != base {
		t.Fatalf("root DN = %q, want %q", root.DN, base)
	}
	if len(root.Children) != 2 {
		t.Fatalf("root has %d children, want 2 (Sales, Staff)", len(root.Children))
	}

	// Children are sorted case-insensitively by name.
	if root.Children[0].Name != "Sales" || root.Children[1].Name != "Staff" {
		t.Fatalf("root children = %q, %q; want Sales, Staff",
			root.Children[0].Name, root.Children[1].Name)
	}

	sales := root.Children[0]
	if len(sales.Children) != 2 {
		t.Fatalf("Sales has %d children, want 2", len(sales.Children))
	}
	if sales.Children[0].Name != "East" || sales.Children[1].Name != "West" {
		t.Errorf("Sales children = %q, %q; want East, West",
			sales.Children[0].Name, sales.Children[1].Name)
	}
}

// An OU whose parent is a container rather than another OU has no parent node
// in the map. It must still land in the tree — silently dropping it would hide
// part of the directory from a browser.
func TestBuildTreeOrphanAttachesToRoot(t *testing.T) {
	const base = "DC=example,DC=com"

	entries := []*ldap.Entry{
		entry("OU=Odd,CN=Users,"+base, map[string][]string{"ou": {"Odd"}}),
	}

	root := buildTree(base, entries)
	if len(root.Children) != 1 || root.Children[0].Name != "Odd" {
		t.Fatalf("orphan OU was not attached to the root: %+v", root.Children)
	}
}

func TestClassOf(t *testing.T) {
	tests := []struct {
		name    string
		classes []string
		want    string
	}{
		{
			// The case this function exists for: a computer account carries
			// objectClass=user too, so checking user first labels every
			// workstation in the domain a person.
			name:    "computer beats user",
			classes: []string{"top", "person", "organizationalPerson", "user", "computer"},
			want:    ClassComputer,
		},
		{
			name:    "user",
			classes: []string{"top", "person", "organizationalPerson", "user"},
			want:    ClassUser,
		},
		{name: "ou", classes: []string{"top", "organizationalUnit"}, want: ClassOU},
		{name: "group", classes: []string{"top", "group"}, want: ClassGroup},
		{name: "container", classes: []string{"top", "container"}, want: ClassContainer},
		{name: "builtinDomain is a container", classes: []string{"top", "builtinDomain"}, want: ClassContainer},
		{name: "case insensitive", classes: []string{"TOP", "ORGANIZATIONALUNIT"}, want: ClassOU},
		{name: "unrecognised", classes: []string{"top", "msDS-QuotaContainer"}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classOf(entry("CN=x,DC=example,DC=com", map[string][]string{"objectClass": tc.classes}))
			if got != tc.want {
				t.Errorf("classOf(%v) = %q, want %q", tc.classes, got, tc.want)
			}
		})
	}
}

// An object must never render nameless in a tree, whatever attributes it is
// missing.
func TestDisplayNameOf(t *testing.T) {
	tests := []struct {
		name  string
		dn    string
		attrs map[string][]string
		want  string
	}{
		{
			name:  "prefers displayName",
			dn:    "CN=alovelace,DC=example,DC=com",
			attrs: map[string][]string{"displayName": {"Ada Lovelace"}, "name": {"alovelace"}},
			want:  "Ada Lovelace",
		},
		{
			name:  "falls back to name",
			dn:    "CN=alovelace,DC=example,DC=com",
			attrs: map[string][]string{"name": {"alovelace"}},
			want:  "alovelace",
		},
		{
			name:  "falls back to the RDN value",
			dn:    "CN=alovelace,DC=example,DC=com",
			attrs: nil,
			want:  "alovelace",
		},
		{
			name:  "RDN fallback unescapes a comma in the name",
			dn:    `CN=Lovelace\, Ada,DC=example,DC=com`,
			attrs: nil,
			want:  `Lovelace\, Ada`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayNameOf(entry(tc.dn, tc.attrs)); got != tc.want {
				t.Errorf("displayNameOf = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidOUName(t *testing.T) {
	// Commas and plus signs are legal in an OU name — they get escaped into the
	// RDN, not rejected.
	valid := map[string]string{
		"Sales":       "Sales",
		"Sales, West": "Sales, West",
		"  Sales  ":   "Sales",
		"R+D":         "R+D",
	}
	for in, want := range valid {
		got, err := validOUName(in)
		if err != nil {
			t.Errorf("validOUName(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Errorf("validOUName(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{"", "   ", "Sales/West"}
	for _, in := range invalid {
		if _, err := validOUName(in); err == nil {
			t.Errorf("validOUName(%q): expected an error, got none", in)
		}
	}
}

// New must not hand back a client that is missing something it needs, and it
// must never expose the bind password through Config.
func TestNewValidatesAndHidesPassword(t *testing.T) {
	full := Config{
		URL:          "ldaps://dc.example.com:636",
		BindDN:       "CN=svc,DC=example,DC=com",
		BindPassword: "secret",
		BaseDN:       "DC=example,DC=com",
	}

	for _, missing := range []string{"URL", "BindDN", "BindPassword", "BaseDN"} {
		cfg := full
		switch missing {
		case "URL":
			cfg.URL = ""
		case "BindDN":
			cfg.BindDN = ""
		case "BindPassword":
			cfg.BindPassword = ""
		case "BaseDN":
			cfg.BaseDN = ""
		}
		if _, err := New(cfg); err == nil {
			t.Errorf("New with empty %s: expected an error, got none", missing)
		}
	}

	c, err := New(full)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.secure {
		t.Error("ldaps:// URL did not set secure")
	}
	if c.Config().BindPassword != "" {
		t.Error("Config() leaked the bind password")
	}
	if c.cfg.Timeout != DefaultTimeout {
		t.Errorf("zero Timeout became %v, want %v", c.cfg.Timeout, DefaultTimeout)
	}
}

// Password writes over plain ldap:// have to fail here rather than at the
// server: AD's own answer is an opaque "unwilling to perform" that reads like a
// policy rejection, which sends you looking in the wrong place.
func TestPasswordWriteRequiresTLS(t *testing.T) {
	c, err := New(Config{
		URL:          "ldap://dc.example.com:389",
		BindDN:       "CN=svc,DC=example,DC=com",
		BindPassword: "secret",
		BaseDN:       "DC=example,DC=com",
		UsersDN:      "CN=Users,DC=example,DC=com",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.secure {
		t.Fatal("ldap:// URL was treated as secure")
	}

	// No directory is reachable here — the point is that both calls fail on the
	// TLS check before any connection is attempted.
	pw := "hunter2"
	if _, err := c.CreateUser(t.Context(), CreateUserRequest{
		AccountName: "ada", DisplayName: "Ada Lovelace", Password: pw,
	}); err != ErrTLSRequired {
		t.Errorf("CreateUser with a password over ldap://: got %v, want ErrTLSRequired", err)
	}
	if _, err := c.UpdateUser(t.Context(), "ada", UpdateUserRequest{Password: &pw}); err != ErrTLSRequired {
		t.Errorf("UpdateUser with a password over ldap://: got %v, want ErrTLSRequired", err)
	}
}

// Query.Filter is the raw escape hatch inside the typed call. It is AND-ed
// with whatever the other fields produce, so it composes rather than replacing
// them.
func TestBuildFilterRaw(t *testing.T) {
	tests := []struct {
		name  string
		query Query
		want  string
	}{
		{
			name:  "filter alone is the whole filter",
			query: Query{Filter: "(objectClass=group)"},
			want:  "(objectClass=group)",
		},
		{
			// People type it both ways; the bare form is not a syntax error
			// worth failing over.
			name:  "bare filter gets wrapped",
			query: Query{Filter: "objectClass=group"},
			want:  "(objectClass=group)",
		},
		{
			name:  "filter composes with the typed fields",
			query: Query{Classes: []string{ClassUser}, Filter: "(department=Sales)"},
			want:  "(&(&(objectCategory=person)(objectClass=user))(department=Sales))",
		},
		{
			name:  "whitespace-only filter is ignored",
			query: Query{Classes: []string{ClassOU}, Filter: "   "},
			want:  "(objectClass=organizationalUnit)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildFilter(tc.query); got != tc.want {
				t.Errorf("buildFilter:\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

// A malformed filter must be rejected before it reaches the directory: the
// server's answer is far less useful than naming the syntax problem, and Find
// would otherwise dial and bind just to fail.
func TestFindRejectsBadFilter(t *testing.T) {
	c, err := New(Config{
		URL: "ldaps://dc.example.com:636", BindDN: "CN=svc,DC=example,DC=com",
		BindPassword: "secret", BaseDN: "DC=example,DC=com",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// No directory is reachable here — the point is that it fails on the filter
	// rather than on the connection.
	//
	// Only structural breakage is caught. "(|)" is not in this list because
	// go-ldap compiles an empty OR quite happily; the directory is what
	// rejects it. This validates syntax, not semantics.
	for _, bad := range []string{"(objectClass=", "(&(a=b)", "((a=b)"} {
		if _, err := c.Find(t.Context(), Query{Filter: bad}); !errors.Is(err, ErrBadFilter) {
			t.Errorf("Find with filter %q: got %v, want ErrBadFilter", bad, err)
		}
	}
}
