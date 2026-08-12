package ad

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Object is any directory entry, in the shape a browser or picker needs: what
// it is, where it is, and what to call it. Use GetUser for the full attribute
// set of an account.
type Object struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`  // display name where there is one, else the RDN value
	Class       string `json:"class"` // one of the Class constants, or "" if unrecognised
	Description string `json:"description,omitempty"`

	// AccountName is sAMAccountName, set for users, groups and computers. It is
	// the key GetUser and the user write operations take, so a browser can go
	// straight from a listing to an edit without another lookup.
	AccountName string `json:"account_name,omitempty"`

	// HasChildren reports whether this object can contain others. It is derived
	// from the class, not measured — an empty OU still reports true, because it
	// can be expanded and written into.
	HasChildren bool `json:"has_children"`
}

// Children lists the direct children of a container: one level, not the whole
// subtree. This is the call a tree view makes when a node is opened.
//
// Results are sorted containers-first, then by name, which is the order every
// directory browser presents and the one people expect.
func (c *Client) Children(ctx context.Context, dn string) ([]Object, error) {
	if strings.TrimSpace(dn) == "" {
		dn = c.cfg.BaseDN
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := c.search(conn, dn, ldap.ScopeSingleLevel, "(objectClass=*)", objectAttrs, 0)
	if err != nil {
		return nil, fmt.Errorf("Children %s: %w", dn, err)
	}

	objects := make([]Object, 0, len(res.Entries))
	for _, e := range res.Entries {
		objects = append(objects, entryToObject(e))
	}

	sort.SliceStable(objects, func(i, j int) bool {
		if objects[i].HasChildren != objects[j].HasChildren {
			return objects[i].HasChildren
		}
		return strings.ToLower(objects[i].Name) < strings.ToLower(objects[j].Name)
	})
	return objects, nil
}

// Get fetches a single object by DN. It returns ErrNotFound if nothing is
// there.
func (c *Client) Get(ctx context.Context, dn string) (*Object, error) {
	if strings.TrimSpace(dn) == "" {
		return nil, fmt.Errorf("Get: %w", ErrNotFound)
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	obj, err := c.get(conn, dn)
	if err != nil {
		return nil, fmt.Errorf("Get %s: %w", dn, err)
	}
	return obj, nil
}

func (c *Client) get(conn *conn, dn string) (*Object, error) {
	// ScopeBaseObject: read this entry and nothing below it.
	res, err := c.search(conn, dn, ldap.ScopeBaseObject, "(objectClass=*)", objectAttrs, 1)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, ErrNotFound
	}
	obj := entryToObject(res.Entries[0])
	return &obj, nil
}

// containerClasses are the classes that can hold other objects.
var containerClasses = map[string]bool{
	ClassOU: true, ClassContainer: true,
}

func entryToObject(e *ldap.Entry) Object {
	class := classOf(e)
	return Object{
		DN:          e.DN,
		Name:        displayNameOf(e),
		Class:       class,
		Description: e.GetAttributeValue("description"),
		AccountName: e.GetAttributeValue("sAMAccountName"),
		HasChildren: containerClasses[class],
	}
}

// classOf reduces the objectClass chain to the one name a browser cares about.
//
// Order matters and is the whole point of this function. An AD computer account
// carries objectClass: top, person, organizationalPerson, user, computer — so
// checking for "user" first labels every workstation a person. Likewise a
// domain root and a builtinDomain both behave as containers.
func classOf(e *ldap.Entry) string {
	classes := make(map[string]bool)
	for _, v := range e.GetAttributeValues("objectClass") {
		classes[strings.ToLower(v)] = true
	}

	switch {
	case classes["computer"]:
		return ClassComputer
	case classes["organizationalunit"]:
		return ClassOU
	case classes["group"]:
		return ClassGroup
	case classes["user"], classes["person"]:
		return ClassUser
	case classes["container"], classes["builtindomain"], classes["domaindns"],
		classes["lostandfound"], classes["msds-quotacontainer"],
		classes["infrastructureupdate"]:
		return ClassContainer
	default:
		return ""
	}
}

// displayNameOf picks the most human label the entry offers, falling back to
// the RDN value so an object never renders nameless in a tree.
func displayNameOf(e *ldap.Entry) string {
	for _, attr := range []string{"displayName", "name", "sAMAccountName"} {
		if v := e.GetAttributeValue(attr); v != "" {
			return v
		}
	}
	if rdn, _, err := splitDN(e.DN); err == nil {
		if _, value, found := strings.Cut(rdn, "="); found {
			return value
		}
	}
	return e.DN
}
