package ad

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// OU is one organizational unit.
type OU struct {
	DN          string `json:"dn"`
	Name        string `json:"name"` // the ou attribute, i.e. the RDN value
	Description string `json:"description,omitempty"`
}

// TreeNode is one node of the OU hierarchy. The root node is the client's
// BaseDN, which is a domain rather than an OU.
type TreeNode struct {
	DN       string      `json:"dn"`
	Name     string      `json:"name"`
	Children []*TreeNode `json:"children,omitempty"`
}

// ouAttrs is the attribute whitelist for OU reads.
var ouAttrs = []string{"distinguishedName", "ou", "name", "description"}

// Tree returns the entire OU hierarchy under BaseDN in a single search.
//
// One query, not one per expanded node: a subtree search for every OU is a
// single round trip and the result is small even on a large directory (a few
// hundred entries), so the hierarchy is assembled here rather than lazily. A
// tree view can render the whole thing at once and expand without further
// requests.
//
// Only organizational units are included. Containers such as CN=Users are not
// OUs and do not appear, though Children will still list them.
func (c *Client) Tree(ctx context.Context) (*TreeNode, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := c.search(conn, c.cfg.BaseDN, ldap.ScopeWholeSubtree,
		classFilters[ClassOU], ouAttrs, 0)
	if err != nil {
		return nil, fmt.Errorf("Tree: %w", err)
	}

	return buildTree(c.cfg.BaseDN, res.Entries), nil
}

// buildTree assembles the hierarchy from a flat list of OU entries. Split out
// from Tree so the assembly can be tested without a directory, which is where
// the fiddly part lives.
func buildTree(baseDN string, entries []*ldap.Entry) *TreeNode {
	root := &TreeNode{DN: baseDN, Name: baseDN}
	nodes := map[string]*TreeNode{canonicalDN(baseDN): root}

	// First pass: every OU becomes a node. The hierarchy cannot be built in the
	// same pass, because the directory returns entries in no particular order —
	// a child routinely arrives before its parent.
	for _, e := range entries {
		nodes[canonicalDN(e.DN)] = &TreeNode{DN: e.DN, Name: ouNameOf(e)}
	}

	// Second pass: attach each node to its parent. A node whose parent is not an
	// OU (one sitting under a container, say) attaches to the root, so it stays
	// reachable in the tree rather than vanishing.
	for _, e := range entries {
		node := nodes[canonicalDN(e.DN)]
		parent := root
		if _, parentDN, err := splitDN(e.DN); err == nil {
			if p, ok := nodes[canonicalDN(parentDN)]; ok {
				parent = p
			}
		}
		parent.Children = append(parent.Children, node)
	}

	sortTree(root)
	return root
}

func sortTree(n *TreeNode) {
	sort.SliceStable(n.Children, func(i, j int) bool {
		return strings.ToLower(n.Children[i].Name) < strings.ToLower(n.Children[j].Name)
	})
	for _, child := range n.Children {
		sortTree(child)
	}
}

// ListOUs returns the direct child OUs of a container. Empty parentDN means the
// client's BaseDN.
func (c *Client) ListOUs(ctx context.Context, parentDN string) ([]OU, error) {
	if strings.TrimSpace(parentDN) == "" {
		parentDN = c.cfg.BaseDN
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := c.search(conn, parentDN, ldap.ScopeSingleLevel,
		classFilters[ClassOU], ouAttrs, 0)
	if err != nil {
		return nil, fmt.Errorf("ListOUs %s: %w", parentDN, err)
	}

	ous := make([]OU, 0, len(res.Entries))
	for _, e := range res.Entries {
		ous = append(ous, OU{
			DN:          e.DN,
			Name:        ouNameOf(e),
			Description: e.GetAttributeValue("description"),
		})
	}
	sort.SliceStable(ous, func(i, j int) bool {
		return strings.ToLower(ous[i].Name) < strings.ToLower(ous[j].Name)
	})
	return ous, nil
}

// CreateOU adds an organizational unit under parentDN. Empty parentDN means the
// client's BaseDN.
func (c *Client) CreateOU(ctx context.Context, parentDN, name, description string) (*OU, error) {
	name, err := validOUName(name)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(parentDN) == "" {
		parentDN = c.cfg.BaseDN
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dn := fmt.Sprintf("OU=%s,%s", ldap.EscapeDN(name), parentDN)

	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"organizationalUnit"})
	add.Attribute("ou", []string{name})
	addOptional(add, "description", description)

	if err := conn.Add(add); err != nil {
		return nil, translateErr(err, "CreateOU "+name)
	}

	return &OU{DN: dn, Name: name, Description: strings.TrimSpace(description)}, nil
}

// UpdateOURequest is a partial edit of an organizational unit. As with
// UpdateUserRequest, a nil field is left alone and a field set to "" clears the
// attribute.
//
// The name is not here: it is part of the DN, so changing it is RenameOU.
type UpdateOURequest struct {
	Description *string `json:"description"`
}

// UpdateOU applies a partial edit to an organizational unit.
func (c *Client) UpdateOU(ctx context.Context, dn string, req UpdateOURequest) error {
	if strings.TrimSpace(dn) == "" {
		return fmt.Errorf("UpdateOU: dn is empty")
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	mod := ldap.NewModifyRequest(dn, nil)
	if replaceOptional(mod, "description", req.Description) == 0 {
		return ErrNothingToUpdate
	}

	if err := conn.Modify(mod); err != nil {
		return translateErr(err, "UpdateOU "+dn)
	}
	return nil
}

// RenameOU changes an organizational unit's name, keeping it where it is.
//
// This is a ModifyDN rather than a write to the ou attribute: the name is part
// of the DN, so renaming the OU rewrites the DN of every object beneath it.
// Anything holding those DNs — a cached group membership, another service's
// config — is stale afterwards.
func (c *Client) RenameOU(ctx context.Context, dn, newName string) error {
	newName, err := validOUName(newName)
	if err != nil {
		return err
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// delOld=true: drop the old ou value, otherwise the entry keeps its old name
	// as a second value of the attribute.
	req := ldap.NewModifyDNRequest(dn, "OU="+ldap.EscapeDN(newName), true, "")
	if err := conn.ModifyDN(req); err != nil {
		return translateErr(err, "RenameOU "+dn)
	}
	return nil
}

// MoveOU moves an organizational unit, and everything under it, to a different
// parent. The same DN-rewriting caveat as RenameOU applies.
func (c *Client) MoveOU(ctx context.Context, dn, newParentDN string) error {
	if strings.TrimSpace(newParentDN) == "" {
		return fmt.Errorf("MoveOU %s: newParentDN is empty", dn)
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	rdn, _, err := splitDN(dn)
	if err != nil {
		return fmt.Errorf("MoveOU %s: %w", dn, err)
	}

	if err := conn.ModifyDN(ldap.NewModifyDNRequest(dn, rdn, true, newParentDN)); err != nil {
		return translateErr(err, "MoveOU "+dn)
	}
	return nil
}

// DeleteOU removes an empty organizational unit.
//
// A non-empty OU returns ErrNotEmpty: LDAP refuses to delete a non-leaf entry,
// and this deliberately does not recurse. Deleting a container full of accounts
// should be a decision the caller makes explicitly, one object at a time.
//
// Note that Active Directory's "Protect object from accidental deletion" flag
// denies the delete at the ACL layer, so a protected OU fails with
// ErrInsufficientAccess even when it is empty and the bind account is
// otherwise privileged.
func (c *Client) DeleteOU(ctx context.Context, dn string) error {
	if strings.TrimSpace(dn) == "" {
		return fmt.Errorf("DeleteOU: dn is empty")
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		return translateErr(err, "DeleteOU "+dn)
	}
	return nil
}

// --- helpers ---

// validRDNValue trims and checks a value that is about to become the naming
// part of a DN.
//
// Characters with DN syntax (comma, plus, backslash and friends) are escaped by
// EscapeDN rather than rejected, so "Sales, West" is a legal name here. The
// rejections are the ones Active Directory itself will not accept: an empty
// name, a forward slash, and leading or trailing whitespace.
//
// The sentinel is passed in so callers get an error naming the thing they were
// creating rather than a generic one.
func validRDNValue(name string, sentinel error) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || strings.ContainsAny(trimmed, "/") {
		return "", fmt.Errorf("%w: %q", sentinel, name)
	}
	return trimmed, nil
}

func validOUName(name string) (string, error) {
	return validRDNValue(name, ErrInvalidOUName)
}

// ouNameOf prefers the ou attribute and falls back to name, which is what the
// directory populates for entries created outside the usual tooling.
func ouNameOf(e *ldap.Entry) string {
	if v := e.GetAttributeValue("ou"); v != "" {
		return v
	}
	return e.GetAttributeValue("name")
}

// canonicalDN normalises a DN for comparison. DNs are case-insensitive and may
// come back with or without spaces after the commas depending on who wrote
// them, so parent/child matching has to compare a normalised form or the tree
// silently comes out flat.
func canonicalDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	parts := make([]string, 0, len(parsed.RDNs))
	for _, r := range parsed.RDNs {
		parts = append(parts, r.String())
	}
	return strings.ToLower(strings.Join(parts, ","))
}
