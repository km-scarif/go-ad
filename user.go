package ad

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// User is one directory account. The comment on each field is the AD attribute
// it maps to, since those names are not guessable from the Go ones.
type User struct {
	AccountName string `json:"account_name"`         // sAMAccountName
	DN          string `json:"dn"`                   // distinguishedName
	DisplayName string `json:"display_name"`         // displayName
	GivenName   string `json:"first_name,omitempty"` // givenName
	Surname     string `json:"last_name,omitempty"`  // sn
	Mail        string `json:"email,omitempty"`      // mail
	Title       string `json:"title,omitempty"`      // title
	Department  string `json:"department,omitempty"` // department
	Office      string `json:"office,omitempty"`     // physicalDeliveryOfficeName
	Phone       string `json:"phone,omitempty"`      // telephoneNumber
	UPN         string `json:"upn,omitempty"`        // userPrincipalName
	Enabled     bool   `json:"enabled"`              // userAccountControl & 2 == 0

	// GUID is objectGUID, base64-encoded from the raw 16 bytes. That encoding
	// rather than the braced hex form on purpose: it is what Entra ID stores as
	// immutableId/sourceAnchor, so this is the value to compare against when
	// checking whether an on-prem account matches its synced cloud object.
	//
	// Read-only. objectGUID is assigned by the directory at creation and cannot
	// be changed.
	GUID string `json:"guid,omitempty"`
}

// CreateUserRequest is the input to CreateUser.
//
// Password is optional. Without one the account is created disabled, because
// Active Directory will not enable an account that has no password — that is a
// directory rule, not a choice this package makes.
type CreateUserRequest struct {
	AccountName string `json:"account_name"`
	DisplayName string `json:"display_name"`
	GivenName   string `json:"first_name"`
	Surname     string `json:"last_name"`
	Mail        string `json:"email"`
	Title       string `json:"title"`
	Department  string `json:"department"`
	Office      string `json:"office"`
	Phone       string `json:"phone"`
	Password    string `json:"password"`

	// ParentDN is the container to create the account in. Empty falls back to
	// Config.UsersDN.
	ParentDN string `json:"parent_dn"`
}

// UpdateUserRequest is a partial edit.
//
// Every field is a pointer so "absent" and "explicitly cleared" stay
// distinguishable: a nil field is left alone, a field set to "" clears the
// attribute. A plain string cannot express the difference, and a partial update
// that silently wiped every omitted attribute would be a data-loss bug the
// first time someone edited only a job title.
type UpdateUserRequest struct {
	DisplayName *string `json:"display_name"`
	GivenName   *string `json:"first_name"`
	Surname     *string `json:"last_name"`
	Mail        *string `json:"email"`
	Title       *string `json:"title"`
	Department  *string `json:"department"`
	Office      *string `json:"office"`
	Phone       *string `json:"phone"`
	Password    *string `json:"password"`
	Enabled     *bool   `json:"enabled"`
}

// userAttrs is the attribute whitelist for account reads.
var userAttrs = []string{
	"sAMAccountName", "distinguishedName", "displayName", "givenName", "sn",
	"mail", "title", "department", "physicalDeliveryOfficeName",
	"telephoneNumber", "userAccountControl", "userPrincipalName", "objectGUID",
}

// personFilter excludes computer accounts, which are a subclass of
// objectClass=user — objectCategory=person is what separates them.
const personFilter = "(&(objectCategory=person)(objectClass=user)%s)"

// userAccountControl is a bit field, so enabling an account means clearing bit
// 2, not assigning 512. A blind assignment silently drops flags that were
// already set on the entry, such as DONT_EXPIRE_PASSWORD.
const (
	uacNormalAccount   = 512
	uacAccountDisabled = 2
)

// accountNameRe is deliberately stricter than Active Directory's own rule.
// AD caps sAMAccountName at 20 characters and forbids /\[]:;|=,+*?<>@" — but
// this value also lands in a DN and a UPN, so anything with syntax in any of
// those three contexts is rejected rather than escaped.
var accountNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`)

// ListUsers returns accounts under the client's BaseDN, optionally narrowed by
// a search term matched against account name, display name and email.
//
// It is a convenience over Find; use Find directly to scope to a container or
// filter on enabled state.
func (c *Client) ListUsers(ctx context.Context, term string, limit int) ([]User, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	extra := ""
	if term = strings.TrimSpace(term); term != "" {
		e := ldap.EscapeFilter(term)
		extra = fmt.Sprintf("(|(sAMAccountName=*%s*)(displayName=*%s*)(mail=*%s*))", e, e, e)
	}

	res, err := c.search(conn, c.cfg.BaseDN, ldap.ScopeWholeSubtree,
		fmt.Sprintf(personFilter, extra), userAttrs, limit)
	if err != nil {
		return nil, fmt.Errorf("ListUsers: %w", err)
	}

	users := make([]User, 0, len(res.Entries))
	for _, e := range res.Entries {
		users = append(users, entryToUser(e))
	}
	return users, nil
}

// GetUser looks one account up by sAMAccountName.
func (c *Client) GetUser(ctx context.Context, accountName string) (*User, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return c.getUser(conn, accountName)
}

// getUser is the shared lookup. The writes reuse it to resolve the DN they are
// about to modify, so there is exactly one place that decides what "no such
// user" means.
//
// It searches from BaseDN rather than from the create container, because an
// account may live under any OU; a lookup scoped to the create container would
// fail to find most of the directory.
func (c *Client) getUser(conn *conn, accountName string) (*User, error) {
	if !accountNameRe.MatchString(accountName) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAccountName, accountName)
	}

	filter := fmt.Sprintf(personFilter, "(sAMAccountName="+ldap.EscapeFilter(accountName)+")")
	res, err := c.search(conn, c.cfg.BaseDN, ldap.ScopeWholeSubtree, filter, userAttrs, 2)
	if err != nil {
		return nil, fmt.Errorf("getUser %s: %w", accountName, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, accountName)
	}

	u := entryToUser(res.Entries[0])
	return &u, nil
}

// CreateUser adds an account and, when a password is supplied, sets it and
// enables the account in the same operation.
//
// The usual documented recipe for this is two steps — add the entry, then set
// unicodePwd over a second, encrypted connection — because that is what the
// ldapadd/ldapmodify command-line flow requires. Over a single LDAPS
// connection AD accepts unicodePwd in the add itself, so this is one round trip
// and there is no window in which a half-created, password-less account exists.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	account := strings.TrimSpace(req.AccountName)
	if !accountNameRe.MatchString(account) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAccountName, account)
	}

	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		return nil, ErrDisplayNameRequired
	}

	if req.Password != "" && !c.secure {
		return nil, ErrTLSRequired
	}

	parent := strings.TrimSpace(req.ParentDN)
	if parent == "" {
		parent = c.cfg.UsersDN
	}
	if parent == "" {
		return nil, fmt.Errorf("CreateUser %s: no ParentDN and no Config.UsersDN", account)
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// EscapeDN on the CN: display names contain commas ("Lovelace, Ada") and
	// plus signs, both of which are DN syntax and would otherwise build a DN
	// pointing somewhere else entirely.
	dn := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(display), parent)

	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"user"}) // AD fills in top/person/organizationalPerson
	add.Attribute("sAMAccountName", []string{account})
	add.Attribute("displayName", []string{display})
	if c.cfg.UPNSuffix != "" {
		add.Attribute("userPrincipalName", []string{account + "@" + c.cfg.UPNSuffix})
	}
	addOptional(add, "givenName", req.GivenName)
	addOptional(add, "sn", req.Surname)
	addOptional(add, "mail", req.Mail)
	addOptional(add, "title", req.Title)
	addOptional(add, "department", req.Department)
	addOptional(add, "physicalDeliveryOfficeName", req.Office)
	addOptional(add, "telephoneNumber", req.Phone)

	if req.Password != "" {
		add.Attribute("unicodePwd", []string{encodePassword(req.Password)})
		add.Attribute("userAccountControl", []string{strconv.Itoa(uacNormalAccount)})
	} else {
		// No password means the account must stay disabled — AD will not enable
		// an account that has none.
		add.Attribute("userAccountControl", []string{strconv.Itoa(uacNormalAccount | uacAccountDisabled)})
	}

	if err := conn.Add(add); err != nil {
		return nil, translateErr(err, "CreateUser "+account)
	}

	return c.getUser(conn, account)
}

// UpdateUser applies a partial edit and returns the account as the directory
// now holds it. Nil fields are left alone; a field set to the empty string
// clears that attribute.
func (c *Client) UpdateUser(ctx context.Context, accountName string, req UpdateUserRequest) (*User, error) {
	if req.Password != nil && *req.Password != "" && !c.secure {
		return nil, ErrTLSRequired
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Resolve the DN, and prove the account exists, before building the modify.
	current, err := c.getUser(conn, accountName)
	if err != nil {
		return nil, err
	}

	mod := ldap.NewModifyRequest(current.DN, nil)
	changes := 0
	changes += replaceOptional(mod, "displayName", req.DisplayName)
	changes += replaceOptional(mod, "givenName", req.GivenName)
	changes += replaceOptional(mod, "sn", req.Surname)
	changes += replaceOptional(mod, "mail", req.Mail)
	changes += replaceOptional(mod, "title", req.Title)
	changes += replaceOptional(mod, "department", req.Department)
	changes += replaceOptional(mod, "physicalDeliveryOfficeName", req.Office)
	changes += replaceOptional(mod, "telephoneNumber", req.Phone)

	if req.Password != nil && *req.Password != "" {
		mod.Replace("unicodePwd", []string{encodePassword(*req.Password)})
		changes++
	}

	if req.Enabled != nil {
		// Flip the disable bit on the value the entry already has, so unrelated
		// UAC flags survive the edit.
		uac := c.currentUAC(conn, current.DN)
		if *req.Enabled {
			uac &^= uacAccountDisabled
		} else {
			uac |= uacAccountDisabled
		}
		mod.Replace("userAccountControl", []string{strconv.Itoa(uac)})
		changes++
	}

	if changes == 0 {
		return nil, ErrNothingToUpdate
	}

	if err := conn.Modify(mod); err != nil {
		return nil, translateErr(err, "UpdateUser "+accountName)
	}

	return c.getUser(conn, accountName)
}

// SetPassword resets an account's password. Requires an ldaps:// connection.
func (c *Client) SetPassword(ctx context.Context, accountName, password string) error {
	if password == "" {
		return fmt.Errorf("SetPassword %s: password is empty", accountName)
	}
	_, err := c.UpdateUser(ctx, accountName, UpdateUserRequest{Password: &password})
	return err
}

// SetEnabled enables or disables an account, preserving the other
// userAccountControl flags.
func (c *Client) SetEnabled(ctx context.Context, accountName string, enabled bool) error {
	_, err := c.UpdateUser(ctx, accountName, UpdateUserRequest{Enabled: &enabled})
	return err
}

// DeleteUser removes an account.
func (c *Client) DeleteUser(ctx context.Context, accountName string) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	current, err := c.getUser(conn, accountName)
	if err != nil {
		return err
	}

	if err := conn.Del(ldap.NewDelRequest(current.DN, nil)); err != nil {
		return translateErr(err, "DeleteUser "+accountName)
	}
	return nil
}

// MoveUser moves an account into a different container, keeping its name.
//
// This is a ModifyDN, not an attribute write: an object's location in the tree
// IS its DN, so moving it means renaming it. The RDN is carried over unchanged
// and only the parent changes.
func (c *Client) MoveUser(ctx context.Context, accountName, newParentDN string) error {
	if strings.TrimSpace(newParentDN) == "" {
		return fmt.Errorf("MoveUser %s: newParentDN is empty", accountName)
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	current, err := c.getUser(conn, accountName)
	if err != nil {
		return err
	}

	rdn, _, err := splitDN(current.DN)
	if err != nil {
		return fmt.Errorf("MoveUser %s: %w", accountName, err)
	}

	// delOld=true: drop the old RDN attribute value, otherwise the entry keeps
	// the stale name alongside the new one.
	if err := conn.ModifyDN(ldap.NewModifyDNRequest(current.DN, rdn, true, newParentDN)); err != nil {
		return translateErr(err, "MoveUser "+accountName)
	}
	return nil
}

// RenameUser changes the CN of an account, keeping it in the same container.
//
// This is the rename that Active Directory Users and Computers performs when
// someone's name changes, and it is separate from UpdateUser for a reason: the
// CN is part of the DN, so this rewrites the account's DN, while displayName is
// an ordinary attribute. AD keeps the `name` attribute in step with the CN
// automatically; displayName, givenName and sn it does not. A full "this person
// changed their name" edit is therefore both calls:
//
//	client.RenameUser(ctx, "alovelace", "Ada King")
//	client.UpdateUser(ctx, "alovelace", ad.UpdateUserRequest{DisplayName: &name})
//
// sAMAccountName is untouched, so the account is still found by the same key
// afterwards.
func (c *Client) RenameUser(ctx context.Context, accountName, newCN string) error {
	newCN, err := validRDNValue(newCN, ErrInvalidName)
	if err != nil {
		return err
	}

	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	current, err := c.getUser(conn, accountName)
	if err != nil {
		return err
	}

	// newSup empty: keep the same parent, change only the RDN. delOld=true drops
	// the old cn value, otherwise the entry keeps both names.
	req := ldap.NewModifyDNRequest(current.DN, "CN="+ldap.EscapeDN(newCN), true, "")
	if err := conn.ModifyDN(req); err != nil {
		return translateErr(err, "RenameUser "+accountName)
	}
	return nil
}

// --- helpers ---

func addOptional(req *ldap.AddRequest, attr, val string) {
	if v := strings.TrimSpace(val); v != "" {
		req.Attribute(attr, []string{v})
	}
}

// replaceOptional returns 1 when it added a change, so the caller can reject an
// update that asked for nothing. A replace with no values is how LDAP spells
// "delete this attribute", which is what an explicit "" means here.
func replaceOptional(req *ldap.ModifyRequest, attr string, val *string) int {
	if val == nil {
		return 0
	}
	if v := strings.TrimSpace(*val); v != "" {
		req.Replace(attr, []string{v})
	} else {
		req.Replace(attr, []string{})
	}
	return 1
}

// currentUAC reads userAccountControl so a toggle can preserve the other flags.
// A failed read falls back to the plain normal-account value rather than
// failing the whole edit.
func (c *Client) currentUAC(conn *conn, dn string) int {
	res, err := c.search(conn, dn, ldap.ScopeBaseObject, "(objectClass=*)",
		[]string{"userAccountControl"}, 1)
	if err != nil || len(res.Entries) == 0 {
		return uacNormalAccount
	}
	uac, err := strconv.Atoi(res.Entries[0].GetAttributeValue("userAccountControl"))
	if err != nil {
		return uacNormalAccount
	}
	return uac
}

// encodePassword renders a password the way Active Directory requires
// unicodePwd to be written: wrapped in literal double quotes, encoded UTF-16
// little-endian. Get this wrong and accounts are created with a password
// nobody can bind with, which presents as a directory problem rather than an
// encoding bug.
func encodePassword(pw string) string {
	quoted := `"` + pw + `"`
	codes := utf16.Encode([]rune(quoted))
	buf := make([]byte, 2*len(codes))
	for i, c := range codes {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return string(buf)
}

func entryToUser(e *ldap.Entry) User {
	uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
	return User{
		AccountName: e.GetAttributeValue("sAMAccountName"),
		DN:          e.DN,
		DisplayName: e.GetAttributeValue("displayName"),
		GivenName:   e.GetAttributeValue("givenName"),
		Surname:     e.GetAttributeValue("sn"),
		Mail:        e.GetAttributeValue("mail"),
		Title:       e.GetAttributeValue("title"),
		Department:  e.GetAttributeValue("department"),
		Office:      e.GetAttributeValue("physicalDeliveryOfficeName"),
		Phone:       e.GetAttributeValue("telephoneNumber"),
		UPN:         e.GetAttributeValue("userPrincipalName"),
		Enabled:     uac&uacAccountDisabled == 0,
		GUID:        base64.StdEncoding.EncodeToString(e.GetRawAttributeValue("objectGUID")),
	}
}
