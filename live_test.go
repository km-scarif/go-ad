package ad

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// The live test exercises the write path against a real directory, because the
// things most likely to be wrong here — the unicodePwd encoding, the
// userAccountControl bit arithmetic, ModifyDN semantics — cannot be proven
// against a fake. It is skipped unless AD_TEST_URL is set, so `go test ./...`
// stays runnable with nothing else installed.
//
//	AD_TEST_URL=ldaps://127.0.0.1:636 \
//	AD_TEST_BIND_DN='CN=Administrator,CN=Users,DC=example,DC=com' \
//	AD_TEST_BIND_PW='...' \
//	AD_TEST_BASE_DN='DC=example,DC=com' \
//	AD_TEST_UPN_SUFFIX=example.com \
//	AD_TEST_SKIP_VERIFY=1 \
//	GODEBUG=x509negativeserial=1 \
//	go test -run Live -v ./...
//
// Everything it creates is namespaced under a scratch OU and removed again,
// including on failure.
func liveClient(t *testing.T) *Client {
	t.Helper()

	url := os.Getenv("AD_TEST_URL")
	if url == "" {
		t.Skip("AD_TEST_URL is not set; skipping live directory test")
	}

	cfg := Config{
		URL:           url,
		BindDN:        os.Getenv("AD_TEST_BIND_DN"),
		BindPassword:  os.Getenv("AD_TEST_BIND_PW"),
		BaseDN:        os.Getenv("AD_TEST_BASE_DN"),
		UPNSuffix:     os.Getenv("AD_TEST_UPN_SUFFIX"),
		TLSSkipVerify: os.Getenv("AD_TEST_SKIP_VERIFY") != "",
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v (set AD_TEST_BIND_DN, AD_TEST_BIND_PW and AD_TEST_BASE_DN)", err)
	}
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	return c
}

func TestLiveReadOnly(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()

	root, err := c.Tree(ctx)
	if err != nil {
		t.Fatalf("Tree: %v", err)
	}
	if root.DN != c.BaseDN() {
		t.Errorf("tree root DN = %q, want %q", root.DN, c.BaseDN())
	}
	t.Logf("tree: %d top-level OUs, %d OUs total", len(root.Children), countNodes(root)-1)

	children, err := c.Children(ctx, c.BaseDN())
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if len(children) == 0 {
		t.Fatal("Children of the base DN returned nothing")
	}
	// Containers sort ahead of leaves, so if anything can hold children the
	// first entry must.
	for _, o := range children {
		if o.HasChildren && !children[0].HasChildren {
			t.Error("containers did not sort before leaves")
			break
		}
	}

	// A limit must be honoured server-side, not by truncating a full fetch.
	limited, err := c.Find(ctx, Query{Classes: []string{ClassUser}, Limit: 5})
	if err != nil {
		t.Fatalf("Find with limit: %v", err)
	}
	if len(limited) > 5 {
		t.Errorf("Find(limit 5) returned %d objects", len(limited))
	}
	for _, o := range limited {
		if o.Class != ClassUser {
			t.Errorf("user search returned a %s: %s", o.Class, o.DN)
		}
	}

	// A search base that does not exist is an LDAP error, not an empty result.
	// Callers reasonably expect the opposite, so it is worth pinning down.
	if _, err := c.Children(ctx, "OU=definitely-not-here,"+c.BaseDN()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Children of a missing container: got %v, want ErrNotFound", err)
	}
}

func TestLiveWriteCycle(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()

	stamp := time.Now().UnixNano()
	ouName := fmt.Sprintf("go-ad-test-%d", stamp)
	destName := ouName + "-dest"
	account := fmt.Sprintf("gadt%d", stamp%100000000) // <= 20 chars, matches accountNameRe
	password := fmt.Sprintf("T3st!%d-Aa", stamp%10000)

	// Cleanup runs in reverse creation order and ignores "already gone", so a
	// failure part-way through still leaves the directory as it was found.
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_ = c.DeleteUser(ctx, account)
		_ = c.DeleteOU(ctx, "OU="+destName+","+c.BaseDN())
		_ = c.DeleteOU(ctx, "OU="+ouName+","+c.BaseDN())
	})

	// --- create the scratch OU ---
	ou, err := c.CreateOU(ctx, c.BaseDN(), ouName, "created by go-ad tests")
	if err != nil {
		t.Fatalf("CreateOU: %v", err)
	}
	if _, err := c.CreateOU(ctx, c.BaseDN(), ouName, ""); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("duplicate CreateOU: got %v, want ErrAlreadyExists", err)
	}

	// --- create a user in it, with a password ---
	user, err := c.CreateUser(ctx, CreateUserRequest{
		AccountName: account,
		DisplayName: "Go AD Test " + account,
		GivenName:   "Go",
		Surname:     "Test",
		Mail:        account + "@example.invalid",
		Title:       "Fixture",
		Password:    password,
		ParentDN:    ou.DN,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !user.Enabled {
		t.Error("account created with a password is disabled; expected enabled")
	}
	if user.AccountName != account {
		t.Errorf("account name = %q, want %q", user.AccountName, account)
	}

	// The real proof that unicodePwd landed correctly: bind as the new account.
	// Every other check would pass just as well if the encoding were wrong.
	if c.cfg.UPNSuffix != "" {
		if err := canBind(c, account+"@"+c.cfg.UPNSuffix, password); err != nil {
			t.Errorf("cannot bind as the new account (unicodePwd encoding?): %v", err)
		}
	}

	// --- partial update leaves untouched attributes alone ---
	newTitle := "Fixture, Updated"
	updated, err := c.UpdateUser(ctx, account, UpdateUserRequest{Title: &newTitle})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.Title != newTitle {
		t.Errorf("title = %q, want %q", updated.Title, newTitle)
	}
	if updated.Mail != user.Mail {
		t.Errorf("unrelated attribute changed: mail %q -> %q", user.Mail, updated.Mail)
	}
	if updated.GivenName != user.GivenName {
		t.Errorf("unrelated attribute changed: givenName %q -> %q", user.GivenName, updated.GivenName)
	}

	if _, err := c.UpdateUser(ctx, account, UpdateUserRequest{}); !errors.Is(err, ErrNothingToUpdate) {
		t.Errorf("empty update: got %v, want ErrNothingToUpdate", err)
	}

	// --- clearing an attribute is distinct from leaving it alone ---
	empty := ""
	cleared, err := c.UpdateUser(ctx, account, UpdateUserRequest{Title: &empty})
	if err != nil {
		t.Fatalf("UpdateUser clearing title: %v", err)
	}
	if cleared.Title != "" {
		t.Errorf("title after clearing = %q, want empty", cleared.Title)
	}

	// --- enable/disable round trip ---
	if err := c.SetEnabled(ctx, account, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if got, _ := c.GetUser(ctx, account); got != nil && got.Enabled {
		t.Error("account still enabled after SetEnabled(false)")
	}
	if err := c.SetEnabled(ctx, account, true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if got, _ := c.GetUser(ctx, account); got != nil && !got.Enabled {
		t.Error("account still disabled after SetEnabled(true)")
	}

	// --- password reset, proven by binding again ---
	rotated := password + "-2"
	if err := c.SetPassword(ctx, account, rotated); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if c.cfg.UPNSuffix != "" {
		if err := canBind(c, account+"@"+c.cfg.UPNSuffix, rotated); err != nil {
			t.Errorf("cannot bind after SetPassword: %v", err)
		}
	}

	// --- the account is findable by search ---
	found, err := c.Find(ctx, Query{Term: account, Classes: []string{ClassUser}})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(found) != 1 || found[0].AccountName != account {
		t.Errorf("Find(%q) returned %d objects, want exactly the test account", account, len(found))
	}

	// --- OU description edit, and rename keeping the OU in place ---
	desc := "renamed by go-ad tests"
	if err := c.UpdateOU(ctx, ou.DN, UpdateOURequest{Description: &desc}); err != nil {
		t.Fatalf("UpdateOU: %v", err)
	}
	if ous, err := c.ListOUs(ctx, c.BaseDN()); err == nil {
		found := false
		for _, o := range ous {
			if canonicalDN(o.DN) == canonicalDN(ou.DN) {
				found = true
				if o.Description != desc {
					t.Errorf("OU description = %q, want %q", o.Description, desc)
				}
			}
		}
		if !found {
			t.Errorf("the scratch OU is missing from ListOUs(%s)", c.BaseDN())
		}
	}
	if err := c.UpdateOU(ctx, ou.DN, UpdateOURequest{}); !errors.Is(err, ErrNothingToUpdate) {
		t.Errorf("empty UpdateOU: got %v, want ErrNothingToUpdate", err)
	}

	// --- rename changes the DN but not the key the account is found by ---
	newCN := "Go AD Renamed " + account
	if err := c.RenameUser(ctx, account, newCN); err != nil {
		t.Fatalf("RenameUser: %v", err)
	}
	renamed, err := c.GetUser(ctx, account)
	if err != nil {
		t.Fatalf("GetUser after rename: %v", err)
	}
	if rdn, parent, _ := splitDN(renamed.DN); rdn != "cn="+newCN {
		t.Errorf("after rename the RDN is %q, want %q", rdn, "cn="+newCN)
	} else if canonicalDN(parent) != canonicalDN(ou.DN) {
		t.Errorf("rename moved the account to %q; it should have stayed under %q", parent, ou.DN)
	}
	// displayName is an ordinary attribute and is deliberately NOT carried along
	// by the rename — the two are separate calls.
	if renamed.DisplayName != user.DisplayName {
		t.Errorf("rename changed displayName %q -> %q; it should be untouched",
			user.DisplayName, renamed.DisplayName)
	}

	// --- a non-empty OU refuses to be deleted ---
	if err := c.DeleteOU(ctx, ou.DN); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("DeleteOU on a non-empty OU: got %v, want ErrNotEmpty", err)
	}

	// --- move the user to a second OU ---
	dest, err := c.CreateOU(ctx, c.BaseDN(), destName, "")
	if err != nil {
		t.Fatalf("CreateOU (destination): %v", err)
	}
	if err := c.MoveUser(ctx, account, dest.DN); err != nil {
		t.Fatalf("MoveUser: %v", err)
	}
	moved, err := c.GetUser(ctx, account)
	if err != nil {
		t.Fatalf("GetUser after move: %v", err)
	}
	if _, parent, _ := splitDN(moved.DN); canonicalDN(parent) != canonicalDN(dest.DN) {
		t.Errorf("after move the account is at %q, want it under %q", moved.DN, dest.DN)
	}

	// The source OU is empty now, so it deletes cleanly.
	if err := c.DeleteOU(ctx, ou.DN); err != nil {
		t.Errorf("DeleteOU on the now-empty source OU: %v", err)
	}

	// --- delete the user ---
	if err := c.DeleteUser(ctx, account); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := c.GetUser(ctx, account); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetUser after delete: got %v, want ErrUserNotFound", err)
	}
	if err := c.DeleteOU(ctx, dest.DN); err != nil {
		t.Errorf("DeleteOU on the destination OU: %v", err)
	}
}

// canBind opens a separate connection and binds as the given identity. It uses
// the client's transport settings but none of its credentials.
func canBind(c *Client, upn, password string) error {
	conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: c.cfg.TLSSkipVerify,
	}))
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(upn, password)
}

func countNodes(n *TreeNode) int {
	total := 1
	for _, child := range n.Children {
		total += countNodes(child)
	}
	return total
}
