# go-ad

A small Active Directory client for Go: browse the OU tree, search for objects,
and create or edit users and organizational units.

It wraps [go-ldap](https://github.com/go-ldap/ldap) with the AD-specific details
that are easy to get wrong the first time — the `unicodePwd` encoding, the
`userAccountControl` bit field, the interaction between server-side size limits
and paged searches, and escaping values that end up inside DNs and filters.

One dependency (`go-ldap/ldap/v3`). Nothing here logs or reads the environment:
build a `Config`, hand it to `New`, and handle the returned errors however your
service already does.

## Install

```sh
go get go-ad
```

## Quick start

```go
client, err := ad.New(ad.Config{
    URL:           "ldaps://dc.example.com:636",
    BindDN:        "CN=directory-svc,OU=Service Accounts,DC=example,DC=com",
    BindPassword:  os.Getenv("AD_BIND_PW"),
    BaseDN:        "DC=example,DC=com",
    UsersDN:       "CN=Users,DC=example,DC=com",
    UPNSuffix:     "example.com",
})
if err != nil {
    return err
}

user, err := client.CreateUser(ctx, ad.CreateUserRequest{
    AccountName: "alovelace",
    DisplayName: "Ada Lovelace",
    GivenName:   "Ada",
    Surname:     "Lovelace",
    Mail:        "ada@example.com",
    Password:    "…",
    ParentDN:    "OU=Staff,DC=example,DC=com",
})
```

## What it does

**Browsing**

```go
root, _ := client.Tree(ctx)              // the whole OU hierarchy, one query
kids, _ := client.Children(ctx, dn)      // direct children of a container
obj,  _ := client.Get(ctx, dn)           // one object by DN
```

**Searching** — typed queries, with a raw filter as the escape hatch:

```go
enabled := true
objs, _ := client.Find(ctx, ad.Query{
    Term:    "lovelace",                  // matched against account name, display name, email, name
    Classes: []string{ad.ClassUser},
    Enabled: &enabled,
    Limit:   25,
})

// When Query cannot express it, write the filter yourself. Anything you
// interpolate must go through ldap.EscapeFilter first.
entries, _ := client.Search(ctx, baseDN, "(&(objectClass=group)(cn=sales*))", nil, 0)
```

**Users**

```go
client.ListUsers(ctx, term, limit)
client.GetUser(ctx, "alovelace")
client.CreateUser(ctx, req)
client.UpdateUser(ctx, "alovelace", req)   // partial; nil = leave alone, "" = clear
client.SetPassword(ctx, "alovelace", pw)
client.SetEnabled(ctx, "alovelace", false)
client.RenameUser(ctx, "alovelace", "Ada King")   // changes the CN, not displayName
client.MoveUser(ctx, "alovelace", newParentDN)
client.DeleteUser(ctx, "alovelace")
```

Renaming and editing are separate calls because they touch different things: the
CN is part of the DN, `displayName` is an ordinary attribute. A full "this
person changed their name" edit is both.

**Organizational units**

```go
client.ListOUs(ctx, parentDN)
client.CreateOU(ctx, parentDN, "Sales", "description")
client.RenameOU(ctx, dn, "Sales West")
client.MoveOU(ctx, dn, newParentDN)
client.DeleteOU(ctx, dn)                   // ErrNotEmpty if it still has children
```

Groups and group membership are not covered.

## Things worth knowing about Active Directory

These are the behaviours this package exists to absorb. They are documented
here because each one costs an afternoon the first time you meet it.

**Password writes need TLS.** AD refuses any write to `unicodePwd` over an
unencrypted connection. Over plain `ldap://` reads keep working while every
create-with-password and password reset fails, which is a confusing half-broken
state. `CreateUser` and `UpdateUser` return `ErrTLSRequired` up front rather than
letting the server answer with an opaque "unwilling to perform".

**`objectClass=user` includes computers.** A computer account is a subclass of
user, so a filter on `objectClass=user` returns every workstation in the domain
alongside the people. `objectCategory=person` is what separates them.

**`userAccountControl` is a bit field.** Enabling an account means clearing bit
2, not assigning 512. A blind assignment silently drops flags that were already
set on the entry, such as `DONT_EXPIRE_PASSWORD`. `SetEnabled` reads the current
value and flips the one bit.

**A search against a base DN that does not exist is an error, not an empty
result.** LDAP answers result 32, "no such object". A typo in a container name
therefore looks nothing like "nothing matched" — this package returns
`ErrNotFound` so the two stay distinguishable.

**Paged searches ignore size limits.** `SearchWithPaging` loops until the server
stops handing out cookies, so using it to fetch 5 entries pulls the entire
matching set across the wire. A small limit goes out as a server-side
`SizeLimit` instead; only a limit larger than one page uses the paging loop.

**Search your root, not your create container.** Accounts live all over the OU
tree. `CN=Users` typically holds only the built-ins, so scoping reads to the
container new accounts are created in hides almost the entire directory.

**Moving an object rewrites its DN, and every DN beneath it.** An object's
location in the tree *is* its DN, so `MoveOU` and `RenameOU` invalidate any DN
anyone else has cached — group memberships, another service's configuration.

**Escaping is not optional.** Values that reach a filter go through
`ldap.EscapeFilter`; values that reach a DN go through `ldap.EscapeDN`. Display
names routinely contain commas ("Lovelace, Ada"), which is DN syntax.

## Errors

Every failure a caller can branch on has a sentinel in `errors.go`; compare with
`errors.Is`. The underlying LDAP detail stays in the message.

`ErrDirectoryUnavailable`, `ErrTLSRequired`, `ErrNotFound`, `ErrUserNotFound`,
`ErrOUNotFound`, `ErrAlreadyExists`, `ErrInvalidAccountName`, `ErrInvalidName`, `ErrInvalidOUName`,
`ErrDisplayNameRequired`, `ErrNothingToUpdate`, `ErrPasswordRejected`,
`ErrNotEmpty`, `ErrInsufficientAccess`, `ErrWriteFailed`, `ErrConfigIncomplete`.

## Permissions

Creating and modifying accounts needs more than a read-only service account has;
AD answers with result 50, "insufficient access rights", surfaced here as
`ErrInsufficientAccess`. On a real domain controller this wants an account with
delegated rights on the target container — create and delete child objects, plus
Reset Password — rather than domain admin.

## Connections

`Client` is safe for concurrent use and holds no connection: each call dials,
binds, works and closes. Binds are cheap on a LAN and this is built for
interactive, low-rate traffic, so a pool would buy little while adding
stale-connection handling to every operation. Add one if this ever fronts a
batch job.

Public methods take a `context.Context` and honour it: go-ldap has no
per-operation context, so cancellation closes the socket, which is what actually
aborts an in-flight search.

## Tests

```sh
just test        # unit tests, no directory required
just test-live   # full write cycle against a real directory (see .env.test.example)
```

The live test creates a scratch OU, creates an account in it, proves the
password by binding as that account, exercises update / enable / disable / move,
and removes everything again — including on failure. It is skipped unless
`AD_TEST_URL` is set.
