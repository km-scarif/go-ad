package ad

import "errors"

// Every failure a caller can reasonably branch on gets a sentinel here, in one
// place. Callers compare with errors.Is. Errors that wrap one of these still
// carry the underlying LDAP detail in their message, so a caller can log the
// specifics while switching on the sentinel.

// ErrDirectoryUnavailable covers dial, TLS and bind failures — anything that
// means we never got far enough to ask the directory a question. It is
// deliberately one error rather than three: a caller can't do anything
// different about a refused connection than about a rejected bind.
var ErrDirectoryUnavailable = errors.New("directory is not available")

// ErrTLSRequired is returned when a password write is attempted over a
// non-TLS connection. Active Directory refuses to accept a write to unicodePwd
// on an unencrypted connection, so this is caught here rather than being sent
// and coming back as an opaque "unwilling to perform".
var ErrTLSRequired = errors.New("setting a password requires an ldaps:// connection")

var (
	ErrConfigIncomplete = errors.New("ad.Config needs URL, BindDN, BindPassword and BaseDN")
	ErrNotFound         = errors.New("no such object")
	ErrUserNotFound     = errors.New("no such user")
	ErrOUNotFound       = errors.New("no such organizational unit")
)

// ErrAlreadyExists is the directory refusing a second object at the same DN. A
// caller should treat this as a 409, not a 400 — the request is well-formed,
// the name is just taken.
var ErrAlreadyExists = errors.New("an object with that name already exists")

// ErrInvalidAccountName is wrapped with the offending value, because naming
// what was rejected is the point.
var ErrInvalidAccountName = errors.New("account name must be 1-20 characters of letters, digits, dot, dash or underscore")

var (
	// ErrInvalidName rejects a value that is about to become the naming part of
	// a DN. Characters with DN syntax are escaped rather than refused, so this
	// only fires on names the directory itself will not accept.
	ErrInvalidName         = errors.New("name must not be empty or contain a forward slash")
	ErrInvalidOUName       = errors.New("organizational unit name must not be empty, contain a forward slash, or have leading or trailing spaces")
	ErrDisplayNameRequired = errors.New("display name is required")
	ErrNothingToUpdate     = errors.New("no updatable fields in the request")
)

// ErrPasswordRejected is the directory's constraint violation on unicodePwd —
// too short, fails the complexity policy, or reuses a password from history.
var ErrPasswordRejected = errors.New("password rejected by the directory policy")

// ErrNotEmpty is returned instead of deleting a container that still has
// children. Active Directory answers this with notAllowedOnNonLeaf, which is
// easy to mistake for a permissions problem; more importantly, a delete that
// quietly does nothing is the worst possible outcome here.
var ErrNotEmpty = errors.New("container is not empty")

// ErrInsufficientAccess means the bind account is not allowed to do this. On a
// real domain controller this is the usual answer for a service account that
// was granted read but not write on the container.
var ErrInsufficientAccess = errors.New("insufficient access rights for this operation")

var ErrWriteFailed = errors.New("directory write failed")

// ErrBadFilter is a raw LDAP filter that does not parse. Caught before the
// search is sent, because the server's answer to a malformed filter is far
// less useful than saying which part did not compile.
var ErrBadFilter = errors.New("invalid LDAP filter")
