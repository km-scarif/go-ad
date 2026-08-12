module github.com/km-scarif/go-ad

go 1.25.0

require github.com/go-ldap/ldap/v3 v3.4.14

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
)

// v0.1.0 was tagged before the module path move and declares `module go-ad`,
// so it fails to resolve as github.com/km-scarif/go-ad. The public proxy has
// it cached permanently; this is what hides it from `go list -m -versions`.
retract v0.1.0
