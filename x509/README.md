# x509

The X.509 extensions the standard library leaves on the floor. `crypto/x509` parses a certificate's Subject Alternative Names but only hands you DNS names and IPs — the other seven SAN types and most extension bodies are just opaque bytes. This package decodes **all nine** SAN types and **every** RFC 5280 §4.2 extension into real Go values, and re-encodes them **byte-for-byte identically**.

```go
cert, _ := x509.ParseCertificate(pemBytes)

san, _ := cert.SubjectAltName()
for _, name := range san.Names {
	switch n := name.(type) {
	case x509.DNSName:
		fmt.Println("dns:", string(n))
	case x509.RFC822Name:
		fmt.Println("email:", string(n))
	case x509.OtherName:
		fmt.Println("otherName:", n.TypeID) // e.g. a UPN
	}
}
```

It wraps `crypto/x509` rather than replacing it — the standard library still does all the parsing, chain building, and signing. This package owns the ASN.1 of the extensions it exposes, and only that.

## What you actually get

| | Standard `crypto/x509` | This package |
| --- | --- | --- |
| SAN: dNSName, iPAddress | ✅ | ✅ |
| SAN: rfc822Name, URI, registeredID | strings only, no re-encode | ✅ typed |
| SAN: otherName, x400Address, directoryName, ediPartyName | ❌ opaque | ✅ fully typed |
| §4.2 extensions (KeyUsage, NameConstraints, policies, AIA, …) | typed fields, can't rebuild arbitrary ones | ✅ parse + marshal |
| Byte-exact decode → encode round-trip | ❌ | ✅ |
| Build + sign with custom typed extensions | via raw `ExtraExtensions` | ✅ typed |

All nine `GeneralName` alternatives are real types behind one `GeneralName` interface: `OtherName`, `RFC822Name`, `DNSName`, `X400Address`, `DirectoryName`, `EDIPartyName`, `URIName`, `IPAddressName`, `RegisteredID`.

## Install

```sh
go get github.com/expki/go-common/x509
```

## Parsing

`ParseCertificate` and `ParseCertificateRequest` take **PEM or DER** — they sniff for a PEM block and fall back to raw DER.

```go
cert, err := x509.ParseCertificate(in)   // *x509.Certificate
if err != nil {
	panic(err)
}

cert.Pem()                  // []byte, PEM re-encoded (cached)
cert.Genuine()              // the underlying crypto/x509.Certificate
exts, _ := cert.Extensions()        // []Extension — every extension, OID + critical + raw value
san, _  := cert.SubjectAltName()    // *SAN, or (nil, nil) if absent
ian, _  := cert.IssuerAltName()     // *SAN
```

`CertificateRequest` (a CSR) has the same accessors.

### Decoding a specific extension

`Extensions()` gives you the OID-tagged list; feed any value into the matching `Parse*` to get a typed struct.

```go
for _, e := range exts {
	switch {
	case e.ID.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}): // KeyUsage
		ku, _ := x509.ParseKeyUsage(e.Value)
		if ku&x509.KeyUsageKeyCertSign != 0 {
			fmt.Println("this is a CA-signing key")
		}
	case e.ID.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}): // NameConstraints
		nc, _ := x509.ParseNameConstraints(e.Value)
		_ = nc
	}
}
```

Parsers cover the whole §4.2 set: `ParseKeyUsage`, `ParseBasicConstraints`, `ParseExtKeyUsage`, `ParseSubjectKeyIdentifier`, `ParseAuthorityKeyIdentifier`, `ParseSubjectAltName`, `ParseNameConstraints`, `ParseCertificatePolicies`, `ParsePolicyMappings`, `ParsePolicyConstraints`, `ParseInhibitAnyPolicy`, `ParseCRLDistributionPoints`, `ParseFreshestCRL`, `ParseInfoAccess` (AIA/SIA), `ParseSubjectDirectoryAttributes`. Each typed value has a matching `Marshal()` back to extension-value DER.

## Byte-exact round-trip

Decoding then re-encoding gives you the **exact same bytes** — even for the cases the standard library mangles. The classic one: a Subject DN encoded as `TeletexString` round-trips back through `pkix.RDNSequence` as `PrintableString`, changing the bytes (and breaking any signature over them). Here it doesn't.

```go
san, _ := x509.ParseSAN(extValue)
out, _ := san.Marshal()
bytes.Equal(out, extValue) // true
```

This works because every CHOICE-of-string leaf keeps the raw DER it was decoded from and replays it verbatim — unless you change the typed value, in which case it re-encodes canonically.

## Building and signing

`BuildCertificate` and `BuildCertificateRequest` take a `crypto/x509` template plus your typed extensions, route them through `ExtraExtensions`, and sign — delegating the actual signing to the standard library. Works with RSA, ECDSA, and Ed25519 keys.

```go
ku, _ := (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyCertSign).Marshal()
san, _ := (&x509.SAN{Names: x509.GeneralNames{
	x509.DNSName("example.com"),
	x509.RFC822Name("admin@example.com"),
}}).Marshal()

cert, err := x509.BuildCertificate(x509.CertificateOptions{
	Template:   template,   // *crypto/x509.Certificate (validity, serial, subject…)
	Parent:     caCert,     // same as Template for self-signed
	PublicKey:  subjectPub,
	SignerKey:  caPriv,
	Extensions: []x509.Extension{
		{ID: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: ku},
		{ID: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san},
	},
})
```

The builder enforces **exactly one extension per OID** — supplying a duplicate is an error. When you pass a typed extension, leave the template's auto-field for it zero (e.g. don't set `template.DNSNames` if you supply a typed SAN), or the standard library would emit a second copy.

## Notes

### iPAddress means two different things

In a SAN, `iPAddress` is a bare 4- or 16-byte address. In `NameConstraints` it's an 8- or 32-byte value: address followed by a mask. `IPAddressName` carries a `NameConstraints` flag and a `Validate()` that rejects the wrong shape for its context, so you can't accidentally encode an invalid one. Parsing threads the context for you — SAN parsers produce bare addresses, NameConstraints parsers produce address+mask.

### otherName / x400Address / ediPartyName are fully modeled

These rare types are decoded into complete typed structures (`OtherName`, the full X.400 `ORAddress`, `EDIPartyName`), not preserved as blobs — and they still round-trip byte-exact. `otherName`'s inner value (an `ANY DEFINED BY`) is kept as raw bytes because that's what it genuinely is.

### Errors, not panics

Every parser is written to reject malformed DER with a sentinel error (`ErrTruncated`, `ErrUnexpectedTag`, `ErrTrailingData`) — never a panic — and rejects trailing garbage. It's fuzz-tested against adversarial input, so it's safe to point at untrusted certificates.

## Building

Pure Go (standard library plus [`golang.org/x/crypto/cryptobyte`](https://pkg.go.dev/golang.org/x/crypto/cryptobyte)), no cgo. Builds anywhere Go does, including both wasm targets.

```sh
go build ./...                            # native (host)
GOOS=js GOARCH=wasm go build ./x509/      # browser
GOOS=wasip1 GOARCH=wasm go build ./x509/  # WASI
GOOS=windows GOARCH=amd64 go build ./x509/
```

The normative reference for everything here is [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.txt), a copy of which lives in this directory.
