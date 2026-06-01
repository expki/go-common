package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
)

// builder.go constructs and signs certificates and CSRs that embed this
// package's typed extensions, delegating all cryptographic work (signing, key
// handling, template defaults) to crypto/x509. We never re-implement signing or
// certificate templating; we only assemble the typed-extension set, guarantee
// exactly one extension per OID, and route every typed extension through
// crypto/x509's ExtraExtensions so the standard library does not also auto-emit a
// duplicate.
//
// This matters because CreateCertificate appends ExtraExtensions verbatim with no
// intra-slice de-dup, and its template auto-fields (KeyUsage, BasicConstraintsValid,
// DNSNames, …) are only suppressed when the matching OID is already present in
// ExtraExtensions. So the contract a caller must follow — and which
// BuildCertificate/BuildCertificateRequest enforce — is: supply each extension
// exactly once as a typed Extension, and do not also set the stdlib template's
// auto-field for that extension. The de-dup guard rejects an assembled set that
// contains the same OID twice.

// ErrDuplicateExtension is returned when the assembled extension set contains
// more than one extension with the same OID. crypto/x509 would otherwise emit
// both verbatim, producing a malformed certificate.
var ErrDuplicateExtension = errors.New("x509: duplicate extension OID in builder set")

// toPKIXExtensions converts the typed, OID-keyed Extension list into the
// pkix.Extension slice crypto/x509 consumes, enforcing exactly-one-per-OID. The
// order of exts is preserved in the output. A nil or empty Value is allowed
// (some extensions legitimately encode to an empty SEQUENCE); only duplicate
// OIDs are rejected.
func toPKIXExtensions(exts []Extension) ([]pkix.Extension, error) {
	out := make([]pkix.Extension, 0, len(exts))
	seen := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		if len(e.ID) == 0 {
			return nil, fmt.Errorf("%w: empty OID", ErrUnexpectedTag)
		}
		key := e.ID.String()
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateExtension, key)
		}
		seen[key] = struct{}{}
		out = append(out, pkix.Extension{
			Id:       asnOIDCopy(e.ID),
			Critical: e.Critical,
			Value:    append([]byte(nil), e.Value...),
		})
	}
	return out, nil
}

// asnOIDCopy returns a defensive copy of an OID so the caller cannot mutate the
// slice we hand to crypto/x509 after the fact.
func asnOIDCopy(oid []int) []int {
	cp := make([]int, len(oid))
	copy(cp, oid)
	return cp
}

// CertificateOptions carries everything BuildCertificate needs beyond the typed
// extensions. The Template is a crypto/x509.Certificate used for the non-
// extension fields (SerialNumber, Subject, validity, …). To avoid duplicate
// emission, leave the template's extension auto-fields (KeyUsage, ExtKeyUsage,
// BasicConstraintsValid, DNSNames, IPAddresses, etc.) ZERO when you supply the
// corresponding typed Extension — the typed extension is authoritative.
type CertificateOptions struct {
	// Template provides the certificate's non-extension fields. Its
	// ExtraExtensions are overwritten by the assembled typed-extension set.
	Template *x509.Certificate
	// Parent is the issuing certificate. For a self-signed certificate pass the
	// same template value as Parent.
	Parent *x509.Certificate
	// PublicKey is the subject's public key to be certified.
	PublicKey any
	// SignerKey is the issuer's (CA's) private key used to sign.
	SignerKey crypto.PrivateKey
	// Extensions are this package's typed extensions, each already marshaled to
	// its Extension{ID, Critical, Value} form. Exactly one per OID.
	Extensions []Extension
}

// BuildCertificate constructs and signs an X.509 certificate embedding the
// supplied typed extensions, returning a wrapped *Certificate. Signing is
// delegated to crypto/x509.CreateCertificate. The typed extensions are
// routed through ExtraExtensions with an exactly-one-per-OID guard.
func BuildCertificate(opts CertificateOptions) (*Certificate, error) {
	if opts.Template == nil {
		return nil, errors.New("x509: BuildCertificate: nil Template")
	}
	if opts.Parent == nil {
		return nil, errors.New("x509: BuildCertificate: nil Parent")
	}
	pkixExts, err := toPKIXExtensions(opts.Extensions)
	if err != nil {
		return nil, err
	}

	// Work on a shallow copy so the caller's template is not mutated, then route
	// all typed extensions through ExtraExtensions. We intentionally do not also
	// populate stdlib auto-fields; the caller is responsible for leaving them
	// unset when a typed equivalent is supplied (documented on CertificateOptions).
	tmpl := *opts.Template
	tmpl.ExtraExtensions = pkixExts

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, opts.Parent, opts.PublicKey, opts.SignerKey)
	if err != nil {
		return nil, fmt.Errorf("x509: create certificate: %w", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509: re-parse created certificate: %w", err)
	}
	return &Certificate{genuine: *parsed}, nil
}

// CertificateRequestOptions carries everything BuildCertificateRequest needs
// beyond the typed extensions. As with CertificateOptions, leave the template's
// extension auto-fields (DNSNames, IPAddresses, …) zero when you supply the
// corresponding typed Extension.
type CertificateRequestOptions struct {
	// Template provides the CSR's non-extension fields (Subject, etc.). Its
	// ExtraExtensions are overwritten by the assembled typed-extension set.
	Template *x509.CertificateRequest
	// SignerKey is the subject's private key used to sign the CSR.
	SignerKey crypto.PrivateKey
	// Extensions are this package's typed extensions. Exactly one per OID.
	Extensions []Extension
}

// BuildCertificateRequest constructs and signs a PKCS#10 CSR embedding the
// supplied typed extensions, returning a wrapped *CertificateRequest. Signing is
// delegated to crypto/x509.CreateCertificateRequest. The typed extensions
// are routed through ExtraExtensions with an exactly-one-per-OID guard.
func BuildCertificateRequest(opts CertificateRequestOptions) (*CertificateRequest, error) {
	if opts.Template == nil {
		return nil, errors.New("x509: BuildCertificateRequest: nil Template")
	}
	pkixExts, err := toPKIXExtensions(opts.Extensions)
	if err != nil {
		return nil, err
	}

	tmpl := *opts.Template
	tmpl.ExtraExtensions = pkixExts

	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, opts.SignerKey)
	if err != nil {
		return nil, fmt.Errorf("x509: create certificate request: %w", err)
	}

	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("x509: re-parse created certificate request: %w", err)
	}
	return &CertificateRequest{genuine: *parsed}, nil
}
