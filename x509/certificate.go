package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sync"
)

type Certificate struct {
	lock    sync.Mutex
	genuine x509.Certificate
	pem     []byte
}

func (c *Certificate) Pem() []byte {
	c.lock.Lock()
	defer c.lock.Unlock()
	if len(c.pem) == 0 {
		c.pem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.genuine.Raw,
		})
	}
	return c.pem
}

// ParseCertificate parses a certificate from either PEM or DER input. It
// first attempts to decode a PEM block; if one is found its bytes are treated as
// DER, otherwise the input is parsed as DER directly. The parsed certificate is
// wrapped so the typed extension accessors below can operate on it.
func ParseCertificate(in []byte) (*Certificate, error) {
	der := in
	if block, _ := pem.Decode(in); block != nil {
		der = block.Bytes
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509: parse certificate: %w", err)
	}
	return &Certificate{genuine: *parsed}, nil
}

// Genuine returns the underlying crypto/x509.Certificate. The returned value is
// a copy; callers must not rely on mutating it to affect this wrapper.
func (c *Certificate) Genuine() x509.Certificate {
	return c.genuine
}

// Extensions returns every X.509v3 extension carried by the certificate as a
// generic OID-keyed list. Values are the raw extension DER (the content
// inside the extension's OCTET STRING, i.e. pkix.Extension.Value). Order matches
// the certificate's encoding.
func (c *Certificate) Extensions() ([]Extension, error) {
	return extensionsFromPKIX(c.genuine.Extensions), nil
}

// SubjectAltName decodes the SubjectAltName extension (id-ce 17) into a typed SAN
// covering all nine GeneralName alternatives. It returns (nil, nil) when
// the certificate has no SubjectAltName extension.
func (c *Certificate) SubjectAltName() (*SAN, error) {
	return subjectAltNameFrom(c.genuine.Extensions)
}

// IssuerAltName decodes the IssuerAltName extension (id-ce 18) into a typed SAN.
// It returns (nil, nil) when the certificate has no IssuerAltName
// extension.
func (c *Certificate) IssuerAltName() (*SAN, error) {
	return issuerAltNameFrom(c.genuine.Extensions)
}

// extensionsFromPKIX converts a slice of pkix.Extension (as exposed by
// crypto/x509 for both certificates and CSRs) into the package's generic
// Extension view. It is the shared accessor backing Certificate.Extensions and
// CertificateRequest.Extensions.
func extensionsFromPKIX(in []pkix.Extension) []Extension {
	out := make([]Extension, 0, len(in))
	for _, e := range in {
		out = append(out, Extension{
			ID:       e.Id,
			Critical: e.Critical,
			Value:    append([]byte(nil), e.Value...),
		})
	}
	return out
}

// subjectAltNameFrom finds the SubjectAltName extension (OID 2.5.29.17) in the
// given extension slice and decodes it via ParseSAN. Returns (nil, nil) when
// absent.
func subjectAltNameFrom(exts []pkix.Extension) (*SAN, error) {
	for _, e := range exts {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return ParseSAN(e.Value)
		}
	}
	return nil, nil
}

// issuerAltNameFrom finds the IssuerAltName extension (OID 2.5.29.18) and decodes
// it via ParseIssuerAltName. Returns (nil, nil) when absent.
func issuerAltNameFrom(exts []pkix.Extension) (*SAN, error) {
	for _, e := range exts {
		if e.Id.Equal(oidExtensionIssuerAltName) {
			return ParseIssuerAltName(e.Value)
		}
	}
	return nil, nil
}

// MarshalExtension converts a generic Extension into a crypto/x509/pkix.Extension
// ready for injection into a template's ExtraExtensions during signing.
func (e Extension) MarshalExtension() pkix.Extension {
	return pkix.Extension{
		Id:       e.ID,
		Critical: e.Critical,
		Value:    append([]byte(nil), e.Value...),
	}
}

// MarshalSANExtension encodes a SAN into a SubjectAltName (id-ce 17)
// pkix.Extension. critical selects the extension's criticality (RFC 5280
// recommends non-critical when the subject DN is non-empty).
func MarshalSANExtension(s *SAN, critical bool) (pkix.Extension, error) {
	value, err := s.Marshal()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: critical,
		Value:    value,
	}, nil
}

// MarshalIssuerAltNameExtension encodes a SAN into an IssuerAltName (id-ce 18)
// pkix.Extension.
func MarshalIssuerAltNameExtension(s *SAN, critical bool) (pkix.Extension, error) {
	value, err := s.Marshal()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       oidExtensionIssuerAltName,
		Critical: critical,
		Value:    value,
	}, nil
}
