package x509

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
)

type CertificateRequest struct {
	lock    sync.Mutex
	genuine x509.CertificateRequest
	pem     []byte
}

func (c *CertificateRequest) Pem() []byte {
	c.lock.Lock()
	defer c.lock.Unlock()
	if len(c.pem) == 0 {
		c.pem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: c.genuine.Raw,
		})
	}
	return c.pem
}

// ParseCertificateRequest parses a PKCS#10 certificate request from either PEM or
// DER input. It first attempts to decode a PEM block; if one is found its
// bytes are treated as DER, otherwise the input is parsed as DER directly.
func ParseCertificateRequest(in []byte) (*CertificateRequest, error) {
	der := in
	if block, _ := pem.Decode(in); block != nil {
		der = block.Bytes
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("x509: parse certificate request: %w", err)
	}
	return &CertificateRequest{genuine: *parsed}, nil
}

// Genuine returns the underlying crypto/x509.CertificateRequest. The returned
// value is a copy.
func (c *CertificateRequest) Genuine() x509.CertificateRequest {
	return c.genuine
}

// Extensions returns the requested X.509v3 extensions carried by the CSR as a
// generic OID-keyed list. For a CSR these live in the parsed request's
// Extensions field (the attributes-derived extensions crypto/x509 surfaces).
func (c *CertificateRequest) Extensions() ([]Extension, error) {
	return extensionsFromPKIX(c.genuine.Extensions), nil
}

// SubjectAltName decodes the requested SubjectAltName extension (id-ce 17) into a
// typed SAN. Returns (nil, nil) when the CSR has no SubjectAltName.
func (c *CertificateRequest) SubjectAltName() (*SAN, error) {
	return subjectAltNameFrom(c.genuine.Extensions)
}

// IssuerAltName decodes a requested IssuerAltName extension (id-ce 18) into a
// typed SAN. Returns (nil, nil) when absent. (An IssuerAltName in a CSR is
// unusual but the accessor is provided for symmetry and completeness.)
func (c *CertificateRequest) IssuerAltName() (*SAN, error) {
	return issuerAltNameFrom(c.genuine.Extensions)
}
