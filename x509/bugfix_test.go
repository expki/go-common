package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// newTestCertDER builds a minimal self-signed certificate and returns its raw DER.
func newTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bugfix-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// newTestCSRDER builds a minimal CSR and returns its raw DER.
func newTestCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bugfix-test"},
	}, key)
	if err != nil {
		t.Fatalf("create certificate request: %v", err)
	}
	return der
}

// TestCertificateWrapsCertificate guards the Step-0 fix that Certificate must
// embed a crypto/x509.Certificate (not a CertificateRequest). A real cert DER
// only parses as an x509.Certificate, so a successful parse + assignment proves
// the field type is correct.
func TestCertificateWrapsCertificate(t *testing.T) {
	der := newTestCertDER(t)
	genuine, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	// Assignment compiles only if the field type is x509.Certificate.
	c := &Certificate{genuine: *genuine}
	if c.genuine.Raw == nil {
		t.Fatal("genuine.Raw is nil")
	}
}

// TestCertificatePem verifies Pem() returns a correct, non-empty CERTIFICATE PEM
// block and that the encoded DER matches the certificate's raw bytes.
func TestCertificatePem(t *testing.T) {
	der := newTestCertDER(t)
	genuine, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	c := &Certificate{genuine: *genuine}

	out := c.Pem()
	if len(out) == 0 {
		t.Fatal("Pem() returned empty bytes")
	}
	block, rest := pem.Decode(out)
	if block == nil {
		t.Fatal("Pem() output is not a valid PEM block")
	}
	if len(rest) != 0 {
		t.Fatalf("trailing data after PEM block: %d bytes", len(rest))
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM type = %q, want CERTIFICATE", block.Type)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Fatal("PEM-encoded DER does not match certificate Raw bytes")
	}
}

// TestCertificatePemCaches verifies the cache guard is no longer inverted:
// the first call populates the cache and repeated calls return the same bytes.
func TestCertificatePemCaches(t *testing.T) {
	der := newTestCertDER(t)
	genuine, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	c := &Certificate{genuine: *genuine}

	first := c.Pem()
	if len(first) == 0 {
		t.Fatal("first Pem() call returned empty bytes")
	}
	// Mutate the source so a non-cached recompute would differ; the cached
	// value must be returned unchanged.
	c.genuine.Raw = nil
	second := c.Pem()
	if !bytes.Equal(first, second) {
		t.Fatal("Pem() did not return cached bytes on second call")
	}
}

// TestCertificateRequestPem verifies the CSR wrapper emits a correct,
// non-empty CERTIFICATE REQUEST PEM block.
func TestCertificateRequestPem(t *testing.T) {
	der := newTestCSRDER(t)
	genuine, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse certificate request: %v", err)
	}
	c := &CertificateRequest{genuine: *genuine}

	out := c.Pem()
	if len(out) == 0 {
		t.Fatal("Pem() returned empty bytes")
	}
	block, rest := pem.Decode(out)
	if block == nil {
		t.Fatal("Pem() output is not a valid PEM block")
	}
	if len(rest) != 0 {
		t.Fatalf("trailing data after PEM block: %d bytes", len(rest))
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("PEM type = %q, want CERTIFICATE REQUEST", block.Type)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Fatal("PEM-encoded DER does not match request Raw bytes")
	}
}

// TestCertificateRequestPemCaches verifies the CSR cache guard is no longer
// inverted: repeated calls return the cached bytes.
func TestCertificateRequestPemCaches(t *testing.T) {
	der := newTestCSRDER(t)
	genuine, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse certificate request: %v", err)
	}
	c := &CertificateRequest{genuine: *genuine}

	first := c.Pem()
	if len(first) == 0 {
		t.Fatal("first Pem() call returned empty bytes")
	}
	c.genuine.Raw = nil
	second := c.Pem()
	if !bytes.Equal(first, second) {
		t.Fatal("Pem() did not return cached bytes on second call")
	}
}
