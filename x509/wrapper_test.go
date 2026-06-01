package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// makeTestCertDER builds a self-signed certificate (via stdlib) carrying a
// SubjectAltName with a DNS name, an IP address, and an email (rfc822Name), plus
// BasicConstraints and KeyUsage, and returns its DER. This is used only as a
// convenient, self-consistent input for the wrapper accessors; the byte-exact
// corpus tests live in roundtrip_test.go.
func makeTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "wrapper.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.IPv4(192, 0, 2, 1)},
		EmailAddresses:        []string{"admin@example.com"},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestParseCertificateDERAndPEM(t *testing.T) {
	der := makeTestCertDER(t)

	// DER path.
	cDER, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(DER): %v", err)
	}
	if cDER.Genuine().Subject.CommonName != "wrapper.test" {
		t.Errorf("DER subject CN = %q, want wrapper.test", cDER.Genuine().Subject.CommonName)
	}

	// PEM path.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cPEM, err := ParseCertificate(pemBytes)
	if err != nil {
		t.Fatalf("ParseCertificate(PEM): %v", err)
	}
	if cPEM.Genuine().Subject.CommonName != "wrapper.test" {
		t.Errorf("PEM subject CN = %q, want wrapper.test", cPEM.Genuine().Subject.CommonName)
	}

	// Pem() round-trips and caches.
	out := cDER.Pem()
	if block, _ := pem.Decode(out); block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("Pem() did not produce a CERTIFICATE block")
	}
}

func TestCertificateSubjectAltName(t *testing.T) {
	der := makeTestCertDER(t)
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	san, err := c.SubjectAltName()
	if err != nil {
		t.Fatalf("SubjectAltName: %v", err)
	}
	if san == nil {
		t.Fatal("SubjectAltName returned nil, want a SAN")
	}

	var dns []string
	var ips []string
	var emails []string
	for _, n := range san.Names {
		switch v := n.(type) {
		case DNSName:
			dns = append(dns, string(v))
		case IPAddressName:
			ips = append(ips, v.IP.String())
		case RFC822Name:
			emails = append(emails, string(v))
		}
	}
	if len(dns) != 2 || dns[0] != "example.com" || dns[1] != "www.example.com" {
		t.Errorf("DNS names = %v, want [example.com www.example.com]", dns)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Errorf("IP names = %v, want [192.0.2.1]", ips)
	}
	if len(emails) != 1 || emails[0] != "admin@example.com" {
		t.Errorf("email names = %v, want [admin@example.com]", emails)
	}
}

func TestCertificateNoSubjectAltName(t *testing.T) {
	// A cert with no SAN must return (nil, nil), not an error.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "no-san.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	san, err := c.SubjectAltName()
	if err != nil {
		t.Fatalf("SubjectAltName: %v", err)
	}
	if san != nil {
		t.Errorf("SubjectAltName = %+v, want nil for a cert with no SAN", san)
	}
}

func TestCertificateExtensions(t *testing.T) {
	der := makeTestCertDER(t)
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	exts, err := c.Extensions()
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	if len(exts) == 0 {
		t.Fatal("Extensions returned empty, want at least SAN/KeyUsage/BasicConstraints")
	}

	// The SAN, KeyUsage, and BasicConstraints extensions must all be listed.
	var sawSAN, sawKU, sawBC bool
	for _, e := range exts {
		switch {
		case e.ID.Equal(oidExtensionSubjectAltName):
			sawSAN = true
		case e.ID.Equal(oidExtensionKeyUsage):
			sawKU = true
		case e.ID.Equal(oidExtensionBasicConstraints):
			sawBC = true
		}
		if len(e.Value) == 0 {
			t.Errorf("extension %v has empty value", e.ID)
		}
	}
	if !sawSAN || !sawKU || !sawBC {
		t.Errorf("Extensions missing one of SAN/KU/BC: san=%v ku=%v bc=%v", sawSAN, sawKU, sawBC)
	}
}

func TestMarshalSANExtensionRoundTrip(t *testing.T) {
	// Build a SAN, marshal to pkix.Extension, then re-parse via the accessor path.
	san := &SAN{Names: GeneralNames{
		DNSName("example.org"),
		RFC822Name("user@example.org"),
		IPAddressName{IP: net.IPv4(203, 0, 113, 5).To4()},
	}}

	ext, err := MarshalSANExtension(san, false)
	if err != nil {
		t.Fatalf("MarshalSANExtension: %v", err)
	}
	if !ext.Id.Equal(oidExtensionSubjectAltName) {
		t.Errorf("ext.Id = %v, want SubjectAltName OID", ext.Id)
	}
	if ext.Critical {
		t.Errorf("ext.Critical = true, want false")
	}

	// Re-decode the marshalled value via ParseSAN and confirm the names survive.
	got, err := ParseSAN(ext.Value)
	if err != nil {
		t.Fatalf("ParseSAN(marshalled): %v", err)
	}
	if len(got.Names) != 3 {
		t.Fatalf("re-parsed SAN has %d names, want 3", len(got.Names))
	}
	if d, ok := got.Names[0].(DNSName); !ok || string(d) != "example.org" {
		t.Errorf("name[0] = %#v, want DNSName(example.org)", got.Names[0])
	}
	if r, ok := got.Names[1].(RFC822Name); !ok || string(r) != "user@example.org" {
		t.Errorf("name[1] = %#v, want RFC822Name(user@example.org)", got.Names[1])
	}
	if ip, ok := got.Names[2].(IPAddressName); !ok || ip.IP.String() != "203.0.113.5" {
		t.Errorf("name[2] = %#v, want IPAddressName(203.0.113.5)", got.Names[2])
	}
}

func TestExtensionMarshalExtension(t *testing.T) {
	e := Extension{ID: oidExtensionKeyUsage, Critical: true, Value: []byte{0x03, 0x02, 0x05, 0xA0}}
	pe := e.MarshalExtension()
	if !pe.Id.Equal(oidExtensionKeyUsage) || !pe.Critical {
		t.Errorf("MarshalExtension lost ID/critical: %+v", pe)
	}
	if len(pe.Value) != len(e.Value) {
		t.Errorf("MarshalExtension value len = %d, want %d", len(pe.Value), len(e.Value))
	}
	// Ensure the returned Value is a copy, not aliased to the source.
	pe.Value[0] = 0xFF
	if e.Value[0] == 0xFF {
		t.Errorf("MarshalExtension aliased the source Value slice")
	}
}
