package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testKey is a signer plus its public key, for the per-algorithm build matrix.
type testKey struct {
	name   string
	signer crypto.PrivateKey
	pub    any
}

// buildMatrixKeys returns one key per required algorithm: RSA-2048,
// ECDSA-P256, Ed25519.
func buildMatrixKeys(t *testing.T) []testKey {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return []testKey{
		{"RSA2048", rsaKey, &rsaKey.PublicKey},
		{"ECDSAP256", ecKey, &ecKey.PublicKey},
		{"Ed25519", edPriv, edPub},
	}
}

// sampleExtensions returns a representative typed-extension set with distinct
// OIDs: KeyUsage (id-ce 15), BasicConstraints (id-ce 19), ExtKeyUsage (id-ce
// 37), and SubjectAltName (id-ce 17) carrying a DNS name.
func sampleExtensions(t *testing.T) []Extension {
	t.Helper()

	kuVal, err := (KeyUsageDigitalSignature | KeyUsageKeyEncipherment).Marshal()
	if err != nil {
		t.Fatalf("KeyUsage.Marshal: %v", err)
	}
	bc := &BasicConstraints{IsCA: true, PathLen: 1, PathLenValid: true}
	bcVal, err := bc.Marshal()
	if err != nil {
		t.Fatalf("BasicConstraints.Marshal: %v", err)
	}
	eku := ExtKeyUsage{oidExtKeyUsageServerAuth()}
	ekuVal, err := eku.Marshal()
	if err != nil {
		t.Fatalf("ExtKeyUsage.Marshal: %v", err)
	}
	san := &SAN{Names: GeneralNames{DNSName("example.com")}}
	sanVal, err := san.Marshal()
	if err != nil {
		t.Fatalf("SAN.Marshal: %v", err)
	}

	return []Extension{
		{ID: oidExtensionKeyUsage, Critical: true, Value: kuVal},
		{ID: oidExtensionBasicConstraints, Critical: true, Value: bcVal},
		{ID: oidExtensionExtendedKeyUsage, Critical: false, Value: ekuVal},
		{ID: oidExtensionSubjectAltName, Critical: false, Value: sanVal},
	}
}

// oidExtKeyUsageServerAuth is the serverAuth EKU purpose OID, declared here for
// the test (the package does not export EKU purpose OIDs).
func oidExtKeyUsageServerAuth() []int { return []int{1, 3, 6, 1, 5, 5, 7, 3, 1} }

func TestBuildCertificate(t *testing.T) {
	for _, k := range buildMatrixKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			exts := sampleExtensions(t)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(42),
				Subject:      pkix.Name{CommonName: "build-cert-test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
			}
			cert, err := BuildCertificate(CertificateOptions{
				Template:   tmpl,
				Parent:     tmpl, // self-signed
				PublicKey:  k.pub,
				SignerKey:  k.signer,
				Extensions: exts,
			})
			if err != nil {
				t.Fatalf("BuildCertificate: %v", err)
			}

			// Re-parse via crypto/x509 (independent of our wrapper).
			reparsed, err := x509.ParseCertificate(cert.genuine.Raw)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			assertExtensionsRoundTrip(t, reparsed.Extensions, exts)
			assertOneInstancePerOID(t, reparsed.Extensions)

			// PEM is available and well-formed.
			if !bytes.Contains(cert.Pem(), []byte("BEGIN CERTIFICATE")) {
				t.Fatal("Pem() missing CERTIFICATE block")
			}
		})
	}
}

func TestBuildCertificateRequest(t *testing.T) {
	for _, k := range buildMatrixKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			// CSRs cannot carry BasicConstraints-as-cert-field meaningfully via
			// stdlib auto-fields, but ExtraExtensions are embedded verbatim in the
			// CSR attributes; use the SAN + KeyUsage + EKU subset.
			all := sampleExtensions(t)
			exts := []Extension{all[0], all[2], all[3]} // KeyUsage, EKU, SAN
			tmpl := &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "build-csr-test"},
			}
			csr, err := BuildCertificateRequest(CertificateRequestOptions{
				Template:   tmpl,
				SignerKey:  k.signer,
				Extensions: exts,
			})
			if err != nil {
				t.Fatalf("BuildCertificateRequest: %v", err)
			}

			reparsed, err := x509.ParseCertificateRequest(csr.genuine.Raw)
			if err != nil {
				t.Fatalf("re-parse CSR: %v", err)
			}
			if err := reparsed.CheckSignature(); err != nil {
				t.Fatalf("CSR signature invalid: %v", err)
			}
			assertExtensionsRoundTrip(t, reparsed.Extensions, exts)
			assertOneInstancePerOID(t, reparsed.Extensions)

			if !bytes.Contains(csr.Pem(), []byte("BEGIN CERTIFICATE REQUEST")) {
				t.Fatal("Pem() missing CERTIFICATE REQUEST block")
			}
		})
	}
}

// TestDuplicateOID verifies the de-dup guard rejects an assembled set with
// two extensions sharing an OID.
func TestDuplicateOID(t *testing.T) {
	kuVal, err := KeyUsageDigitalSignature.Marshal()
	if err != nil {
		t.Fatalf("KeyUsage.Marshal: %v", err)
	}
	dup := []Extension{
		{ID: oidExtensionKeyUsage, Critical: true, Value: kuVal},
		{ID: oidExtensionKeyUsage, Critical: false, Value: kuVal},
	}
	if _, err := toPKIXExtensions(dup); err == nil {
		t.Fatal("toPKIXExtensions accepted duplicate OID; want ErrDuplicateExtension")
	}

	// And the guard surfaces through the public builder entry point.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "dup-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if _, err := BuildCertificate(CertificateOptions{
		Template:   tmpl,
		Parent:     tmpl,
		PublicKey:  &key.PublicKey,
		SignerKey:  key,
		Extensions: dup,
	}); err == nil {
		t.Fatal("BuildCertificate accepted duplicate OID; want error")
	}
}

// assertExtensionsRoundTrip checks every supplied typed extension reappears in
// the parsed extension list with identical Value bytes and Critical flag.
func assertExtensionsRoundTrip(t *testing.T, got []pkix.Extension, want []Extension) {
	t.Helper()
	for _, w := range want {
		var match *pkix.Extension
		for i := range got {
			if got[i].Id.Equal(w.ID) {
				match = &got[i]
				break
			}
		}
		if match == nil {
			t.Fatalf("extension %s missing from parsed certificate", w.ID)
		}
		if match.Critical != w.Critical {
			t.Fatalf("extension %s Critical = %v, want %v", w.ID, match.Critical, w.Critical)
		}
		if !bytes.Equal(match.Value, w.Value) {
			t.Fatalf("extension %s Value mismatch:\n got %x\nwant %x", w.ID, match.Value, w.Value)
		}
	}
}

// assertOneInstancePerOID fails if any OID appears more than once.
func assertOneInstancePerOID(t *testing.T, exts []pkix.Extension) {
	t.Helper()
	seen := make(map[string]int)
	for _, e := range exts {
		seen[e.Id.String()]++
	}
	for oid, n := range seen {
		if n > 1 {
			t.Fatalf("OID %s appears %d times; want exactly 1", oid, n)
		}
	}
}
