package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// e2e_test.go builds a certificate / CSR with typed extensions through the
// builder, then re-accesses those extensions through this package's wrapper
// accessors (ParseCertificate + SubjectAltName/Extensions) and asserts the field
// values survive the build→parse→re-access round-trip. builder_test.go already
// re-parses via stdlib across RSA/ECDSA/Ed25519; this test exercises the
// wrapper-accessor path the builder feeds into.

func e2eKeys(t *testing.T) []struct {
	name   string
	signer crypto.PrivateKey
	pub    any
} {
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
	return []struct {
		name   string
		signer crypto.PrivateKey
		pub    any
	}{
		{"RSA2048", rsaKey, &rsaKey.PublicKey},
		{"ECDSAP256", ecKey, &ecKey.PublicKey},
		{"Ed25519", edPriv, edPub},
	}
}

func TestBuildThenWrapperAccessors(t *testing.T) {
	for _, k := range e2eKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			// A multi-type SAN exercises arms beyond the stdlib DNS/IP subset.
			san := &SAN{Names: GeneralNames{
				DNSName("e2e.example.com"),
				RFC822Name("e2e@example.com"),
				IPAddressName{IP: net.IPv4(198, 51, 100, 7).To4()},
				URIName("https://e2e.example.com/x"),
			}}
			sanVal, err := san.Marshal()
			if err != nil {
				t.Fatalf("SAN.Marshal: %v", err)
			}
			kuVal, err := (KeyUsageDigitalSignature | KeyUsageCRLSign).Marshal()
			if err != nil {
				t.Fatalf("KeyUsage.Marshal: %v", err)
			}
			exts := []Extension{
				{ID: oidExtensionKeyUsage, Critical: true, Value: kuVal},
				{ID: oidExtensionSubjectAltName, Critical: false, Value: sanVal},
			}

			tmpl := &stdx509.Certificate{
				SerialNumber: big.NewInt(2024),
				Subject:      pkix.Name{CommonName: "e2e-build"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
			}
			built, err := BuildCertificate(CertificateOptions{
				Template:   tmpl,
				Parent:     tmpl,
				PublicKey:  k.pub,
				SignerKey:  k.signer,
				Extensions: exts,
			})
			if err != nil {
				t.Fatalf("BuildCertificate: %v", err)
			}

			// Re-access through the wrapper: parse the built cert's PEM and read
			// the SAN back through our typed accessor.
			parsed, err := ParseCertificate(built.Pem())
			if err != nil {
				t.Fatalf("ParseCertificate(built.Pem()): %v", err)
			}
			gotSAN, err := parsed.SubjectAltName()
			if err != nil {
				t.Fatalf("SubjectAltName: %v", err)
			}
			if gotSAN == nil {
				t.Fatal("SubjectAltName returned nil after build")
			}
			assertSANNamesEqual(t, gotSAN.Names, san.Names)

			// Extensions() must list the SAN and KeyUsage we embedded.
			all, err := parsed.Extensions()
			if err != nil {
				t.Fatalf("Extensions: %v", err)
			}
			var sawSAN, sawKU bool
			for _, e := range all {
				if e.ID.Equal(oidExtensionSubjectAltName) {
					sawSAN = true
				}
				if e.ID.Equal(oidExtensionKeyUsage) {
					sawKU = true
					if !e.Critical {
						t.Errorf("KeyUsage extension should be critical")
					}
				}
			}
			if !sawSAN || !sawKU {
				t.Errorf("re-accessed extensions missing SAN(%v)/KU(%v)", sawSAN, sawKU)
			}
		})
	}
}

func TestBuildCSRThenWrapperAccessors(t *testing.T) {
	for _, k := range e2eKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			san := &SAN{Names: GeneralNames{
				DNSName("csr.example.com"),
				RFC822Name("csr@example.com"),
			}}
			sanVal, err := san.Marshal()
			if err != nil {
				t.Fatalf("SAN.Marshal: %v", err)
			}
			exts := []Extension{{ID: oidExtensionSubjectAltName, Critical: false, Value: sanVal}}

			tmpl := &stdx509.CertificateRequest{Subject: pkix.Name{CommonName: "e2e-csr"}}
			built, err := BuildCertificateRequest(CertificateRequestOptions{
				Template:   tmpl,
				SignerKey:  k.signer,
				Extensions: exts,
			})
			if err != nil {
				t.Fatalf("BuildCertificateRequest: %v", err)
			}

			parsed, err := ParseCertificateRequest(built.Pem())
			if err != nil {
				t.Fatalf("ParseCertificateRequest(built.Pem()): %v", err)
			}
			gotSAN, err := parsed.SubjectAltName()
			if err != nil {
				t.Fatalf("SubjectAltName: %v", err)
			}
			if gotSAN == nil {
				t.Fatal("CSR SubjectAltName returned nil after build")
			}
			assertSANNamesEqual(t, gotSAN.Names, san.Names)
		})
	}
}

// assertSANNamesEqual compares two GeneralNames slices by their concrete arm
// types and primitive values (sufficient for the primitive arms used in E2E).
func assertSANNamesEqual(t *testing.T, got, want GeneralNames) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("SAN name count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		switch w := want[i].(type) {
		case DNSName:
			g, ok := got[i].(DNSName)
			if !ok || g != w {
				t.Errorf("name[%d] = %#v, want DNSName(%s)", i, got[i], w)
			}
		case RFC822Name:
			g, ok := got[i].(RFC822Name)
			if !ok || g != w {
				t.Errorf("name[%d] = %#v, want RFC822Name(%s)", i, got[i], w)
			}
		case URIName:
			g, ok := got[i].(URIName)
			if !ok || g != w {
				t.Errorf("name[%d] = %#v, want URIName(%s)", i, got[i], w)
			}
		case IPAddressName:
			g, ok := got[i].(IPAddressName)
			if !ok || !g.IP.Equal(w.IP) {
				t.Errorf("name[%d] = %#v, want IPAddressName(%s)", i, got[i], w.IP)
			}
		default:
			t.Errorf("name[%d]: unhandled want type %T", i, want[i])
		}
	}
}
