package x509

import (
	"bytes"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"net/url"
	"sort"
	"testing"
)

// These tests use OpenSSL as an independent oracle. The fixtures in testdata/
// (openssl_cert.der, openssl_csr.der) are produced by gen_openssl_fixtures.sh
// and carry every X.509v3 extension OpenSSL emits natively that this package
// also models. OpenSSL builds the DER from its own model, so decoding and
// re-encoding it byte-for-byte is evidence we agree with a real implementation
// rather than only with our own encoder.

// extensionRoundTrippers maps each supported extension OID to a parse→marshal
// round-trip. Every extension OpenSSL can emit must appear here, otherwise
// assertEveryExtensionRoundTrips fails on the unhandled OID.
func extensionRoundTrippers() map[string]func([]byte) ([]byte, error) {
	return map[string]func([]byte) ([]byte, error){
		oidExtensionKeyUsage.String(): func(v []byte) ([]byte, error) {
			x, err := ParseKeyUsage(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionBasicConstraints.String(): func(v []byte) ([]byte, error) {
			x, err := ParseBasicConstraints(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionExtendedKeyUsage.String(): func(v []byte) ([]byte, error) {
			x, err := ParseExtKeyUsage(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionSubjectKeyIdentifier.String(): func(v []byte) ([]byte, error) {
			x, err := ParseSubjectKeyIdentifier(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionAuthorityKeyIdentifier.String(): func(v []byte) ([]byte, error) {
			x, err := ParseAuthorityKeyIdentifier(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionSubjectAltName.String(): func(v []byte) ([]byte, error) {
			x, err := ParseSAN(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionIssuerAltName.String(): func(v []byte) ([]byte, error) {
			x, err := ParseIssuerAltName(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionNameConstraints.String(): func(v []byte) ([]byte, error) {
			x, err := ParseNameConstraints(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionCertificatePolicies.String(): func(v []byte) ([]byte, error) {
			x, err := ParseCertificatePolicies(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionPolicyMappings.String(): func(v []byte) ([]byte, error) {
			x, err := ParsePolicyMappings(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionPolicyConstraints.String(): func(v []byte) ([]byte, error) {
			x, err := ParsePolicyConstraints(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionInhibitAnyPolicy.String(): func(v []byte) ([]byte, error) {
			x, err := ParseInhibitAnyPolicy(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionCRLDistributionPoints.String(): func(v []byte) ([]byte, error) {
			x, err := ParseCRLDistributionPoints(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionFreshestCRL.String(): func(v []byte) ([]byte, error) {
			x, err := ParseFreshestCRL(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionAuthorityInfoAccess.String(): func(v []byte) ([]byte, error) {
			x, err := ParseInfoAccess(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionSubjectInfoAccess.String(): func(v []byte) ([]byte, error) {
			x, err := ParseInfoAccess(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
		oidExtensionSubjectDirectoryAttrs.String(): func(v []byte) ([]byte, error) {
			x, err := ParseSubjectDirectoryAttributes(v)
			if err != nil {
				return nil, err
			}
			return x.Marshal()
		},
	}
}

// assertEveryExtensionRoundTrips requires that every extension in the list is one
// this package models and re-encodes byte-exact against its original DER. An
// unhandled OID is a failure, so the oracle corpus can never silently outgrow our
// coverage. It returns the set of OIDs seen for presence assertions.
func assertEveryExtensionRoundTrips(t *testing.T, exts []Extension) map[string]bool {
	t.Helper()
	rt := extensionRoundTrippers()
	seen := make(map[string]bool, len(exts))
	for _, e := range exts {
		key := e.ID.String()
		seen[key] = true
		fn, ok := rt[key]
		if !ok {
			t.Errorf("extension %s is present but not modeled by this package", key)
			continue
		}
		out, err := fn(e.Value)
		if err != nil {
			t.Errorf("extension %s: parse/marshal failed: %v", key, err)
			continue
		}
		if !bytes.Equal(out, e.Value) {
			t.Errorf("extension %s not byte-exact:\n got  %x\n want %x", key, out, e.Value)
		}
	}
	return seen
}

func assertPresent(t *testing.T, seen map[string]bool, want ...asn1.ObjectIdentifier) {
	t.Helper()
	for _, oid := range want {
		if !seen[oid.String()] {
			t.Errorf("expected extension %s in fixture but it was absent", oid)
		}
	}
}

func TestOpenSSLCertificateExtensionsRoundTrip(t *testing.T) {
	der := readCorpus(t, "openssl_cert.der")

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	exts, err := cert.Extensions()
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}

	seen := assertEveryExtensionRoundTrips(t, exts)

	// Guard against a regenerated-but-thin corpus: the interesting extensions
	// must actually be there, or the round-trip would pass vacuously.
	assertPresent(t, seen,
		oidExtensionKeyUsage, oidExtensionBasicConstraints, oidExtensionExtendedKeyUsage,
		oidExtensionSubjectKeyIdentifier, oidExtensionAuthorityKeyIdentifier,
		oidExtensionSubjectAltName, oidExtensionIssuerAltName, oidExtensionNameConstraints,
		oidExtensionCertificatePolicies, oidExtensionPolicyConstraints,
		oidExtensionInhibitAnyPolicy, oidExtensionCRLDistributionPoints,
		oidExtensionFreshestCRL, oidExtensionAuthorityInfoAccess,
	)

	// The PEM path must decode to the same certificate.
	certPEM, err := ParseCertificate(readCorpus(t, "openssl_cert.pem"))
	if err != nil {
		t.Fatalf("ParseCertificate(PEM): %v", err)
	}
	if !bytes.Equal(certPEM.Genuine().Raw, cert.Genuine().Raw) {
		t.Errorf("PEM and DER parse paths disagree on certificate bytes")
	}
}

// TestOpenSSLCertificateSANMatchesStdlib decodes the SubjectAltName two ways —
// through this package and through crypto/x509 — and requires the overlapping
// GeneralName types to agree exactly. This catches misinterpretation that a
// pure round-trip (which replays raw bytes) would not: the typed projection must
// match an independent decoder. It also confirms we surface the three SAN arms
// the standard library silently drops.
func TestOpenSSLCertificateSANMatchesStdlib(t *testing.T) {
	der := readCorpus(t, "openssl_cert.der")

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	san, err := cert.SubjectAltName()
	if err != nil {
		t.Fatalf("SubjectAltName: %v", err)
	}
	if san == nil {
		t.Fatal("SubjectAltName returned nil")
	}

	std, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("stdlib ParseCertificate: %v", err)
	}

	var dns, emails, uris, ips []string
	var sawOtherName, sawDirName, sawRID bool
	for _, n := range san.Names {
		switch v := n.(type) {
		case DNSName:
			dns = append(dns, string(v))
		case RFC822Name:
			emails = append(emails, string(v))
		case URIName:
			uris = append(uris, string(v))
		case IPAddressName:
			ips = append(ips, v.IP.String())
		case OtherName:
			sawOtherName = true
		case DirectoryName:
			sawDirName = true
		case RegisteredID:
			sawRID = true
		}
	}

	assertSameStrings(t, "DNS", dns, std.DNSNames)
	assertSameStrings(t, "email", emails, std.EmailAddresses)
	assertSameStrings(t, "URI", uris, urlStrings(std.URIs))
	assertSameStrings(t, "IP", ips, ipStrings(std))

	// crypto/x509 cannot represent these arms; this package does.
	if !sawOtherName {
		t.Error("SAN missing otherName arm (stdlib drops it; we should not)")
	}
	if !sawDirName {
		t.Error("SAN missing directoryName arm")
	}
	if !sawRID {
		t.Error("SAN missing registeredID arm")
	}
}

func TestOpenSSLCSRExtensionsRoundTrip(t *testing.T) {
	der := readCorpus(t, "openssl_csr.der")

	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	exts, err := csr.Extensions()
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}

	seen := assertEveryExtensionRoundTrips(t, exts)
	assertPresent(t, seen,
		oidExtensionBasicConstraints, oidExtensionKeyUsage,
		oidExtensionExtendedKeyUsage, oidExtensionSubjectAltName,
	)

	// Cross-check the requested SAN against the stdlib CSR parser.
	san, err := csr.SubjectAltName()
	if err != nil {
		t.Fatalf("SubjectAltName: %v", err)
	}
	if san == nil {
		t.Fatal("CSR SubjectAltName returned nil")
	}
	std, err := stdx509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("stdlib ParseCertificateRequest: %v", err)
	}

	var dns, emails, uris, ips []string
	for _, n := range san.Names {
		switch v := n.(type) {
		case DNSName:
			dns = append(dns, string(v))
		case RFC822Name:
			emails = append(emails, string(v))
		case URIName:
			uris = append(uris, string(v))
		case IPAddressName:
			ips = append(ips, v.IP.String())
		}
	}
	assertSameStrings(t, "CSR DNS", dns, std.DNSNames)
	assertSameStrings(t, "CSR email", emails, std.EmailAddresses)
	assertSameStrings(t, "CSR URI", uris, urlStrings(std.URIs))
	assertSameStrings(t, "CSR IP", ips, csrIPStrings(std))
}

// assertSameStrings compares two string sets regardless of order.
func assertSameStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) != len(w) {
		t.Errorf("%s: got %v, want %v", label, g, w)
		return
	}
	for i := range g {
		if g[i] != w[i] {
			t.Errorf("%s: got %v, want %v", label, g, w)
			return
		}
	}
}

func urlStrings(us []*url.URL) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	return out
}

func ipStrings(c *stdx509.Certificate) []string {
	out := make([]string, len(c.IPAddresses))
	for i, ip := range c.IPAddresses {
		out[i] = ip.String()
	}
	return out
}

func csrIPStrings(c *stdx509.CertificateRequest) []string {
	out := make([]string, len(c.IPAddresses))
	for i, ip := range c.IPAddresses {
		out[i] = ip.String()
	}
	return out
}
