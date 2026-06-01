package x509

import (
	"bytes"
	stdx509 "crypto/x509"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// roundtrip_test.go verifies byte-exactness against an externally sourced corpus
// that is NOT produced by this package's own builder
// (avoiding circular self-certification). The corpus in testdata/ is:
//
//	multisan_leaf.der      — a real openssl-generated ECDSA leaf with a multi-type
//	                         SubjectAltName (DNS, IP, email, URI).
//	teletex_dn.der         — a real openssl cert whose Subject DN uses TeletexString
//	                         (T61String) — the case that breaks naive RDNSequence
//	                         re-encoding.
//	bmp_dn.der             — a real openssl cert whose Subject DN uses BMPString.
//	othername_upn_san.der  — a hand-built GeneralNames value with an otherName/UPN.
//	x400address_san.der    — a hand-built GeneralNames value with an x400Address.
//	nameconstraints_ip8.der— a hand-built NameConstraints value with an 8-byte
//	                         (addr+mask) iPAddress.
//
// Each test decodes the relevant structure with THIS package and asserts the
// re-encoded DER is byte-identical to the corpus input.

func readCorpus(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read corpus %s: %v", name, err)
	}
	return b
}

// extractExtensionValue parses a certificate DER and returns the raw value bytes
// of the extension with the given OID (pkix.Extension.Value).
func extractExtensionValue(t *testing.T, certDER []byte, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	cert, err := stdx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse corpus certificate: %v", err)
	}
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	t.Fatalf("certificate has no extension %v", oid)
	return nil
}

func TestRoundTripMultiSANLeaf(t *testing.T) {
	der := readCorpus(t, "multisan_leaf.der")
	sanValue := extractExtensionValue(t, der, oidExtensionSubjectAltName)

	san, err := ParseSAN(sanValue)
	if err != nil {
		t.Fatalf("ParseSAN: %v", err)
	}

	// Sanity: the multi-type SAN decoded into several distinct arms.
	if len(san.Names) < 4 {
		t.Errorf("expected >=4 SAN names (DNS x2, IP, email, URI), got %d", len(san.Names))
	}

	out, err := san.Marshal()
	if err != nil {
		t.Fatalf("SAN.Marshal: %v", err)
	}
	if !bytes.Equal(out, sanValue) {
		t.Errorf("multi-SAN leaf not byte-exact:\n got %x\nwant %x", out, sanValue)
	}
}

// directoryNameArmFromRawDN wraps a raw Name (RDNSequence) DER — e.g. a cert's
// RawSubject — into a directoryName [4] GeneralName element TLV, the shape the
// dispatcher hands parseDirectoryName.
func directoryNameArmTLV(t *testing.T, rawName []byte) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(c *cryptobyte.Builder) {
		c.AddBytes(rawName)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("wrap directoryName: %v", err)
	}
	return out
}

func directoryNameByteExact(t *testing.T, corpus string) {
	t.Helper()
	der := readCorpus(t, corpus)
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse corpus certificate: %v", err)
	}
	// The Subject DN carries the Teletex/BMP string. Wrap RawSubject as a
	// directoryName[4] arm and round-trip it through our DirectoryName decode/
	// encode — the captured-raw replay must reproduce the bytes exactly.
	armTLV := directoryNameArmTLV(t, cert.RawSubject)

	in := cryptobyte.String(armTLV)
	var content cryptobyte.String
	if !in.ReadASN1(&content, cbasn1.Tag(4).ContextSpecific().Constructed()) {
		t.Fatalf("strip [4] tag failed")
	}
	d, err := parseDirectoryName(content)
	if err != nil {
		t.Fatalf("parseDirectoryName: %v", err)
	}

	b := cryptobyte.NewBuilder(nil)
	if err := d.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("builder.Bytes: %v", err)
	}
	if !bytes.Equal(out, armTLV) {
		t.Errorf("%s directoryName not byte-exact:\n got %x\nwant %x", corpus, out, armTLV)
	}
}

func TestRoundTripTeletexDN(t *testing.T) { directoryNameByteExact(t, "teletex_dn.der") }
func TestRoundTripBMPDN(t *testing.T)     { directoryNameByteExact(t, "bmp_dn.der") }

func TestRoundTripOtherNameUPN(t *testing.T) {
	value := readCorpus(t, "othername_upn_san.der")
	san, err := ParseSAN(value)
	if err != nil {
		t.Fatalf("ParseSAN: %v", err)
	}
	if len(san.Names) != 1 {
		t.Fatalf("expected 1 name, got %d", len(san.Names))
	}
	on, ok := san.Names[0].(OtherName)
	if !ok {
		t.Fatalf("name[0] = %#v, want OtherName", san.Names[0])
	}
	if !on.TypeID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}) {
		t.Errorf("otherName type-id = %v, want MS UPN", on.TypeID)
	}

	out, err := san.Marshal()
	if err != nil {
		t.Fatalf("SAN.Marshal: %v", err)
	}
	if !bytes.Equal(out, value) {
		t.Errorf("otherName/UPN SAN not byte-exact:\n got %x\nwant %x", out, value)
	}
}

func TestRoundTripX400AddressSAN(t *testing.T) {
	value := readCorpus(t, "x400address_san.der")
	san, err := ParseSAN(value)
	if err != nil {
		t.Fatalf("ParseSAN: %v", err)
	}
	if len(san.Names) != 1 {
		t.Fatalf("expected 1 name, got %d", len(san.Names))
	}
	x, ok := san.Names[0].(X400Address)
	if !ok {
		t.Fatalf("name[0] = %#v, want X400Address", san.Names[0])
	}
	if x.ORAddress.BuiltInStandard.CountryName == nil ||
		x.ORAddress.BuiltInStandard.CountryName.Value.Value != "US" {
		t.Errorf("x400Address country-name = %+v, want US", x.ORAddress.BuiltInStandard.CountryName)
	}

	out, err := san.Marshal()
	if err != nil {
		t.Fatalf("SAN.Marshal: %v", err)
	}
	if !bytes.Equal(out, value) {
		t.Errorf("x400Address SAN not byte-exact:\n got %x\nwant %x", out, value)
	}
}

func TestRoundTripNameConstraintsIP8(t *testing.T) {
	value := readCorpus(t, "nameconstraints_ip8.der")
	nc, err := ParseNameConstraints(value)
	if err != nil {
		t.Fatalf("ParseNameConstraints: %v", err)
	}
	if len(nc.Permitted) != 1 {
		t.Fatalf("expected 1 permitted subtree, got %d", len(nc.Permitted))
	}
	ip, ok := nc.Permitted[0].Base.(IPAddressName)
	if !ok {
		t.Fatalf("base = %#v, want IPAddressName", nc.Permitted[0].Base)
	}
	if !ip.NameConstraints {
		t.Errorf("iPAddress NameConstraints flag = false, want true (8-byte addr+mask)")
	}
	if ip.IP.String() != "192.0.2.0" {
		t.Errorf("iPAddress = %v, want 192.0.2.0", ip.IP)
	}
	if len(ip.Mask) != 4 {
		t.Errorf("iPAddress mask len = %d, want 4", len(ip.Mask))
	}

	out, err := nc.Marshal()
	if err != nil {
		t.Fatalf("NameConstraints.Marshal: %v", err)
	}
	if !bytes.Equal(out, value) {
		t.Errorf("NameConstraints(ip8) not byte-exact:\n got %x\nwant %x", out, value)
	}
}
