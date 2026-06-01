package x509

import (
	"bytes"
	"encoding/asn1"
	"net"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// encodeName is a test helper: encode a single GeneralName arm to DER.
func encodeName(t *testing.T, n GeneralName) []byte {
	t.Helper()
	var b cryptobyte.Builder
	if err := n.encodeInto(&b); err != nil {
		t.Fatalf("encodeInto(%T): %v", n, err)
	}
	der, err := b.Bytes()
	if err != nil {
		t.Fatalf("Bytes(%T): %v", n, err)
	}
	return der
}

// readOneGeneralName wraps the encoded arm bytes and re-reads it as a single
// asn1.RawValue the way the dispatcher would (one element of GeneralNames).
func readOneGeneralName(t *testing.T, der []byte, nameConstraints bool) GeneralName {
	t.Helper()
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after GeneralName: %x", rest)
	}
	gn, err := parseGeneralName(raw, nameConstraints)
	if err != nil {
		t.Fatalf("parseGeneralName: %v", err)
	}
	return gn
}

// TestGeneralNameTagTable asserts the leading identifier octet of each arm's
// DER encoding matches the canonical tag table.
func TestGeneralNameTagTable(t *testing.T) {
	cases := []struct {
		name     string
		gn       GeneralName
		leadByte byte
	}{
		{"rfc822Name[1]", RFC822Name("a@b.com"), 0x81},
		{"dNSName[2]", DNSName("example.com"), 0x82},
		{"uri[6]", URIName("https://x"), 0x86},
		{"iPAddress[7]", IPAddressName{IP: net.IPv4(192, 0, 2, 1).To4()}, 0x87},
		{"registeredID[8]", RegisteredID(asn1.ObjectIdentifier{1, 3, 6, 1}), 0x88},
		{"otherName[0]", OtherName{
			TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
			Value:  rawUTF8(t, "user@dom"),
		}, 0xA0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der := encodeName(t, tc.gn)
			if len(der) == 0 {
				t.Fatal("empty encoding")
			}
			if der[0] != tc.leadByte {
				t.Errorf("lead byte = 0x%02X, want 0x%02X (full: %x)", der[0], tc.leadByte, der)
			}
		})
	}
}

// rawUTF8 builds a verbatim UTF8String TLV for use as an OtherName value.
func rawUTF8(t *testing.T, s string) asn1.RawValue {
	t.Helper()
	der, err := asn1.Marshal(s) // asn1 marshals Go string as PrintableString/UTF8 per content; force UTF8 below
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return asn1.RawValue{FullBytes: der}
}

func TestRFC822NameRoundTrip(t *testing.T) {
	orig := RFC822Name("alice@example.com")
	der := encodeName(t, orig)
	got := readOneGeneralName(t, der, false)
	g, ok := got.(RFC822Name)
	if !ok {
		t.Fatalf("got %T, want RFC822Name", got)
	}
	if g != orig {
		t.Errorf("got %q, want %q", g, orig)
	}
	if !bytes.Equal(encodeName(t, g), der) {
		t.Error("re-encode not byte-exact")
	}
}

func TestDNSNameRoundTrip(t *testing.T) {
	orig := DNSName("www.example.com")
	der := encodeName(t, orig)
	got := readOneGeneralName(t, der, false)
	if g, ok := got.(DNSName); !ok || g != orig {
		t.Fatalf("got %v (%T), want %v", got, got, orig)
	}
}

func TestURINameRoundTrip(t *testing.T) {
	orig := URIName("https://example.com/path")
	der := encodeName(t, orig)
	got := readOneGeneralName(t, der, false)
	if g, ok := got.(URIName); !ok || g != orig {
		t.Fatalf("got %v (%T), want %v", got, got, orig)
	}
}

func TestRegisteredIDRoundTrip(t *testing.T) {
	orig := RegisteredID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311})
	der := encodeName(t, orig)
	got := readOneGeneralName(t, der, false)
	g, ok := got.(RegisteredID)
	if !ok {
		t.Fatalf("got %T, want RegisteredID", got)
	}
	if !asn1.ObjectIdentifier(g).Equal(asn1.ObjectIdentifier(orig)) {
		t.Errorf("got %v, want %v", g, orig)
	}
	if !bytes.Equal(encodeName(t, g), der) {
		t.Error("re-encode not byte-exact")
	}
}

func TestIPAddressNameSAN(t *testing.T) {
	// IPv4 SAN: 4 bytes, no mask.
	v4 := IPAddressName{IP: net.IPv4(10, 0, 0, 1).To4()}
	der := encodeName(t, v4)
	if !bytes.Equal(der, []byte{0x87, 0x04, 10, 0, 0, 1}) {
		t.Errorf("IPv4 SAN encoding = %x", der)
	}
	got := readOneGeneralName(t, der, false)
	g := got.(IPAddressName)
	if !g.IP.Equal(net.IPv4(10, 0, 0, 1)) || g.NameConstraints || len(g.Mask) != 0 {
		t.Errorf("decoded = %+v", g)
	}

	// IPv6 SAN: 16 bytes.
	v6 := IPAddressName{IP: net.ParseIP("2001:db8::1")}
	der6 := encodeName(t, v6)
	if der6[0] != 0x87 || der6[1] != 16 {
		t.Errorf("IPv6 SAN header = %x", der6[:2])
	}
}

func TestIPAddressNameNameConstraints(t *testing.T) {
	// 192.0.2.0/24 → C0 00 02 00 FF FF FF 00 (RFC 5280 example).
	nc := IPAddressName{
		IP:              net.IPv4(192, 0, 2, 0).To4(),
		Mask:            net.IPMask{0xff, 0xff, 0xff, 0x00},
		NameConstraints: true,
	}
	der := encodeName(t, nc)
	want := []byte{0x87, 0x08, 0xC0, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00}
	if !bytes.Equal(der, want) {
		t.Errorf("NC encoding = %x, want %x", der, want)
	}
	got := readOneGeneralName(t, der, true).(IPAddressName)
	if !got.NameConstraints || len(got.Mask) != 4 {
		t.Errorf("decoded = %+v", got)
	}
}

// TestIPAddressNameValidate checks that a wrong length or mask-context is
// rejected on both decode and encode.
func TestIPAddressNameValidate(t *testing.T) {
	// SAN context but mask present → invalid.
	bad := IPAddressName{IP: net.IPv4(1, 2, 3, 4).To4(), Mask: net.IPMask{0xff, 0xff, 0xff, 0xff}}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for SAN with mask")
	}
	var b cryptobyte.Builder
	if err := bad.encodeInto(&b); err == nil {
		t.Error("encodeInto should reject SAN-with-mask")
	}

	// NameConstraints context but no mask → invalid.
	bad2 := IPAddressName{IP: net.IPv4(1, 2, 3, 4).To4(), NameConstraints: true}
	if err := bad2.Validate(); err == nil {
		t.Error("expected error for NameConstraints without mask")
	}

	// Decode: 8-byte value parsed in SAN context must fail.
	if _, err := parseIPAddressName([]byte{1, 2, 3, 4, 5, 6, 7, 8}, false); err == nil {
		t.Error("8-byte SAN iPAddress should be rejected")
	}
	// Decode: 4-byte value in NameConstraints context must fail.
	if _, err := parseIPAddressName([]byte{1, 2, 3, 4}, true); err == nil {
		t.Error("4-byte NameConstraints iPAddress should be rejected")
	}
}

func TestParseGeneralNameMalformed(t *testing.T) {
	// Non-context-class element must be rejected, not panic.
	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: 2, Bytes: []byte{1}}
	if _, err := parseGeneralName(raw, false); err == nil {
		t.Error("expected error for non-context-class GeneralName")
	}
	// Out-of-range context tag.
	raw2 := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 9, Bytes: nil}
	if _, err := parseGeneralName(raw2, false); err == nil {
		t.Error("expected error for tag 9")
	}
}

func TestOtherNameRoundTrip(t *testing.T) {
	// Build an otherName with a UTF8String value and verify byte-exact
	// preservation of the inner value. UTF8String TLV: 0x0C len "upn".
	valTLV := []byte{0x0C, 0x03, 'u', 'p', 'n'}
	orig := OtherName{
		TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
		Value:  asn1.RawValue{FullBytes: valTLV},
	}
	der := encodeName(t, orig)
	if der[0] != 0xA0 {
		t.Fatalf("otherName lead byte = 0x%02X, want 0xA0", der[0])
	}
	got := readOneGeneralName(t, der, false)
	on, ok := got.(OtherName)
	if !ok {
		t.Fatalf("got %T, want OtherName", got)
	}
	if !on.TypeID.Equal(orig.TypeID) {
		t.Errorf("TypeID = %v, want %v", on.TypeID, orig.TypeID)
	}
	if !bytes.Equal(on.Value.FullBytes, valTLV) {
		t.Errorf("value FullBytes = %x, want %x", on.Value.FullBytes, valTLV)
	}
	// Re-encode must be byte-exact.
	if !bytes.Equal(encodeName(t, on), der) {
		t.Error("otherName re-encode not byte-exact")
	}
}

// TestGeneralNamePrimitiveConstructedRejected asserts DER strictness: the five
// primitive alternatives (rfc822Name[1], dNSName[2], URI[6], iPAddress[7],
// registeredID[8]) MUST be primitive-form; a constructed (0xAn) encoding is
// rejected with ErrUnexpectedTag, not silently accepted.
func TestGeneralNamePrimitiveConstructedRejected(t *testing.T) {
	// Primitive dNSName [2] is 0x82; the constructed variant is 0xA2.
	primitive := []byte{0x82, 0x03, 'a', '.', 'b'}
	if _, err := parseGeneralName(unmarshalRaw(t, primitive), false); err != nil {
		t.Fatalf("primitive dNSName should parse: %v", err)
	}
	constructed := []byte{0xA2, 0x03, 'a', '.', 'b'}
	if _, err := parseGeneralName(unmarshalRaw(t, constructed), false); err == nil {
		t.Error("constructed-form dNSName [2] (0xA2) must be rejected")
	}

	// Spot-check the other four primitive arms in constructed form.
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"rfc822Name", []byte{0xA1, 0x01, 'x'}},
		{"uri", []byte{0xA6, 0x01, 'x'}},
		{"iPAddress", []byte{0xA7, 0x04, 1, 2, 3, 4}},
		{"registeredID", []byte{0xA8, 0x01, 0x2A}},
	} {
		t.Run(tc.name+"-constructed-rejected", func(t *testing.T) {
			if _, err := parseGeneralName(unmarshalRaw(t, tc.der), false); err == nil {
				t.Errorf("constructed-form %s must be rejected", tc.name)
			}
		})
	}

	// The legitimately-constructed arms must still be accepted (directoryName[4]
	// holding an empty Name SEQUENCE).
	dirName := []byte{0xA4, 0x02, 0x30, 0x00}
	if _, err := parseGeneralName(unmarshalRaw(t, dirName), false); err != nil {
		t.Errorf("directoryName[4] constructed form should parse: %v", err)
	}
}

// unmarshalRaw parses a single GeneralName TLV into an asn1.RawValue the way the
// GeneralNames iterator does.
func unmarshalRaw(t *testing.T, der []byte) asn1.RawValue {
	t.Helper()
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		t.Fatalf("asn1.Unmarshal(%x): %v", der, err)
	}
	return raw
}
