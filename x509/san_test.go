package x509

import (
	"bytes"
	"encoding/asn1"
	"net"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// buildGeneralNamesDER encodes a slice of arms into a GeneralNames SEQUENCE DER
// for use as test input.
func buildGeneralNamesDER(t *testing.T, arms ...GeneralName) []byte {
	t.Helper()
	g := GeneralNames(arms)
	der, err := g.marshal()
	if err != nil {
		t.Fatalf("marshal GeneralNames: %v", err)
	}
	return der
}

// otherNameUPN builds a representative otherName [0] arm (MS UPN) with a
// verbatim UTF8String value.
func otherNameUPN(s string) OtherName {
	val := append([]byte{0x0C, byte(len(s))}, []byte(s)...) // UTF8String TLV
	return OtherName{
		TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
		Value:  asn1.RawValue{FullBytes: val},
	}
}

// TestSANMultiTypeRoundTrip covers order/count and byte-exactness for a
// multi-type SAN: dNSName + iPAddress + rfc822Name + URI + otherName.
func TestSANMultiTypeRoundTrip(t *testing.T) {
	arms := []GeneralName{
		DNSName("example.com"),
		IPAddressName{IP: net.IPv4(192, 0, 2, 10).To4()},
		RFC822Name("admin@example.com"),
		URIName("https://example.com/ca"),
		otherNameUPN("user@DOMAIN"),
	}
	der := buildGeneralNamesDER(t, arms...)

	san, err := ParseSAN(der)
	if err != nil {
		t.Fatalf("ParseSAN: %v", err)
	}
	// Count preserved.
	if len(san.Names) != len(arms) {
		t.Fatalf("count = %d, want %d", len(san.Names), len(arms))
	}
	// Order + types preserved.
	wantTags := []int{2, 7, 1, 6, 0}
	for i, n := range san.Names {
		if n.tagNumber() != wantTags[i] {
			t.Errorf("name[%d] tag = %d, want %d", i, n.tagNumber(), wantTags[i])
		}
	}
	// Spot-check decoded values.
	if dns, ok := san.Names[0].(DNSName); !ok || string(dns) != "example.com" {
		t.Errorf("name[0] = %v, want DNSName example.com", san.Names[0])
	}
	if ip, ok := san.Names[1].(IPAddressName); !ok || !ip.IP.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Errorf("name[1] = %v, want iPAddress 192.0.2.10", san.Names[1])
	}
	if on, ok := san.Names[4].(OtherName); !ok || !on.TypeID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}) {
		t.Errorf("name[4] = %v, want otherName UPN", san.Names[4])
	}

	// Byte-exact round-trip.
	out, err := san.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(out, der) {
		t.Errorf("round-trip not byte-exact:\n got %x\nwant %x", out, der)
	}
}

// TestSANSingleTypes exercises each primitive arm through the SAN path.
func TestSANSingleTypes(t *testing.T) {
	cases := []struct {
		name string
		arm  GeneralName
	}{
		{"dns", DNSName("a.example")},
		{"rfc822", RFC822Name("x@a.example")},
		{"uri", URIName("urn:example:1")},
		{"ipv4", IPAddressName{IP: net.IPv4(10, 1, 2, 3).To4()}},
		{"ipv6", IPAddressName{IP: net.ParseIP("2001:db8::2")}},
		{"regid", RegisteredID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der := buildGeneralNamesDER(t, tc.arm)
			san, err := ParseSAN(der)
			if err != nil {
				t.Fatalf("ParseSAN: %v", err)
			}
			if len(san.Names) != 1 {
				t.Fatalf("count = %d, want 1", len(san.Names))
			}
			out, err := san.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.Equal(out, der) {
				t.Errorf("not byte-exact: got %x want %x", out, der)
			}
		})
	}
}

// TestIssuerAltNameSharedPath checks that IAN uses the same GeneralNames path.
func TestIssuerAltNameSharedPath(t *testing.T) {
	der := buildGeneralNamesDER(t, RFC822Name("issuer@example.com"), DNSName("ca.example.com"))
	ian, err := ParseIssuerAltName(der)
	if err != nil {
		t.Fatalf("ParseIssuerAltName: %v", err)
	}
	if len(ian.Names) != 2 {
		t.Fatalf("count = %d, want 2", len(ian.Names))
	}
	out, err := ian.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(out, der) {
		t.Error("IAN round-trip not byte-exact")
	}
}

// TestParseGeneralNamesMalformed asserts malformed input is rejected, not
// panicked on.
func TestParseGeneralNamesMalformed(t *testing.T) {
	// Not a SEQUENCE.
	if _, err := parseGeneralNames([]byte{0x05, 0x00}, false); err == nil {
		t.Error("expected error for non-SEQUENCE")
	}
	// Truncated SEQUENCE length.
	if _, err := parseGeneralNames([]byte{0x30, 0x05, 0x81, 0x01}, false); err == nil {
		t.Error("expected error for truncated element")
	}
	// Trailing data after the SEQUENCE.
	good := buildGeneralNamesDER(t, DNSName("a.b"))
	trailing := append(append([]byte(nil), good...), 0x00)
	if _, err := parseGeneralNames(trailing, false); err == nil {
		t.Error("expected error for trailing data")
	}
	// Empty input.
	if _, err := parseGeneralNames(nil, false); err == nil {
		t.Error("expected error for empty input")
	}
}

// TestSANNameConstraintsContext verifies the nameConstraints flag is NOT applied
// on the SAN path: an 8-byte iPAddress (NameConstraints shape) must be rejected
// when parsed as a SAN.
func TestSANNameConstraintsContext(t *testing.T) {
	// Hand-build a GeneralNames with a single 8-byte iPAddress element.
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(cbasn1.Tag(7).ContextSpecific(), func(v *cryptobyte.Builder) {
			v.AddBytes([]byte{192, 0, 2, 0, 255, 255, 255, 0})
		})
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSAN(der); err == nil {
		t.Error("8-byte iPAddress should be rejected in SAN context")
	}
	// But valid in NameConstraints context.
	if _, err := parseGeneralNames(der, true); err != nil {
		t.Errorf("8-byte iPAddress should parse in NameConstraints context: %v", err)
	}
}
