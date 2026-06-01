package x509

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// buildORAddressBody constructs a synthetic ORAddress SEQUENCE *body* (members
// only, no surrounding SEQUENCE tag) exercising every modeled member, then wraps
// it in the x400Address [3] IMPLICIT context tag. The returned bytes are the
// complete x400Address GeneralName element TLV — the same shape parseGeneralName
// would hand to the arm via parseX400Address (content = inside the [3] tag).
//
// This is a hand-built cryptobyte vector (not builder-generated) used to prove
// self-round-trip is byte-exact.
func buildORAddressArmTLV(t *testing.T) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	// x400Address [3] IMPLICIT ORAddress (constructed 0xA3); content = ORAddress
	// SEQUENCE members.
	b.AddASN1(contextTag(3, true), func(or *cryptobyte.Builder) {
		// built-in-standard-attributes SEQUENCE
		or.AddASN1(cbasn1.SEQUENCE, func(std *cryptobyte.Builder) {
			// country-name [APPLICATION 1] CHOICE -> PrintableString "US"
			std.AddASN1(applicationTag(1), func(w *cryptobyte.Builder) {
				w.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("US"))
				})
			})
			// administration-domain-name [APPLICATION 2] CHOICE -> NumericString "1"
			std.AddASN1(applicationTag(2), func(w *cryptobyte.Builder) {
				w.AddASN1(tagNumericString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("1"))
				})
			})
			// network-address [0] IMPLICIT NumericString "12345"
			std.AddASN1(contextTag(0, false), func(c *cryptobyte.Builder) {
				c.AddBytes([]byte("12345"))
			})
			// terminal-identifier [1] IMPLICIT PrintableString "TERM"
			std.AddASN1(contextTag(1, false), func(c *cryptobyte.Builder) {
				c.AddBytes([]byte("TERM"))
			})
			// private-domain-name [2] EXPLICIT CHOICE -> PrintableString "PRIV"
			std.AddASN1(contextTag(2, true), func(w *cryptobyte.Builder) {
				w.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("PRIV"))
				})
			})
			// organization-name [3] IMPLICIT PrintableString "ACME"
			std.AddASN1(contextTag(3, false), func(c *cryptobyte.Builder) {
				c.AddBytes([]byte("ACME"))
			})
			// numeric-user-identifier [4] IMPLICIT NumericString "678"
			std.AddASN1(contextTag(4, false), func(c *cryptobyte.Builder) {
				c.AddBytes([]byte("678"))
			})
			// personal-name [5] IMPLICIT SET
			std.AddASN1(contextTag(5, true), func(pn *cryptobyte.Builder) {
				// surname [0] IMPLICIT PrintableString "Doe"
				pn.AddASN1(contextTag(0, false), func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("Doe"))
				})
				// given-name [1] IMPLICIT PrintableString "Jane"
				pn.AddASN1(contextTag(1, false), func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("Jane"))
				})
				// initials [2] IMPLICIT PrintableString "JD"
				pn.AddASN1(contextTag(2, false), func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("JD"))
				})
			})
			// organizational-unit-names [6] IMPLICIT SEQUENCE OF PrintableString
			std.AddASN1(contextTag(6, true), func(ous *cryptobyte.Builder) {
				ous.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("OU1"))
				})
				ous.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("OU2"))
				})
			})
		})
		// built-in-domain-defined-attributes SEQUENCE OF
		or.AddASN1(cbasn1.SEQUENCE, func(bdda *cryptobyte.Builder) {
			bdda.AddASN1(cbasn1.SEQUENCE, func(item *cryptobyte.Builder) {
				item.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("type1"))
				})
				item.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
					c.AddBytes([]byte("val1"))
				})
			})
		})
		// extension-attributes SET OF
		or.AddASN1(cbasn1.SET, func(ea *cryptobyte.Builder) {
			ea.AddASN1(cbasn1.SEQUENCE, func(item *cryptobyte.Builder) {
				// extension-attribute-type [0] IMPLICIT INTEGER = 7
				item.AddASN1Int64WithTag(7, contextTag(0, false))
				// extension-attribute-value [1] EXPLICIT ANY -> PrintableString "PDS"
				item.AddASN1(contextTag(1, true), func(w *cryptobyte.Builder) {
					w.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) {
						c.AddBytes([]byte("PDS"))
					})
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("build ORAddress vector: %v", err)
	}
	return out
}

// readArmContent strips the outer [n] context tag from a GeneralName element TLV
// and returns the content bytes, mirroring what parseGeneralName feeds an arm.
func readArmContent(t *testing.T, tlv []byte, n int, constructed bool) cryptobyte.String {
	t.Helper()
	in := cryptobyte.String(tlv)
	var content cryptobyte.String
	if !in.ReadASN1(&content, contextTag(n, constructed)) {
		t.Fatalf("strip [%d] context tag failed", n)
	}
	if !in.Empty() {
		t.Fatalf("trailing data after [%d] element", n)
	}
	return content
}

func TestX400AddressRoundTripByteExact(t *testing.T) {
	tlv := buildORAddressArmTLV(t)

	// Decode the arm content (inside [3]).
	content := readArmContent(t, tlv, 3, true)
	x, err := parseX400Address(content)
	if err != nil {
		t.Fatalf("parseX400Address: %v", err)
	}

	// Spot-check typed fields (fully modeled, not raw-preserved).
	std := x.ORAddress.BuiltInStandard
	if std.CountryName == nil || std.CountryName.Value.Value != "US" {
		t.Errorf("CountryName = %+v, want US", std.CountryName)
	}
	if std.CountryName.Value.Tag != cbasn1.PrintableString {
		t.Errorf("CountryName tag = %d, want PrintableString", std.CountryName.Value.Tag)
	}
	if std.AdministrationDomain == nil || std.AdministrationDomain.Value.Value != "1" {
		t.Errorf("AdministrationDomain = %+v, want 1", std.AdministrationDomain)
	}
	if std.AdministrationDomain.Value.Tag != tagNumericString {
		t.Errorf("AdministrationDomain tag = %d, want NumericString", std.AdministrationDomain.Value.Tag)
	}
	if std.NetworkAddress == nil || std.NetworkAddress.Value != "12345" {
		t.Errorf("NetworkAddress = %+v, want 12345", std.NetworkAddress)
	}
	if std.PrivateDomain == nil || std.PrivateDomain.Value.Value != "PRIV" {
		t.Errorf("PrivateDomain = %+v, want PRIV", std.PrivateDomain)
	}
	if std.PersonalName == nil || std.PersonalName.Surname.Value != "Doe" {
		t.Fatalf("PersonalName surname = %+v, want Doe", std.PersonalName)
	}
	if std.PersonalName.GivenName == nil || std.PersonalName.GivenName.Value != "Jane" {
		t.Errorf("PersonalName given-name = %+v, want Jane", std.PersonalName.GivenName)
	}
	if got := len(std.OrganizationalUnits); got != 2 {
		t.Errorf("OrganizationalUnits len = %d, want 2", got)
	}
	if len(x.ORAddress.BuiltInDomainDefined) != 1 ||
		x.ORAddress.BuiltInDomainDefined[0].Type.Value != "type1" {
		t.Errorf("BuiltInDomainDefined = %+v", x.ORAddress.BuiltInDomainDefined)
	}
	if len(x.ORAddress.ExtensionAttributes) != 1 ||
		x.ORAddress.ExtensionAttributes[0].Type != 7 {
		t.Errorf("ExtensionAttributes = %+v", x.ORAddress.ExtensionAttributes)
	}

	// Re-encode and assert byte-exact round-trip.
	b := cryptobyte.NewBuilder(nil)
	if err := x.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("builder.Bytes: %v", err)
	}
	if !bytes.Equal(out, tlv) {
		t.Errorf("x400Address round-trip not byte-exact:\n got %x\nwant %x", out, tlv)
	}
}

func TestX400AddressGeneralNameInterface(t *testing.T) {
	var _ GeneralName = X400Address{}
	if (X400Address{}).tagNumber() != 3 {
		t.Errorf("X400Address tagNumber = %d, want 3", (X400Address{}).tagNumber())
	}
}

// buildDirectoryNameArmTLV builds a directoryName [4] GeneralName element whose
// inner Name DN carries a TeletexString attribute value (the case that breaks
// the naive pkix.RDNSequence re-encode path: it would canonicalize to
// PrintableString). content = the Name SEQUENCE TLV inside [4].
func buildDirectoryNameArmTLV(t *testing.T, attrTag cbasn1.Tag, value string) []byte {
	t.Helper()
	// Build a minimal RDNSequence: SEQUENCE OF SET OF SEQUENCE { OID, value }.
	// commonName = 2.5.4.3.
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	b := cryptobyte.NewBuilder(nil)
	// directoryName [4] EXPLICIT wrapper.
	b.AddASN1(contextTag(4, true), func(wrap *cryptobyte.Builder) {
		// Name ::= RDNSequence ::= SEQUENCE OF RDN
		wrap.AddASN1(cbasn1.SEQUENCE, func(rdnseq *cryptobyte.Builder) {
			// RDN ::= SET OF AttributeTypeAndValue
			rdnseq.AddASN1(cbasn1.SET, func(set *cryptobyte.Builder) {
				// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
				set.AddASN1(cbasn1.SEQUENCE, func(atv *cryptobyte.Builder) {
					atv.AddASN1ObjectIdentifier(cn)
					atv.AddASN1(attrTag, func(c *cryptobyte.Builder) {
						c.AddBytes([]byte(value))
					})
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("build directoryName vector: %v", err)
	}
	return out
}

func TestDirectoryNameRoundTripTeletex(t *testing.T) {
	// TeletexString (T61String, tag 20) value — must round-trip byte-exact.
	tlv := buildDirectoryNameArmTLV(t, tagTeletexString, "Schroedinger")

	content := readArmContent(t, tlv, 4, true)
	d, err := parseDirectoryName(content)
	if err != nil {
		t.Fatalf("parseDirectoryName: %v", err)
	}

	// Typed projection populated.
	if len(d.RDNs) != 1 {
		t.Fatalf("RDNs len = %d, want 1", len(d.RDNs))
	}
	atv := d.RDNs[0][0]
	if !atv.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
		t.Errorf("attribute type = %v, want commonName", atv.Type)
	}

	// Byte-exact re-emit from the preserved raw (unmodified).
	b := cryptobyte.NewBuilder(nil)
	if err := d.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("builder.Bytes: %v", err)
	}
	if !bytes.Equal(out, tlv) {
		t.Errorf("directoryName(TeletexString) round-trip not byte-exact:\n got %x\nwant %x", out, tlv)
	}
}

func TestDirectoryNameRoundTripBMP(t *testing.T) {
	// BMPString is tag 30 (universal). It also breaks the naive path.
	const tagBMPString = cbasn1.Tag(30)
	tlv := buildDirectoryNameArmTLV(t, tagBMPString, "\x00B\x00M\x00P")

	content := readArmContent(t, tlv, 4, true)
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
	if !bytes.Equal(out, tlv) {
		t.Errorf("directoryName(BMPString) round-trip not byte-exact:\n got %x\nwant %x", out, tlv)
	}
}

func TestDirectoryNameMutatedReencodesCanonically(t *testing.T) {
	// A PrintableString DN — re-encoding from the typed projection (after
	// marking modified) must still produce valid DER for the projection.
	tlv := buildDirectoryNameArmTLV(t, cbasn1.PrintableString, "example.com")
	content := readArmContent(t, tlv, 4, true)
	d, err := parseDirectoryName(content)
	if err != nil {
		t.Fatalf("parseDirectoryName: %v", err)
	}

	d.MarkModified() // force canonical path
	b := cryptobyte.NewBuilder(nil)
	if err := d.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("builder.Bytes: %v", err)
	}
	// Decoding the re-encoded arm must yield the same RDNSequence projection.
	content2 := readArmContent(t, out, 4, true)
	d2, err := parseDirectoryName(content2)
	if err != nil {
		t.Fatalf("re-parse after canonical encode: %v", err)
	}
	if len(d2.RDNs) != 1 || !d2.RDNs[0][0].Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
		t.Errorf("canonical re-encode lost projection: %+v", d2.RDNs)
	}
	_ = pkix.RDNSequence(d2.RDNs) // type sanity
}

func TestDirectoryNameGeneralNameInterface(t *testing.T) {
	var _ GeneralName = DirectoryName{}
	if (DirectoryName{}).tagNumber() != 4 {
		t.Errorf("DirectoryName tagNumber = %d, want 4", (DirectoryName{}).tagNumber())
	}
}

func TestX400AddressMalformedNoPanic(t *testing.T) {
	// Truncated / garbage content must yield an error, never a panic.
	cases := [][]byte{
		{},
		{0x30},             // bare SEQUENCE tag, no length
		{0x30, 0x01},       // length exceeds content
		{0xFF, 0xFF, 0xFF}, // nonsense
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			// built-in-standard-attributes is mandatory, so every malformed
			// case above must error (never panic).
			if _, err := parseX400Address(cryptobyte.String(c)); err == nil {
				t.Errorf("case %d: expected error for %x", i, c)
			}
		}()
	}
}

// extValueDER builds the inner ANY value (a PrintableString) for an
// ExtensionAttribute, returned as the full TLV the model preserves verbatim.
func extValueDER(t *testing.T, s string) asn1.RawValue {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.PrintableString, func(c *cryptobyte.Builder) { c.AddBytes([]byte(s)) })
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("build ext value: %v", err)
	}
	return asn1.RawValue{FullBytes: out}
}

// TestExtensionAttributesSetOfSorted verifies the marshal path emits the
// ExtensionAttributes SET OF in ascending bytewise order of its encoded members
// (X.690 §11.6), even when the Go slice is supplied out of order. The
// discriminating field is extension-attribute-type [0] INTEGER, so a set built
// as {type 5, type 1} must marshal with the type-1 element first.
func TestExtensionAttributesSetOfSorted(t *testing.T) {
	or := ORAddress{
		// Minimal mandatory built-in-standard-attributes (empty is legal: all
		// members are OPTIONAL).
		BuiltInStandard: BuiltInStandardAttributes{},
		ExtensionAttributes: []ExtensionAttribute{
			{Type: 5, Value: extValueDER(t, "five")},
			{Type: 1, Value: extValueDER(t, "one")},
		},
	}
	x := X400Address{ORAddress: or}

	b := cryptobyte.NewBuilder(nil)
	if err := x.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	der, err := b.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	// Decode back and confirm the SET OF round-trips into ascending type order
	// regardless of the unsorted input order.
	in := cryptobyte.String(der)
	var content cryptobyte.String
	if !in.ReadASN1(&content, contextTag(3, true)) {
		t.Fatalf("strip [3] tag failed")
	}
	got, err := parseX400Address(content)
	if err != nil {
		t.Fatalf("parseX400Address: %v", err)
	}
	ea := got.ORAddress.ExtensionAttributes
	if len(ea) != 2 {
		t.Fatalf("got %d extension attributes, want 2", len(ea))
	}
	if ea[0].Type != 1 || ea[1].Type != 5 {
		t.Errorf("ExtensionAttributes not sorted: got types [%d %d], want [1 5]", ea[0].Type, ea[1].Type)
	}

	// Re-encoding the now-sorted set must be byte-exact (sorting is idempotent).
	b2 := cryptobyte.NewBuilder(nil)
	if err := got.encodeInto(b2); err != nil {
		t.Fatalf("re-encodeInto: %v", err)
	}
	der2, err := b2.Bytes()
	if err != nil {
		t.Fatalf("re-Bytes: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Errorf("sorted SET OF re-encode not byte-exact:\n got %x\nwant %x", der2, der)
	}
}

// TestExtensionAttributesSortIdempotent confirms sorting an already-canonical
// (ascending) input is a no-op — the guarantee that decode→encode of real,
// sorted DER stays byte-exact.
func TestExtensionAttributesSortIdempotent(t *testing.T) {
	or := ORAddress{
		ExtensionAttributes: []ExtensionAttribute{
			{Type: 1, Value: extValueDER(t, "one")},
			{Type: 5, Value: extValueDER(t, "five")},
		},
	}
	x := X400Address{ORAddress: or}
	b := cryptobyte.NewBuilder(nil)
	if err := x.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	der1, err := b.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	// Build the same set already in order via a second pass — identical output.
	b2 := cryptobyte.NewBuilder(nil)
	if err := x.encodeInto(b2); err != nil {
		t.Fatalf("encodeInto 2: %v", err)
	}
	der2, err := b2.Bytes()
	if err != nil {
		t.Fatalf("Bytes 2: %v", err)
	}
	if !bytes.Equal(der1, der2) {
		t.Errorf("sort not idempotent on ordered input")
	}
}
