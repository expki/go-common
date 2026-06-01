package x509

import (
	"encoding/asn1"
	"fmt"
	"net"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// GeneralName CHOICE dispatch (rfc5280.txt:2093-2102).
//
// Each alternative is a context-specific tag 0..8. This file holds the
// parseGeneralName dispatcher and the five primitive arms (RFC822Name, DNSName,
// URIName, IPAddressName, RegisteredID). The heavier arms live in sibling files
// and are reached through their parse funcs:
//
//	parseOtherName       othername.go
//	parseX400Address     oraddress.go
//	parseDirectoryName   oraddress.go
//	parseEDIPartyName    edipartyname.go
//
// In every case the content passed in is the bytes inside the [n] element — the
// outer context tag and length already stripped by the dispatcher — and each
// arm's encodeInto re-adds its own outer [n] tag.

// Canonical GeneralName CHOICE wire shapes. Each alternative's leading
// identifier octet is fixed by its context number plus the implicit/explicit and
// primitive/constructed rules:
//   - rfc822Name[1]/dNSName[2]/uniformResourceIdentifier[6] are IMPLICIT
//     IA5String → primitive context tags 0x81/0x82/0x86.
//   - iPAddress[7] is IMPLICIT OCTET STRING → primitive 0x87.
//   - registeredID[8] is IMPLICIT OBJECT IDENTIFIER → primitive 0x88.
//   - otherName[0] is a constructed SEQUENCE-shaped body whose value field is
//     [0] EXPLICIT; the outer [0] is constructed → 0xA0.
//   - x400Address[3] wraps ORAddress (a SEQUENCE) IMPLICITly → constructed 0xA3.
//   - directoryName[4] wraps Name (a SEQUENCE); because Name is itself a CHOICE
//     it is effectively EXPLICIT → constructed 0xA4.
//   - ediPartyName[5] wraps a SEQUENCE → constructed 0xA5.
//
// parseGeneralName decodes one GeneralName element from raw. raw.FullBytes must
// be the complete context-tagged TLV of a single GeneralName (as produced by
// reading one element of the GeneralNames SEQUENCE OF). It dispatches on the
// context number and returns the matching concrete arm. It never panics; on
// malformed input it returns one of the sentinel errors.
//
// nameConstraints selects the iPAddress interpretation: false → SAN/IAN context
// (4 or 16 bytes, no mask), true → NameConstraints context (8 or 32 bytes,
// addr+mask).
func parseGeneralName(raw asn1.RawValue, nameConstraints bool) (GeneralName, error) {
	if raw.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("%w: GeneralName class %d", ErrUnexpectedTag, raw.Class)
	}
	if raw.Tag < 0 || raw.Tag > 8 {
		return nil, fmt.Errorf("%w: GeneralName tag %d out of range", ErrUnexpectedTag, raw.Tag)
	}
	// DER strictness: the five primitive alternatives — rfc822Name[1], dNSName[2],
	// uniformResourceIdentifier[6], iPAddress[7], registeredID[8] — are IMPLICITLY
	// tagged over primitive base types (IA5String / OCTET STRING / OID), so they
	// MUST appear in primitive (non-constructed) form. Accepting a constructed
	// 0xAn variant for these would deviate from DER and could mask a smuggled
	// nested structure; reject it. The remaining alternatives (otherName[0],
	// x400Address[3], directoryName[4], ediPartyName[5]) are legitimately
	// constructed and are validated by their own arm parsers.
	switch raw.Tag {
	case 1, 2, 6, 7, 8:
		if raw.IsCompound {
			return nil, fmt.Errorf("%w: GeneralName [%d] must be primitive, got constructed", ErrUnexpectedTag, raw.Tag)
		}
	}
	// Sibling arm parsers (othername.go, oraddress.go, edipartyname.go) take the
	// content INSIDE the [n] element as a cryptobyte.String. raw.Bytes is that
	// content (the outer context tag/length already stripped by asn1.Unmarshal).
	content := cryptobyte.String(raw.Bytes)
	switch raw.Tag {
	case 0: // otherName
		return parseOtherName(content)
	case 1: // rfc822Name
		return RFC822Name(string(raw.Bytes)), nil
	case 2: // dNSName
		return DNSName(string(raw.Bytes)), nil
	case 3: // x400Address
		return parseX400Address(content)
	case 4: // directoryName
		return parseDirectoryName(content)
	case 5: // ediPartyName
		return parseEDIPartyName(content)
	case 6: // uniformResourceIdentifier
		return URIName(string(raw.Bytes)), nil
	case 7: // iPAddress
		return parseIPAddressName(raw.Bytes, nameConstraints)
	case 8: // registeredID
		oid, err := parseRawOID(raw.Bytes)
		if err != nil {
			return nil, err
		}
		return RegisteredID(oid), nil
	default:
		return nil, fmt.Errorf("%w: GeneralName tag %d", ErrUnexpectedTag, raw.Tag)
	}
}

// parseRawOID decodes the content octets of an OBJECT IDENTIFIER (the value
// after the implicit [8] tag was stripped). cryptobyte's OID reader expects a
// full OID TLV, so we re-wrap the content in a universal OID header.
func parseRawOID(content []byte) (asn1.ObjectIdentifier, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.OBJECT_IDENTIFIER, func(c *cryptobyte.Builder) { c.AddBytes(content) })
	der, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	in := cryptobyte.String(der)
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1ObjectIdentifier(&oid) {
		return nil, fmt.Errorf("%w: registeredID OID", ErrTruncated)
	}
	return oid, nil
}

// --- Primitive arm: RFC822Name [1] IMPLICIT IA5String -----------------------

// RFC822Name is the rfc822Name [1] GeneralName alternative: an RFC 822 mailbox
// carried as an IA5String.
type RFC822Name string

func (RFC822Name) isGeneralName() {}
func (RFC822Name) tagNumber() int { return 1 }
func (n RFC822Name) encodeInto(b *cryptobyte.Builder) error {
	addContextImplicit(b, 1, false, func(c *cryptobyte.Builder) { c.AddBytes([]byte(n)) })
	return nil
}

// --- Primitive arm: DNSName [2] IMPLICIT IA5String --------------------------

// DNSName is the dNSName [2] GeneralName alternative: a DNS name as IA5String.
type DNSName string

func (DNSName) isGeneralName() {}
func (DNSName) tagNumber() int { return 2 }
func (n DNSName) encodeInto(b *cryptobyte.Builder) error {
	addContextImplicit(b, 2, false, func(c *cryptobyte.Builder) { c.AddBytes([]byte(n)) })
	return nil
}

// --- Primitive arm: URIName [6] IMPLICIT IA5String --------------------------

// URIName is the uniformResourceIdentifier [6] GeneralName alternative: a URI
// as IA5String.
type URIName string

func (URIName) isGeneralName() {}
func (URIName) tagNumber() int { return 6 }
func (n URIName) encodeInto(b *cryptobyte.Builder) error {
	addContextImplicit(b, 6, false, func(c *cryptobyte.Builder) { c.AddBytes([]byte(n)) })
	return nil
}

// --- Primitive arm: RegisteredID [8] IMPLICIT OBJECT IDENTIFIER -------------

// RegisteredID is the registeredID [8] GeneralName alternative: an OID.
type RegisteredID asn1.ObjectIdentifier

func (RegisteredID) isGeneralName() {}
func (RegisteredID) tagNumber() int { return 8 }
func (n RegisteredID) encodeInto(b *cryptobyte.Builder) error {
	// Encode a universal OID then strip its tag/length, re-emitting the content
	// under the implicit [8] primitive tag.
	var inner cryptobyte.Builder
	inner.AddASN1ObjectIdentifier(asn1.ObjectIdentifier(n))
	der, err := inner.Bytes()
	if err != nil {
		b.SetError(err)
		return err
	}
	content, ok := stripUniversalHeader(der)
	if !ok {
		err := fmt.Errorf("%w: registeredID OID encode", ErrTruncated)
		b.SetError(err)
		return err
	}
	addContextImplicit(b, 8, false, func(c *cryptobyte.Builder) { c.AddBytes(content) })
	return nil
}

// stripUniversalHeader removes the leading tag + DER length octets from a single
// universal-class TLV and returns its content bytes. Used to convert a
// stdlib/cryptobyte-emitted universal element into the content for an IMPLICIT
// context-tagged re-emission. Returns ok=false on malformed input.
func stripUniversalHeader(der []byte) (content []byte, ok bool) {
	in := cryptobyte.String(der)
	var elem cryptobyte.String
	var tag cbasn1.Tag
	if !in.ReadAnyASN1(&elem, &tag) || !in.Empty() {
		return nil, false
	}
	return []byte(elem), true
}

// --- Primitive arm: IPAddressName [7] IMPLICIT OCTET STRING -----------------

// IPAddressName is the iPAddress [7] GeneralName alternative. Its encoding
// depends on the context it appears in:
//
//   - SAN / IssuerAltName: a bare 4-byte (IPv4) or 16-byte (IPv6) address, no
//     mask. NameConstraints==false.
//   - NameConstraints: an 8-byte (IPv4) or 32-byte (IPv6) value carrying the
//     address followed by a mask (rfc5280.txt:2325-2332). NameConstraints==true.
//
// Validate enforces the length/context rules on both decode and encode so an
// illegal shape can never round-trip.
type IPAddressName struct {
	// IP is the address. 4 or 16 bytes.
	IP net.IP
	// Mask is the network mask, present only in the NameConstraints context.
	// Length matches IP (4 or 16 bytes) when set.
	Mask net.IPMask
	// NameConstraints discriminates the two encodings.
	NameConstraints bool
}

func (IPAddressName) isGeneralName() {}
func (IPAddressName) tagNumber() int { return 7 }

// Validate enforces the iPAddress length/mask rules for the active context.
func (n IPAddressName) Validate() error {
	ipLen := len(n.IP)
	if ipLen != 4 && ipLen != 16 {
		return fmt.Errorf("%w: iPAddress must be 4 or 16 bytes, got %d", ErrUnexpectedTag, ipLen)
	}
	if n.NameConstraints {
		if len(n.Mask) != ipLen {
			return fmt.Errorf("%w: NameConstraints iPAddress requires a %d-byte mask, got %d", ErrUnexpectedTag, ipLen, len(n.Mask))
		}
	} else {
		if len(n.Mask) != 0 {
			return fmt.Errorf("%w: SAN iPAddress must not carry a mask", ErrUnexpectedTag)
		}
	}
	return nil
}

func (n IPAddressName) encodeInto(b *cryptobyte.Builder) error {
	if err := n.Validate(); err != nil {
		b.SetError(err)
		return err
	}
	addContextImplicit(b, 7, false, func(c *cryptobyte.Builder) {
		c.AddBytes(n.IP)
		if n.NameConstraints {
			c.AddBytes(n.Mask)
		}
	})
	return nil
}

// parseIPAddressName decodes the OCTET STRING content of an iPAddress [7] arm.
// content is the raw octets (the [7] tag/length already stripped).
func parseIPAddressName(content []byte, nameConstraints bool) (IPAddressName, error) {
	n := IPAddressName{NameConstraints: nameConstraints}
	if nameConstraints {
		switch len(content) {
		case 8:
			n.IP = net.IP(append([]byte(nil), content[:4]...))
			n.Mask = net.IPMask(append([]byte(nil), content[4:]...))
		case 32:
			n.IP = net.IP(append([]byte(nil), content[:16]...))
			n.Mask = net.IPMask(append([]byte(nil), content[16:]...))
		default:
			return n, fmt.Errorf("%w: NameConstraints iPAddress must be 8 or 32 bytes, got %d", ErrUnexpectedTag, len(content))
		}
	} else {
		switch len(content) {
		case 4, 16:
			n.IP = net.IP(append([]byte(nil), content...))
		default:
			return n, fmt.Errorf("%w: SAN iPAddress must be 4 or 16 bytes, got %d", ErrUnexpectedTag, len(content))
		}
	}
	if err := n.Validate(); err != nil {
		return n, err
	}
	return n, nil
}
