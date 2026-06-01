package x509

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// DirectoryString models the X.509 DirectoryString CHOICE
// (rfc5280.txt:1099-1104):
//
//	DirectoryString ::= CHOICE {
//	      teletexString    TeletexString    (SIZE (1..MAX)),
//	      printableString  PrintableString  (SIZE (1..MAX)),
//	      universalString  UniversalString  (SIZE (1..MAX)),
//	      utf8String       UTF8String       (SIZE (1..MAX)),
//	      bmpString        BMPString        (SIZE (1..MAX)) }
//
// It is a CHOICE-of-string leaf, so it follows the package's preserve-and-project
// contract (see RawPreserve in types.go): on decode it captures the verbatim DER
// — preserving the exact CHOICE tag, e.g. TeletexString 0x14 vs PrintableString
// 0x13 — alongside a decoded Go string projection. On encode it re-emits the
// captured DER byte-for-byte unless the caller mutated the typed value, in which
// case it canonically re-encodes from Tag+String. That is the only way a
// byte-exact round-trip and a usable typed field can coexist: the naive
// pkix.RDNSequence path collapses a TeletexString DN to PrintableString on
// re-encode.
//
// DirectoryString is reused as a leaf by EDIPartyName's two fields and by the
// directoryName[4] RDN attribute values. It does not itself implement
// GeneralName; it is a building block.
type DirectoryString struct {
	RawPreserve

	// Tag is the UNIVERSAL tag number of the chosen CHOICE alternative as it
	// appeared (or will appear) on the wire. One of the directoryStringTag*
	// constants below.
	Tag int

	// String is the decoded UTF-8 projection of the chosen alternative. It is
	// populated on decode and is the source of truth when the value is built or
	// mutated programmatically.
	String string
}

// DirectoryString CHOICE alternative UNIVERSAL tag numbers.
const (
	directoryStringTagTeletex   = 20 // TeletexString / T61String (0x14)
	directoryStringTagPrintable = 19 // PrintableString (0x13)
	directoryStringTagUniversal = 28 // UniversalString, UCS-4/UTF-32BE (0x1C)
	directoryStringTagUTF8      = 12 // UTF8String (0x0C)
	directoryStringTagBMP       = 30 // BMPString, UCS-2/UTF-16BE (0x1E)
)

// isDirectoryStringTag reports whether n is one of the five DirectoryString
// CHOICE alternative tags.
func isDirectoryStringTag(n int) bool {
	switch n {
	case directoryStringTagTeletex, directoryStringTagPrintable,
		directoryStringTagUniversal, directoryStringTagUTF8,
		directoryStringTagBMP:
		return true
	default:
		return false
	}
}

// NewDirectoryString constructs a DirectoryString for the build path. It marks
// the value Modified so encodeInto canonicalizes from tag+s rather than trying
// to replay an (absent) raw capture. When tag is not a valid DirectoryString
// CHOICE tag it defaults to UTF8String, the encoding RFC 5280 §4.1.2.4 prefers
// for new values.
func NewDirectoryString(tag int, s string) DirectoryString {
	if !isDirectoryStringTag(tag) {
		tag = directoryStringTagUTF8
	}
	d := DirectoryString{Tag: tag, String: s}
	d.MarkModified()
	return d
}

// parseDirectoryString consumes exactly one DirectoryString TLV from s. It
// captures the verbatim element bytes for byte-exact re-emission and decodes a
// Go string projection. It returns ErrUnexpectedTag when the leading element is
// not one of the five DirectoryString CHOICE alternatives, and ErrTruncated on
// short input. It never panics.
func parseDirectoryString(s *cryptobyte.String) (DirectoryString, error) {
	var d DirectoryString
	var elem cryptobyte.String
	var tag cbasn1.Tag
	// ReadAnyASN1Element keeps the tag+length in elem so we capture the exact
	// TLV that appeared on the wire.
	if !s.ReadAnyASN1Element(&elem, &tag) {
		if s.Empty() {
			return d, ErrTruncated
		}
		return d, ErrUnexpectedTag
	}
	full := []byte(elem)

	// The chosen alternative must be a UNIVERSAL primitive string: the class
	// (0xc0) and constructed (0x20) bits must be clear, leaving only the tag
	// number in the low 5 bits, which must be one of the five DirectoryString
	// tags. cryptobyte's asn1.Tag is a bare uint8 with no boolean accessors, so
	// we mask the wire octet directly.
	if uint8(tag)&0xe0 != 0 {
		return d, ErrUnexpectedTag
	}
	tagNum := int(uint8(tag) & 0x1f)
	if !isDirectoryStringTag(tagNum) {
		return d, ErrUnexpectedTag
	}

	// Re-read the same element for its content (tag/length stripped) so we can
	// project to a Go string. elem still holds the full TLV for capture.
	var content cryptobyte.String
	var contentTag cbasn1.Tag
	reread := cryptobyte.String(full)
	if !reread.ReadAnyASN1(&content, &contentTag) {
		return d, ErrTruncated
	}

	str, err := decodeDirectoryStringContent(tagNum, []byte(content))
	if err != nil {
		return d, err
	}

	d.Tag = tagNum
	d.String = str
	d.capture(full)
	return d, nil
}

// decodeDirectoryStringContent projects the raw content octets of a
// DirectoryString alternative into a Go (UTF-8) string. Teletex, Printable and
// UTF8 octets are taken verbatim as bytes (Teletex is treated as Latin-1-ish
// pass-through per RFC 5280 §A note; the raw capture preserves exact bytes for
// round-trip, so the projection is best-effort and never the encode source
// while unmodified). BMPString is UTF-16BE and UniversalString is UTF-32BE.
func decodeDirectoryStringContent(tag int, content []byte) (string, error) {
	switch tag {
	case directoryStringTagUTF8, directoryStringTagPrintable, directoryStringTagTeletex:
		return string(content), nil
	case directoryStringTagBMP:
		if len(content)%2 != 0 {
			return "", fmt.Errorf("x509: BMPString length %d not a multiple of 2: %w", len(content), ErrTruncated)
		}
		u16 := make([]uint16, len(content)/2)
		for i := range u16 {
			u16[i] = binary.BigEndian.Uint16(content[i*2:])
		}
		return string(utf16.Decode(u16)), nil
	case directoryStringTagUniversal:
		if len(content)%4 != 0 {
			return "", fmt.Errorf("x509: UniversalString length %d not a multiple of 4: %w", len(content), ErrTruncated)
		}
		runes := make([]rune, len(content)/4)
		for i := range runes {
			runes[i] = rune(binary.BigEndian.Uint32(content[i*4:]))
		}
		return string(runes), nil
	default:
		return "", ErrUnexpectedTag
	}
}

// encodeDirectoryStringContent produces the content octets for the given
// DirectoryString alternative tag from a UTF-8 Go string. It is used only on
// the canonical (mutated/built) encode path; unmodified decoded values replay
// their captured raw bytes instead.
func encodeDirectoryStringContent(tag int, s string) ([]byte, error) {
	switch tag {
	case directoryStringTagUTF8, directoryStringTagPrintable, directoryStringTagTeletex:
		return []byte(s), nil
	case directoryStringTagBMP:
		u16 := utf16.Encode([]rune(s))
		out := make([]byte, len(u16)*2)
		for i, v := range u16 {
			binary.BigEndian.PutUint16(out[i*2:], v)
		}
		return out, nil
	case directoryStringTagUniversal:
		runes := []rune(s)
		out := make([]byte, len(runes)*4)
		for i, r := range runes {
			binary.BigEndian.PutUint32(out[i*4:], uint32(r))
		}
		return out, nil
	default:
		return nil, ErrUnexpectedTag
	}
}

// encodeInto appends this DirectoryString's own TLV to b. When the value is
// unmodified and carries a raw decode capture, the captured bytes are written
// verbatim (byte-exact). Otherwise the value is canonically encoded
// from Tag+String. On an unencodable tag it reports the error via b.SetError
// rather than panicking.
func (d DirectoryString) encodeInto(b *cryptobyte.Builder) {
	if d.HasRaw() {
		b.AddBytes(d.Raw.FullBytes)
		return
	}
	content, err := encodeDirectoryStringContent(d.Tag, d.String)
	if err != nil {
		b.SetError(err)
		return
	}
	b.AddASN1(cbasn1.Tag(uint8(d.Tag)), func(c *cryptobyte.Builder) {
		c.AddBytes(content)
	})
}
