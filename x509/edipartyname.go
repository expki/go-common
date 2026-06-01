package x509

import (
	"golang.org/x/crypto/cryptobyte"
)

// EDIPartyName models the ediPartyName [5] GeneralName alternative
// (rfc5280.txt:2099, 2108-2110):
//
//	EDIPartyName ::= SEQUENCE {
//	     nameAssigner            [0]     DirectoryString OPTIONAL,
//	     partyName               [1]     DirectoryString }
//
// Both fields are DirectoryString, a CHOICE-of-string, so each uses the
// preserve-and-project DirectoryString leaf (directorystring.go) to guarantee a
// byte-exact decode→encode round-trip (a TeletexString partyName must not
// collapse to PrintableString). It satisfies the GeneralName interface as
// CHOICE alternative [5].
//
// Context-tag note: because DirectoryString is itself a CHOICE, the [0] and [1]
// member tags cannot be IMPLICIT (an IMPLICIT tag would erase the inner CHOICE
// tag and make the alternative undecodable). They are therefore EXPLICIT
// constructed wrappers: nameAssigner is 0xA0 around the DirectoryString TLV and
// partyName is 0xA1. The whole SEQUENCE is IMPLICITly tagged [5] by the
// GeneralName CHOICE, so on the wire the outer element is 0xA5 (constructed
// context 5) in place of the SEQUENCE's 0x30.
type EDIPartyName struct {
	// NameAssigner is the optional nameAssigner [0] field; nil when absent.
	NameAssigner *DirectoryString
	// PartyName is the mandatory partyName [1] field.
	PartyName DirectoryString
}

// EDIPartyName member (context) tag numbers within the SEQUENCE.
const (
	ediNameAssignerTag = 0 // nameAssigner [0] EXPLICIT DirectoryString OPTIONAL
	ediPartyNameTag    = 1 // partyName    [1] EXPLICIT DirectoryString
)

// isGeneralName marks EDIPartyName as a GeneralName CHOICE alternative. It uses
// a value receiver to match the sibling arms (OtherName, X400Address,
// DirectoryName), so the dispatcher can return an EDIPartyName value as a
// GeneralName.
func (EDIPartyName) isGeneralName() {}

// tagNumber returns the GeneralName CHOICE context number for ediPartyName.
func (EDIPartyName) tagNumber() int { return 5 }

// parseEDIPartyName decodes the content of an ediPartyName [5] element (the
// SEQUENCE body, with the outer [5] tag/length already stripped by the
// GeneralName dispatcher). The signature matches the sibling arms
// (parseOtherName/parseX400Address/parseDirectoryName): cryptobyte.String in,
// value out. It returns ErrTruncated on short input, ErrUnexpectedTag on a
// misplaced member tag, and ErrTrailingData when bytes remain after partyName.
// It never panics.
func parseEDIPartyName(content cryptobyte.String) (EDIPartyName, error) {
	s := content
	var edi EDIPartyName

	// nameAssigner [0] EXPLICIT DirectoryString OPTIONAL.
	if assignerBody, present, err := readExplicitOptional(&s, ediNameAssignerTag); err != nil {
		return EDIPartyName{}, err
	} else if present {
		inner := cryptobyte.String(assignerBody)
		ds, err := parseDirectoryString(&inner)
		if err != nil {
			return EDIPartyName{}, err
		}
		if !inner.Empty() {
			return EDIPartyName{}, ErrTrailingData
		}
		edi.NameAssigner = &ds
	}

	// partyName [1] EXPLICIT DirectoryString (mandatory).
	partyBody, err := readContextExplicit(&s, ediPartyNameTag)
	if err != nil {
		return EDIPartyName{}, err
	}
	inner := cryptobyte.String(partyBody)
	party, err := parseDirectoryString(&inner)
	if err != nil {
		return EDIPartyName{}, err
	}
	if !inner.Empty() {
		return EDIPartyName{}, ErrTrailingData
	}
	edi.PartyName = party

	if !s.Empty() {
		return EDIPartyName{}, ErrTrailingData
	}
	return edi, nil
}

// readExplicitOptional reads an OPTIONAL [n] EXPLICIT wrapper. It peeks the next
// element's tag and, only if it is the context-constructed tag [n], consumes it
// and returns its inner bytes with present=true. A non-matching or empty input
// yields present=false and no consumption, so a following mandatory field can
// still be read. This is required because cryptobyte has no peek primitive that
// also leaves the element in place; we read an element copy from a clone first.
func readExplicitOptional(s *cryptobyte.String, n int) (inner []byte, present bool, err error) {
	if s.Empty() {
		return nil, false, nil
	}
	// Clone the cursor so a non-match leaves s untouched.
	probe := *s
	var elem cryptobyte.String
	if !probe.ReadASN1Element(&elem, contextTag(n, true)) {
		// Not this optional field; leave s as-is for the next reader.
		return nil, false, nil
	}
	// It matched: advance the real cursor and return the inner content.
	body, err := readContextExplicit(s, n)
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

// encodeInto appends the fully [5]-context-tagged DER for this EDIPartyName to
// b. Each DirectoryString member is wrapped in its EXPLICIT [0]/[1] constructed
// tag; the DirectoryString itself re-emits its preserved raw bytes when
// unmodified (byte-exact) or canonicalizes when built/mutated. Errors from the
// DirectoryString leaves surface via b.SetError; this method never panics.
func (e EDIPartyName) encodeInto(b *cryptobyte.Builder) error {
	addContextImplicit(b, e.tagNumber(), true, func(seq *cryptobyte.Builder) {
		if e.NameAssigner != nil {
			addContextExplicit(seq, ediNameAssignerTag, func(w *cryptobyte.Builder) {
				e.NameAssigner.encodeInto(w)
			})
		}
		addContextExplicit(seq, ediPartyNameTag, func(w *cryptobyte.Builder) {
			e.PartyName.encodeInto(w)
		})
	})
	return nil
}
