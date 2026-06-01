package x509

import (
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OtherName is the otherName [0] GeneralName alternative (rfc5280.txt:2104-2106):
//
//	OtherName ::= SEQUENCE {
//	    type-id    OBJECT IDENTIFIER,
//	    value      [0] EXPLICIT ANY DEFINED BY type-id }
//
// The value is preserved verbatim (the inner element's FullBytes captured from
// inside the [0] EXPLICIT wrapper) so any ANY-typed payload round-trips
// byte-exactly. TypeID is the typed projection of the OID.
//
// On the wire the whole arm is the constructed [0] element 0xA0 whose content
// is the SEQUENCE body: the type-id OID followed by the value [0] EXPLICIT
// wrapper. Note there are two distinct [0] tags here — the OUTER GeneralName
// CHOICE [0] (the arm tag, handled by the dispatcher / encodeInto) and the
// INNER value [0] EXPLICIT (handled within this file).
type OtherName struct {
	// TypeID is the type-id OBJECT IDENTIFIER.
	TypeID asn1.ObjectIdentifier
	// Value is the inner element of the value [0] EXPLICIT field, with its
	// FullBytes preserved verbatim for byte-exact re-emission.
	Value asn1.RawValue
}

func (OtherName) isGeneralName() {}
func (OtherName) tagNumber() int { return 0 }

// parseOtherName decodes the content of the outer [0] GeneralName element: the
// SEQUENCE body { type-id OID, value [0] EXPLICIT ANY }. content has had the
// outer [0] arm tag/length stripped by the dispatcher.
func parseOtherName(content cryptobyte.String) (OtherName, error) {
	var on OtherName
	// The outer arm tag was already a constructed [0] whose content IS the
	// SEQUENCE fields (otherName is encoded as the SEQUENCE under the [0] tag,
	// i.e. [0] is IMPLICIT over the SEQUENCE). Read the OID then the [0]
	// EXPLICIT value directly from content.
	if !content.ReadASN1ObjectIdentifier(&on.TypeID) {
		return on, fmt.Errorf("%w: otherName type-id", ErrTruncated)
	}
	var valueWrapper cryptobyte.String
	if !content.ReadASN1(&valueWrapper, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return on, fmt.Errorf("%w: otherName value [0] EXPLICIT", ErrUnexpectedTag)
	}
	// valueWrapper now holds the inner ANY element; capture it verbatim.
	var inner cryptobyte.String
	var innerTag cbasn1.Tag
	if !valueWrapper.ReadAnyASN1Element(&inner, &innerTag) {
		return on, fmt.Errorf("%w: otherName value inner element", ErrTruncated)
	}
	if !valueWrapper.Empty() {
		return on, fmt.Errorf("%w: otherName value [0] EXPLICIT", ErrTrailingData)
	}
	on.Value = asn1.RawValue{FullBytes: append([]byte(nil), []byte(inner)...)}
	if !content.Empty() {
		return on, fmt.Errorf("%w: otherName SEQUENCE", ErrTrailingData)
	}
	return on, nil
}

func (on OtherName) encodeInto(b *cryptobyte.Builder) error {
	if len(on.Value.FullBytes) == 0 {
		err := fmt.Errorf("%w: otherName value is empty", ErrTruncated)
		b.SetError(err)
		return err
	}
	// Outer arm: [0] IMPLICIT over the SEQUENCE body (constructed 0xA0).
	addContextImplicit(b, 0, true, func(c *cryptobyte.Builder) {
		c.AddASN1ObjectIdentifier(on.TypeID)
		// value [0] EXPLICIT wraps the preserved inner element verbatim.
		addContextExplicit(c, 0, func(v *cryptobyte.Builder) {
			v.AddBytes(on.Value.FullBytes)
		})
	})
	return nil
}
