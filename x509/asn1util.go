package x509

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Typed sentinel errors returned by every decode path in this package. Decode
// functions MUST return one of these (or an error wrapping one) on malformed
// input; they MUST NOT panic. cryptobyte's reader methods report failure via a
// bool, so the helpers below translate that into these errors.
var (
	// ErrTruncated is returned when the input ends before a structure that the
	// grammar requires is fully read (a missing field, short length, etc.).
	ErrTruncated = errors.New("x509: truncated ASN.1 data")
	// ErrUnexpectedTag is returned when the tag octet read does not match the
	// tag the grammar requires at that position.
	ErrUnexpectedTag = errors.New("x509: unexpected ASN.1 tag")
	// ErrTrailingData is returned when bytes remain after a structure that the
	// grammar says should consume its entire input.
	ErrTrailingData = errors.New("x509: trailing data after ASN.1 structure")
)

// Context-class tag helpers.
//
// In the GeneralName CHOICE every alternative is a context-specific tag. An
// IMPLICIT alternative replaces the underlying type's tag with the context tag
// (primitive bit preserved for primitive types, e.g. rfc822Name[1] is
// 0x81). An EXPLICIT alternative wraps the underlying TLV inside a constructed
// context tag (e.g. otherName's value [0] EXPLICIT, which is 0xA0 around the
// inner element). directoryName[4] holds a constructed Name, so it is
// effectively constructed-explicit as well (0xA4).
//
// contextTag builds the cryptobyte asn1.Tag for context number n.
//
//	constructed=false → IMPLICIT primitive (e.g. rfc822Name[1] = 0x81)
//	constructed=true  → constructed context (EXPLICIT wrapper or implicit
//	                    constructed type, e.g. otherName[0] = 0xA0)
func contextTag(n int, constructed bool) cbasn1.Tag {
	t := cbasn1.Tag(uint8(n)).ContextSpecific()
	if constructed {
		t = t.Constructed()
	}
	return t
}

// readContextExplicit reads a constructed context-tagged wrapper [n] EXPLICIT
// and returns the inner element's bytes (the wrapper's tag/length stripped, the
// inner TLV intact). Used for otherName's value [0] EXPLICIT. The caller then
// parses the inner element itself.
func readContextExplicit(in *cryptobyte.String, n int) ([]byte, error) {
	var child cryptobyte.String
	if !in.ReadASN1(&child, contextTag(n, true)) {
		if in.Empty() {
			return nil, ErrTruncated
		}
		return nil, ErrUnexpectedTag
	}
	return []byte(child), nil
}

// addContextImplicit appends a context-tagged element [n] IMPLICIT whose content
// is produced by f. Pass constructed=true for arms whose underlying type is
// constructed (e.g. directoryName[4] wrapping a SEQUENCE).
func addContextImplicit(b *cryptobyte.Builder, n int, constructed bool, f func(*cryptobyte.Builder)) {
	b.AddASN1(contextTag(n, constructed), f)
}

// addContextExplicit appends a constructed context-tagged wrapper [n] EXPLICIT
// around the element(s) produced by f. Encode counterpart of
// readContextExplicit.
func addContextExplicit(b *cryptobyte.Builder, n int, f func(*cryptobyte.Builder)) {
	b.AddASN1(contextTag(n, true), f)
}

// buildBytes finalizes a builder, wrapping any builder-level error with package
// context so a construction failure surfaces as a descriptive, returnable error
// rather than a bare cryptobyte error or a panic. Helpers that construct DER
// through cryptobyte should end with this.
func buildBytes(b *cryptobyte.Builder) ([]byte, error) {
	out, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("x509: encoding DER: %w", err)
	}
	return out, nil
}
