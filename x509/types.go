package x509

import (
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
)

// GeneralName is the shared contract for the nine RFC 5280 GeneralName CHOICE
// alternatives (rfc5280.txt:2093-2102). It is an interface rather than a
// multi-field struct so that illegal multi-arm states are unrepresentable.
//
// The concrete arms, their CHOICE tag numbers, and the files they live in:
//
//	OtherName      [0]  othername.go
//	RFC822Name     [1]  generalname.go
//	DNSName        [2]  generalname.go
//	X400Address    [3]  oraddress.go
//	DirectoryName  [4]  oraddress.go
//	EDIPartyName   [5]  edipartyname.go
//	URIName        [6]  generalname.go
//	IPAddressName  [7]  generalname.go
//	RegisteredID   [8]  generalname.go
//
// Each arm carries its typed projection (plus a RawPreserve for CHOICE-of-string
// and ANY leaves), reports its context number from tagNumber, and serializes
// itself — including its own outer context tag — through encodeInto. encodeInto
// writes the fully context-tagged DER for the arm (e.g. RFC822Name writes the
// [1] IMPLICIT IA5String element 0x81…, OtherName the [0] constructed element
// 0xA0…); it never panics, reporting malformed state via b.SetError. The
// dispatcher in generalname.go calls encodeInto for each name in turn.
type GeneralName interface {
	// isGeneralName is an unexported marker so only types in this package can
	// satisfy the interface.
	isGeneralName()
	// tagNumber returns the GeneralName CHOICE context number (0..8).
	tagNumber() int
	// encodeInto appends the fully context-tagged DER encoding of this name to
	// b. On malformed internal state it calls b.SetError rather than panicking.
	encodeInto(b *cryptobyte.Builder) error
}

// RawPreserve gives a value a byte-exact round-trip: it holds the verbatim DER a
// leaf was decoded from and replays it on re-encode unless the typed projection
// has been mutated. Every CHOICE-of-string and ANY-typed leaf embeds one, since
// the typed projection alone would canonicalize differently — the classic case
// being a TeletexString DN that re-encodes as PrintableString through
// pkix.RDNSequence.
//
// The contract:
//   - decode: capture the leaf's exact DER into Raw and leave Modified false;
//     also fill in the owning type's typed fields.
//   - mutation: a caller that changes the typed projection must call MarkModified
//     so the now-stale Raw is not replayed.
//   - encode: call Emit(canonical) — Raw verbatim when unmodified, otherwise the
//     caller's freshly canonicalized DER.
//
// It is embedded in the heavier arms (DirectoryName, EDIPartyName's two
// DirectoryStrings, OtherName's value, each RDN attribute value). Primitives with
// no canonical ambiguity — IA5String, OCTET STRING, OID — do not need it.
type RawPreserve struct {
	// Raw is the verbatim DER captured at decode (the complete TLV of the leaf).
	// Empty when the value was constructed programmatically rather than decoded.
	Raw asn1.RawValue
	// Modified is the dirty-bit. False means Raw is authoritative and may be
	// re-emitted verbatim; true means the typed projection changed and the
	// encoder must canonicalize.
	Modified bool
}

// MarkModified records that the typed projection has been mutated, so Emit will
// canonicalize from the typed value instead of replaying Raw.
func (p *RawPreserve) MarkModified() { p.Modified = true }

// HasRaw reports whether a verbatim decode capture is available for replay.
func (p *RawPreserve) HasRaw() bool { return !p.Modified && len(p.Raw.FullBytes) > 0 }

// Emit returns the bytes to write for this leaf. When an unmodified raw capture
// exists it is returned verbatim (byte-exact round-trip); otherwise the
// caller-supplied canonical DER is returned. canonical may be nil when the
// caller knows HasRaw() is true.
func (p *RawPreserve) Emit(canonical []byte) []byte {
	if p.HasRaw() {
		return p.Raw.FullBytes
	}
	return canonical
}

// capture stores the verbatim TLV bytes as the preserved raw value and clears
// the dirty-bit. Helper for decoders.
func (p *RawPreserve) capture(fullBytes []byte) {
	p.Raw = asn1.RawValue{FullBytes: fullBytes}
	p.Modified = false
}
