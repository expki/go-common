package x509

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// This file implements two of the nine GeneralName CHOICE arms (types.go):
//
//	x400Address   [3]  X400Address    full structured X.400 ORAddress
//	directoryName [4]  DirectoryName  pkix.RDNSequence projection + raw preserve
//
// Both are built directly with cryptobyte: the X.400 OR-address uses
// [APPLICATION n] CHOICE and IMPLICIT context tags that encoding/asn1 cannot
// express, and the directoryName arm must round-trip a TeletexString / BMPString
// DN byte-exactly (which pkix.RDNSequence alone cannot — it would canonicalize
// the string tag). DirectoryName therefore re-emits its captured raw Name DER
// verbatim unless the typed projection was mutated.
//
// ORAddress grammar: rfc5280.txt:6594-6711 (with PDS sub-types and upper bounds
// continuing through rfc5280.txt:6937).

// applicationClass is the ASN.1 identifier-octet class bits for [APPLICATION n]
// tags (bit 7 set, bit 8 clear = 0x40). cryptobyte's asn1 package only exports
// helpers for the context-specific and constructed classes, so the X.400
// CountryName [APPLICATION 1] and AdministrationDomainName [APPLICATION 2]
// wrappers build their tag here. Only the low-tag-number form is needed (n < 31).
const applicationClass = 0x40

// applicationTag builds the cryptobyte asn1.Tag for [APPLICATION n]. The
// constructed bit is set because both APPLICATION-tagged ORAddress members
// (CountryName, AdministrationDomainName) wrap a CHOICE and are encoded
// constructed on the wire.
func applicationTag(n int) cbasn1.Tag {
	return cbasn1.Tag(uint8(n) | applicationClass | 0x20)
}

// -----------------------------------------------------------------------------
// X.400 ORAddress
// -----------------------------------------------------------------------------

// X400Address is the x400Address [3] GeneralName arm: a fully structured X.400
// OR-address (ORAddress, rfc5280.txt:6594). It carries the typed projection of
// every built-in standard attribute, the optional built-in domain-defined
// attributes, and the optional extension attributes.
//
// Byte-exact round-trip is achieved structurally: every leaf string preserves
// the exact ASN.1 string tag it was decoded under (PrintableString vs
// TeletexString vs NumericString are distinct, non-collapsing tags), and the
// ANY-DEFINED-BY value inside each ExtensionAttribute is preserved verbatim.
type X400Address struct {
	ORAddress ORAddress
}

func (X400Address) isGeneralName() {}
func (X400Address) tagNumber() int { return 3 }

func (x X400Address) encodeInto(b *cryptobyte.Builder) error {
	// x400Address [3] IMPLICIT ORAddress. ORAddress is a SEQUENCE; the IMPLICIT
	// tag REPLACES the SEQUENCE's universal tag, so the [3] constructed element's
	// content is the ORAddress SEQUENCE body, not a nested SEQUENCE TLV.
	body, err := x.ORAddress.marshalBody()
	if err != nil {
		b.SetError(err)
		return err
	}
	addContextImplicit(b, 3, true, func(child *cryptobyte.Builder) {
		child.AddBytes(body)
	})
	return nil
}

// ORAddress models ORAddress ::= SEQUENCE (rfc5280.txt:6594).
type ORAddress struct {
	BuiltInStandard      BuiltInStandardAttributes
	BuiltInDomainDefined []BuiltInDomainDefinedAttribute // OPTIONAL; nil when absent
	ExtensionAttributes  []ExtensionAttribute            // OPTIONAL; nil when absent
}

// BuiltInStandardAttributes models BuiltInStandardAttributes ::= SEQUENCE
// (rfc5280.txt:6617). Every member is OPTIONAL; pointer/slice nil-ness records
// presence so an absent member is never re-emitted (preserving byte-exactness).
type BuiltInStandardAttributes struct {
	CountryName           *CountryName          // [APPLICATION 1] CHOICE
	AdministrationDomain  *AdministrationDomain // [APPLICATION 2] CHOICE
	NetworkAddress        *ASN1String           // [0] IMPLICIT NumericString
	TerminalIdentifier    *ASN1String           // [1] IMPLICIT PrintableString
	PrivateDomain         *PrivateDomainName    // [2] CHOICE (no IMPLICIT)
	OrganizationName      *ASN1String           // [3] IMPLICIT PrintableString
	NumericUserIdentifier *ASN1String           // [4] IMPLICIT NumericString
	PersonalName          *PersonalName         // [5] IMPLICIT SET
	OrganizationalUnits   []ASN1String          // [6] IMPLICIT SEQUENCE OF PrintableString
}

// ASN1String preserves both the chosen ASN.1 string tag and its content so that
// re-encoding reproduces the exact bytes. The X.400 grammar mixes NumericString,
// PrintableString and TeletexString; collapsing them would break round-trip.
type ASN1String struct {
	Tag   cbasn1.Tag // the underlying universal string tag (e.g. NumericString=18)
	Value string     // decoded content (the bytes between the leaf's length and end)
}

// numericString and the other universal string tags used by the X.400 grammar.
// cryptobyte's asn1 package omits the rarer ones, so they are named here.
const (
	tagNumericString   = cbasn1.Tag(18)
	tagPrintableString = cbasn1.PrintableString // 19
	tagTeletexString   = cbasn1.T61String       // 20 (TeletexString == T61String)
)

// CountryName models CountryName ::= [APPLICATION 1] CHOICE { x121-dcc-code
// NumericString, iso-3166-alpha2-code PrintableString } (rfc5280.txt:6634).
type CountryName struct {
	Value ASN1String // tag is NumericString or PrintableString
}

// AdministrationDomain models AdministrationDomainName ::= [APPLICATION 2]
// CHOICE { numeric NumericString, printable PrintableString }
// (rfc5280.txt:6640).
type AdministrationDomain struct {
	Value ASN1String
}

// PrivateDomainName models PrivateDomainName ::= CHOICE { numeric NumericString,
// printable PrintableString } (rfc5280.txt:6650). It is reached through the
// [2] context tag of BuiltInStandardAttributes, which is NOT marked IMPLICIT in
// the module, so the [2] wrapper is EXPLICIT around the CHOICE's chosen string.
type PrivateDomainName struct {
	Value ASN1String
}

// PersonalName models PersonalName ::= SET (rfc5280.txt:6671). All members are
// IMPLICIT PrintableString. Surname is mandatory; the rest are OPTIONAL.
type PersonalName struct {
	Surname             ASN1String  // [0] IMPLICIT PrintableString
	GivenName           *ASN1String // [1] IMPLICIT PrintableString OPTIONAL
	Initials            *ASN1String // [2] IMPLICIT PrintableString OPTIONAL
	GenerationQualifier *ASN1String // [3] IMPLICIT PrintableString OPTIONAL
}

// BuiltInDomainDefinedAttribute models BuiltInDomainDefinedAttribute ::=
// SEQUENCE { type PrintableString, value PrintableString } (rfc5280.txt:6696).
type BuiltInDomainDefinedAttribute struct {
	Type  ASN1String
	Value ASN1String
}

// ExtensionAttribute models ExtensionAttribute ::= SEQUENCE {
//
//	extension-attribute-type  [0] IMPLICIT INTEGER,
//	extension-attribute-value [1] ANY DEFINED BY extension-attribute-type }
//
// (rfc5280.txt:6707). The value is an open ANY selected by 23 distinct PDS
// sub-types; modeling each would not improve fidelity over preserving the exact
// inner TLV, since the value is genuinely ANY. The [1] wrapper is EXPLICIT, so
// Value holds the complete inner TLV (tag+length+content) verbatim.
type ExtensionAttribute struct {
	Type  int
	Value asn1.RawValue // the ANY value's full TLV, preserved byte-exact
}

// -----------------------------------------------------------------------------
// ORAddress decode
// -----------------------------------------------------------------------------

// parseX400Address decodes the content of an x400Address [3] GeneralName arm.
// Because x400Address is [3] IMPLICIT ORAddress and ORAddress is a SEQUENCE, the
// IMPLICIT tag replaced the SEQUENCE tag on the wire: content is therefore the
// ORAddress SEQUENCE body (the members), not a nested SEQUENCE TLV. It never
// panics; malformed input yields a sentinel error.
func parseX400Address(content cryptobyte.String) (X400Address, error) {
	or, err := parseORAddressBody(content)
	if err != nil {
		return X400Address{}, err
	}
	return X400Address{ORAddress: *or}, nil
}

// parseORAddressBody decodes the body (members) of an ORAddress SEQUENCE — the
// SEQUENCE tag/length already stripped by the IMPLICIT [3] context tag.
func parseORAddressBody(seq cryptobyte.String) (*ORAddress, error) {
	out := &ORAddress{}
	if err := parseBuiltInStandard(&seq, &out.BuiltInStandard); err != nil {
		return nil, err
	}

	// built-in-domain-defined-attributes BuiltInDomainDefinedAttributes OPTIONAL
	// — an untagged SEQUENCE OF, so it is recognised by its SEQUENCE tag.
	if peekTag(seq, cbasn1.SEQUENCE) {
		bdda, err := parseBuiltInDomainDefined(&seq)
		if err != nil {
			return nil, err
		}
		out.BuiltInDomainDefined = bdda
	}

	// extension-attributes ExtensionAttributes OPTIONAL — a SET OF, recognised
	// by its SET tag.
	if peekTag(seq, cbasn1.SET) {
		ea, err := parseExtensionAttributes(&seq)
		if err != nil {
			return nil, err
		}
		out.ExtensionAttributes = ea
	}

	if !seq.Empty() {
		return nil, ErrTrailingData
	}
	return out, nil
}

// peekTag reports whether the next element in s carries the given tag, without
// consuming it.
func peekTag(s cryptobyte.String, tag cbasn1.Tag) bool {
	if len(s) == 0 {
		return false
	}
	return cbasn1.Tag(s[0]) == tag
}

// peekIdentifier reports whether the next element's identifier octet equals the
// given raw identifier byte (class+constructed+number), without consuming it.
func peekIdentifier(s cryptobyte.String, id byte) bool {
	return len(s) > 0 && s[0] == id
}

func parseBuiltInStandard(in *cryptobyte.String, out *BuiltInStandardAttributes) error {
	var body cryptobyte.String
	if !in.ReadASN1(&body, cbasn1.SEQUENCE) {
		return ErrUnexpectedTag
	}

	// country-name CountryName OPTIONAL — [APPLICATION 1].
	if peekIdentifier(body, byte(applicationTag(1))) {
		s, err := readApplicationString(&body, 1)
		if err != nil {
			return err
		}
		out.CountryName = &CountryName{Value: s}
	}
	// administration-domain-name AdministrationDomainName OPTIONAL — [APPLICATION 2].
	if peekIdentifier(body, byte(applicationTag(2))) {
		s, err := readApplicationString(&body, 2)
		if err != nil {
			return err
		}
		out.AdministrationDomain = &AdministrationDomain{Value: s}
	}
	// network-address [0] IMPLICIT NumericString OPTIONAL.
	if peekIdentifier(body, byte(contextTag(0, false))) {
		s, err := readImplicitString(&body, 0, tagNumericString)
		if err != nil {
			return err
		}
		out.NetworkAddress = &s
	}
	// terminal-identifier [1] IMPLICIT PrintableString OPTIONAL.
	if peekIdentifier(body, byte(contextTag(1, false))) {
		s, err := readImplicitString(&body, 1, tagPrintableString)
		if err != nil {
			return err
		}
		out.TerminalIdentifier = &s
	}
	// private-domain-name [2] PrivateDomainName OPTIONAL — EXPLICIT wrapper (the
	// CHOICE has no IMPLICIT keyword in the module), so [2] is constructed.
	if peekIdentifier(body, byte(contextTag(2, true))) {
		var wrap cryptobyte.String
		if !body.ReadASN1(&wrap, contextTag(2, true)) {
			return ErrUnexpectedTag
		}
		s, err := readAnyString(&wrap)
		if err != nil {
			return err
		}
		if !wrap.Empty() {
			return ErrTrailingData
		}
		out.PrivateDomain = &PrivateDomainName{Value: s}
	}
	// organization-name [3] IMPLICIT PrintableString OPTIONAL.
	if peekIdentifier(body, byte(contextTag(3, false))) {
		s, err := readImplicitString(&body, 3, tagPrintableString)
		if err != nil {
			return err
		}
		out.OrganizationName = &s
	}
	// numeric-user-identifier [4] IMPLICIT NumericString OPTIONAL.
	if peekIdentifier(body, byte(contextTag(4, false))) {
		s, err := readImplicitString(&body, 4, tagNumericString)
		if err != nil {
			return err
		}
		out.NumericUserIdentifier = &s
	}
	// personal-name [5] IMPLICIT PersonalName OPTIONAL — a SET, so [5] constructed.
	if peekIdentifier(body, byte(contextTag(5, true))) {
		pn, err := parsePersonalName(&body)
		if err != nil {
			return err
		}
		out.PersonalName = pn
	}
	// organizational-unit-names [6] IMPLICIT SEQUENCE OF PrintableString OPTIONAL.
	if peekIdentifier(body, byte(contextTag(6, true))) {
		ous, err := parseOrganizationalUnits(&body)
		if err != nil {
			return err
		}
		out.OrganizationalUnits = ous
	}

	if !body.Empty() {
		return ErrTrailingData
	}
	return nil
}

// readApplicationString reads an [APPLICATION n] CHOICE-of-string wrapper and
// returns the chosen string with its tag preserved. The APPLICATION wrapper is
// constructed; inside is a single primitive string (NumericString or
// PrintableString).
func readApplicationString(in *cryptobyte.String, n int) (ASN1String, error) {
	var wrap cryptobyte.String
	if !in.ReadASN1(&wrap, applicationTag(n)) {
		return ASN1String{}, ErrUnexpectedTag
	}
	s, err := readAnyString(&wrap)
	if err != nil {
		return ASN1String{}, err
	}
	if !wrap.Empty() {
		return ASN1String{}, ErrTrailingData
	}
	return s, nil
}

// readImplicitString reads a [n] IMPLICIT primitive string. The IMPLICIT tag
// replaces the universal string tag on the wire, so the original tag is supplied
// by the grammar (universalTag) and recorded for faithful re-encode.
func readImplicitString(in *cryptobyte.String, n int, universalTag cbasn1.Tag) (ASN1String, error) {
	var child cryptobyte.String
	if !in.ReadASN1(&child, contextTag(n, false)) {
		return ASN1String{}, ErrUnexpectedTag
	}
	return ASN1String{Tag: universalTag, Value: string(child)}, nil
}

// readAnyString reads one primitive string element of any universal string tag,
// preserving the tag. Used inside CHOICE wrappers where the chosen tag must be
// observed rather than assumed.
func readAnyString(in *cryptobyte.String) (ASN1String, error) {
	var child cryptobyte.String
	var tag cbasn1.Tag
	if !in.ReadAnyASN1(&child, &tag) {
		return ASN1String{}, ErrTruncated
	}
	return ASN1String{Tag: tag, Value: string(child)}, nil
}

func parsePersonalName(in *cryptobyte.String) (*PersonalName, error) {
	var body cryptobyte.String
	if !in.ReadASN1(&body, contextTag(5, true)) {
		return nil, ErrUnexpectedTag
	}
	pn := &PersonalName{}
	// surname [0] IMPLICIT PrintableString — mandatory.
	if !peekIdentifier(body, byte(contextTag(0, false))) {
		return nil, ErrUnexpectedTag
	}
	surname, err := readImplicitString(&body, 0, tagPrintableString)
	if err != nil {
		return nil, err
	}
	pn.Surname = surname
	// given-name [1], initials [2], generation-qualifier [3] — all OPTIONAL
	// IMPLICIT PrintableString, in order.
	if peekIdentifier(body, byte(contextTag(1, false))) {
		s, err := readImplicitString(&body, 1, tagPrintableString)
		if err != nil {
			return nil, err
		}
		pn.GivenName = &s
	}
	if peekIdentifier(body, byte(contextTag(2, false))) {
		s, err := readImplicitString(&body, 2, tagPrintableString)
		if err != nil {
			return nil, err
		}
		pn.Initials = &s
	}
	if peekIdentifier(body, byte(contextTag(3, false))) {
		s, err := readImplicitString(&body, 3, tagPrintableString)
		if err != nil {
			return nil, err
		}
		pn.GenerationQualifier = &s
	}
	if !body.Empty() {
		return nil, ErrTrailingData
	}
	return pn, nil
}

func parseOrganizationalUnits(in *cryptobyte.String) ([]ASN1String, error) {
	var body cryptobyte.String
	if !in.ReadASN1(&body, contextTag(6, true)) {
		return nil, ErrUnexpectedTag
	}
	var out []ASN1String
	for !body.Empty() {
		s, err := readAnyString(&body)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

func parseBuiltInDomainDefined(in *cryptobyte.String) ([]BuiltInDomainDefinedAttribute, error) {
	var body cryptobyte.String
	if !in.ReadASN1(&body, cbasn1.SEQUENCE) {
		return nil, ErrUnexpectedTag
	}
	var out []BuiltInDomainDefinedAttribute
	for !body.Empty() {
		var item cryptobyte.String
		if !body.ReadASN1(&item, cbasn1.SEQUENCE) {
			return nil, ErrUnexpectedTag
		}
		typ, err := readAnyString(&item)
		if err != nil {
			return nil, err
		}
		val, err := readAnyString(&item)
		if err != nil {
			return nil, err
		}
		if !item.Empty() {
			return nil, ErrTrailingData
		}
		out = append(out, BuiltInDomainDefinedAttribute{Type: typ, Value: val})
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

func parseExtensionAttributes(in *cryptobyte.String) ([]ExtensionAttribute, error) {
	var body cryptobyte.String
	if !in.ReadASN1(&body, cbasn1.SET) {
		return nil, ErrUnexpectedTag
	}
	var out []ExtensionAttribute
	for !body.Empty() {
		var item cryptobyte.String
		if !body.ReadASN1(&item, cbasn1.SEQUENCE) {
			return nil, ErrUnexpectedTag
		}
		// extension-attribute-type [0] IMPLICIT INTEGER.
		var typ int64
		if !item.ReadASN1Int64WithTag(&typ, contextTag(0, false)) {
			return nil, ErrUnexpectedTag
		}
		// extension-attribute-value [1] EXPLICIT ANY — the [1] wrapper is
		// constructed and the inner ANY TLV is preserved verbatim.
		var wrap cryptobyte.String
		if !item.ReadASN1(&wrap, contextTag(1, true)) {
			return nil, ErrUnexpectedTag
		}
		var anyTLV cryptobyte.String
		var anyTag cbasn1.Tag
		if !wrap.ReadAnyASN1Element(&anyTLV, &anyTag) {
			return nil, ErrTruncated
		}
		if !wrap.Empty() {
			return nil, ErrTrailingData
		}
		if !item.Empty() {
			return nil, ErrTrailingData
		}
		out = append(out, ExtensionAttribute{
			Type:  int(typ),
			Value: asn1.RawValue{FullBytes: append([]byte(nil), anyTLV...)},
		})
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// ORAddress encode
// -----------------------------------------------------------------------------

// marshalBody produces the ORAddress SEQUENCE members WITHOUT the surrounding
// SEQUENCE tag/length. The x400Address [3] IMPLICIT context tag supplies the
// constructed wrapper, so only the body is needed.
func (o *ORAddress) marshalBody() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	o.encodeMembers(b)
	return buildBytes(b)
}

// encodeMembers appends the ORAddress members to b (no SEQUENCE wrapper).
func (o *ORAddress) encodeMembers(seq *cryptobyte.Builder) {
	o.BuiltInStandard.encode(seq)
	if len(o.BuiltInDomainDefined) > 0 {
		seq.AddASN1(cbasn1.SEQUENCE, func(s *cryptobyte.Builder) {
			for _, a := range o.BuiltInDomainDefined {
				s.AddASN1(cbasn1.SEQUENCE, func(item *cryptobyte.Builder) {
					a.Type.encode(item)
					a.Value.encode(item)
				})
			}
		})
	}
	if len(o.ExtensionAttributes) > 0 {
		// ExtensionAttributes is a SET OF, so its members MUST be emitted in
		// ascending bytewise order of their full DER encodings (X.690 §11.6).
		// Encode each element independently, sort, then append — sorting
		// already-canonical input is a no-op, so a decode→encode of sorted DER
		// stays byte-exact while a programmatically-built unsorted set is
		// canonicalized.
		elems := make([][]byte, 0, len(o.ExtensionAttributes))
		for _, a := range o.ExtensionAttributes {
			var eb cryptobyte.Builder
			eb.AddASN1(cbasn1.SEQUENCE, func(item *cryptobyte.Builder) {
				item.AddASN1Int64WithTag(int64(a.Type), contextTag(0, false))
				addContextExplicit(item, 1, func(w *cryptobyte.Builder) {
					w.AddBytes(a.Value.FullBytes)
				})
			})
			b, err := eb.Bytes()
			if err != nil {
				seq.SetError(err)
				return
			}
			elems = append(elems, b)
		}
		sortDERSetOf(elems)
		seq.AddASN1(cbasn1.SET, func(s *cryptobyte.Builder) {
			for _, e := range elems {
				s.AddBytes(e)
			}
		})
	}
}

// sortDERSetOf orders the encoded members of a SET OF in ascending bytewise
// (lexicographic) order of their complete DER encodings, as DER requires
// (X.690 §11.6). bytes.Compare gives the correct shortest-then-lexicographic
// ordering for already-length-prefixed TLVs.
func sortDERSetOf(elems [][]byte) {
	sort.Slice(elems, func(i, j int) bool {
		return bytes.Compare(elems[i], elems[j]) < 0
	})
}

// encode writes a string leaf using its preserved tag.
func (s ASN1String) encode(b *cryptobyte.Builder) {
	b.AddASN1(s.Tag, func(c *cryptobyte.Builder) {
		c.AddBytes([]byte(s.Value))
	})
}

// encodeImplicit writes a string leaf under a [n] IMPLICIT context tag (the
// universal string tag is dropped on the wire).
func (s ASN1String) encodeImplicit(b *cryptobyte.Builder, n int) {
	addContextImplicit(b, n, false, func(c *cryptobyte.Builder) {
		c.AddBytes([]byte(s.Value))
	})
}

func (a *BuiltInStandardAttributes) encode(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		if a.CountryName != nil {
			seq.AddASN1(applicationTag(1), func(w *cryptobyte.Builder) {
				a.CountryName.Value.encode(w)
			})
		}
		if a.AdministrationDomain != nil {
			seq.AddASN1(applicationTag(2), func(w *cryptobyte.Builder) {
				a.AdministrationDomain.Value.encode(w)
			})
		}
		if a.NetworkAddress != nil {
			a.NetworkAddress.encodeImplicit(seq, 0)
		}
		if a.TerminalIdentifier != nil {
			a.TerminalIdentifier.encodeImplicit(seq, 1)
		}
		if a.PrivateDomain != nil {
			addContextExplicit(seq, 2, func(w *cryptobyte.Builder) {
				a.PrivateDomain.Value.encode(w)
			})
		}
		if a.OrganizationName != nil {
			a.OrganizationName.encodeImplicit(seq, 3)
		}
		if a.NumericUserIdentifier != nil {
			a.NumericUserIdentifier.encodeImplicit(seq, 4)
		}
		if a.PersonalName != nil {
			a.PersonalName.encode(seq)
		}
		if len(a.OrganizationalUnits) > 0 {
			addContextImplicit(seq, 6, true, func(w *cryptobyte.Builder) {
				for _, ou := range a.OrganizationalUnits {
					ou.encode(w)
				}
			})
		}
	})
}

func (p *PersonalName) encode(b *cryptobyte.Builder) {
	addContextImplicit(b, 5, true, func(set *cryptobyte.Builder) {
		p.Surname.encodeImplicit(set, 0)
		if p.GivenName != nil {
			p.GivenName.encodeImplicit(set, 1)
		}
		if p.Initials != nil {
			p.Initials.encodeImplicit(set, 2)
		}
		if p.GenerationQualifier != nil {
			p.GenerationQualifier.encodeImplicit(set, 3)
		}
	})
}

// -----------------------------------------------------------------------------
// directoryName [4]
// -----------------------------------------------------------------------------

// DirectoryName is the directoryName [4] GeneralName arm. It projects the X.501
// Name (an RDNSequence) into pkix.RDNSequence for typed access, while preserving
// the exact Name DER captured at decode so that a DN bearing TeletexString /
// BMPString attribute values round-trips byte-exactly.
//
// On encode the preserved raw Name TLV is replayed verbatim unless the caller
// mutated the projection (RawPreserve.Modified). When no raw capture exists (the
// value was built programmatically), the RDNSequence is marshalled canonically.
type DirectoryName struct {
	// RawPreserve is embedded per the types.go / generalname.go contract so the
	// dirty-bit machinery (HasRaw/MarkModified/Emit) is reachable directly. It
	// holds the verbatim Name SEQUENCE TLV captured at decode.
	RawPreserve
	// RDNs is the typed projection of the X.501 Name.
	RDNs pkix.RDNSequence
}

func (DirectoryName) isGeneralName() {}
func (DirectoryName) tagNumber() int { return 4 }

func (d DirectoryName) encodeInto(b *cryptobyte.Builder) error {
	// directoryName [4] holds a constructed Name (an RDNSequence SEQUENCE). The
	// CHOICE alternative is EXPLICIT-equivalent: the [4] context tag wraps the
	// inner Name SEQUENCE TLV intact.
	var nameDER []byte
	if d.HasRaw() {
		nameDER = d.Raw.FullBytes
	} else {
		canonical, err := asn1.Marshal(d.RDNs)
		if err != nil {
			b.SetError(err)
			return err
		}
		nameDER = canonical
	}
	addContextExplicit(b, 4, func(child *cryptobyte.Builder) {
		child.AddBytes(nameDER)
	})
	return nil
}

// parseDirectoryName decodes the content of a directoryName [4] GeneralName arm.
// directoryName is [4] EXPLICIT-equivalent around a Name (because Name is itself
// a CHOICE/RDNSequence), so content is the inner Name SEQUENCE TLV intact. It
// captures that exact Name DER for byte-exact re-emission (a TeletexString /
// BMPString DN would otherwise be canonicalized away by pkix.RDNSequence) and
// projects it into a pkix.RDNSequence.
func parseDirectoryName(content cryptobyte.String) (DirectoryName, error) {
	// The [4] content is a single Name SEQUENCE element; capture its full TLV.
	var nameTLV cryptobyte.String
	if !content.ReadASN1Element(&nameTLV, cbasn1.SEQUENCE) {
		return DirectoryName{}, ErrUnexpectedTag
	}
	if !content.Empty() {
		return DirectoryName{}, ErrTrailingData
	}
	full := append([]byte(nil), nameTLV...)

	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(full, &rdns); err != nil {
		return DirectoryName{}, fmt.Errorf("x509: directoryName: %w", err)
	} else if len(rest) != 0 {
		return DirectoryName{}, ErrTrailingData
	}

	d := DirectoryName{RDNs: rdns}
	d.capture(full)
	return d, nil
}
