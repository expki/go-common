package x509

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"sort"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Extension is the generic, OID-keyed view of one X.509v3 extension. Value is
// the raw DER of the extension's value (the content inside the extension's
// OCTET STRING wrapper, i.e. what crypto/x509 exposes as pkix.Extension.Value).
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// =============================================================================
// KeyUsage (id-ce 15) — BIT STRING.  encoding/asn1 permitted (no CHOICE/SET-OF).
// =============================================================================

// KeyUsage models the KeyUsage BIT STRING (rfc5280.txt:7017-7027) as a bitmask.
// Bit 0 (digitalSignature) is the most significant bit of the first content
// byte, per DER BIT STRING numbering.
type KeyUsage uint16

const (
	KeyUsageDigitalSignature KeyUsage = 1 << (15 - iota)
	KeyUsageNonRepudiation            // a.k.a. contentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageKeyCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// ParseKeyUsage decodes the KeyUsage extension value.
func ParseKeyUsage(der []byte) (KeyUsage, error) {
	var bits asn1.BitString
	rest, err := asn1.Unmarshal(der, &bits)
	if err != nil {
		return 0, fmt.Errorf("x509: KeyUsage: %w", err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: KeyUsage", ErrTrailingData)
	}
	var ku KeyUsage
	for i := 0; i < 9; i++ {
		if bits.At(i) != 0 {
			ku |= 1 << (15 - i)
		}
	}
	return ku, nil
}

// Marshal encodes the KeyUsage extension value, trimming trailing zero bits per
// DER (the canonical minimal-length BIT STRING).
func (ku KeyUsage) Marshal() ([]byte, error) {
	// Find the highest set bit (0..8) to determine the bit length.
	bitLen := 0
	for i := 0; i < 9; i++ {
		if ku&(1<<(15-i)) != 0 {
			bitLen = i + 1
		}
	}
	nBytes := (bitLen + 7) / 8
	bytesOut := make([]byte, nBytes)
	for i := 0; i < bitLen; i++ {
		if ku&(1<<(15-i)) != 0 {
			bytesOut[i/8] |= 0x80 >> (uint(i) % 8)
		}
	}
	bs := asn1.BitString{Bytes: bytesOut, BitLength: bitLen}
	out, err := asn1.Marshal(bs)
	if err != nil {
		return nil, fmt.Errorf("x509: KeyUsage marshal: %w", err)
	}
	return out, nil
}

// =============================================================================
// BasicConstraints (id-ce 19).  encoding/asn1 permitted (fixed shape).
// =============================================================================

// BasicConstraints models BasicConstraints (rfc5280.txt:7155-7157). PathLen is
// honored only when PathLenValid (so a 0 path length is distinguishable from
// "absent"). On marshal, cA=false is omitted (DEFAULT) for canonical DER.
type BasicConstraints struct {
	IsCA         bool
	PathLen      int
	PathLenValid bool
}

// ParseBasicConstraints decodes the BasicConstraints extension value.
func ParseBasicConstraints(der []byte) (*BasicConstraints, error) {
	// Decode generically so we can tell whether pathLenConstraint was present.
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: BasicConstraints SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: BasicConstraints", ErrTrailingData)
	}
	bc := &BasicConstraints{}
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) {
		if !seq.ReadASN1Boolean(&bc.IsCA) {
			return nil, fmt.Errorf("%w: BasicConstraints cA", ErrTruncated)
		}
	}
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		var pathLen int
		if !seq.ReadASN1Integer(&pathLen) {
			return nil, fmt.Errorf("%w: BasicConstraints pathLen", ErrTruncated)
		}
		bc.PathLen = pathLen
		bc.PathLenValid = true
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: BasicConstraints fields", ErrTrailingData)
	}
	return bc, nil
}

// Marshal encodes the BasicConstraints extension value as canonical DER: cA is
// omitted when false (DEFAULT FALSE), and pathLenConstraint is emitted whenever
// valid — even a 0 value (which encoding/asn1's optional-int would wrongly drop).
// This matches stdlib output and keeps the builder de-dup invariant.
func (bc *BasicConstraints) Marshal() ([]byte, error) {
	if bc == nil {
		return nil, fmt.Errorf("%w: nil BasicConstraints", ErrTruncated)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		if bc.IsCA {
			c.AddASN1Boolean(true)
		}
		if bc.PathLenValid {
			c.AddASN1Int64(int64(bc.PathLen))
		}
	})
	return b.Bytes()
}

// =============================================================================
// InhibitAnyPolicy (id-ce 54) — INTEGER.  encoding/asn1 permitted.
// =============================================================================

// InhibitAnyPolicy is the SkipCerts INTEGER (rfc5280.txt:7267).
type InhibitAnyPolicy int

// ParseInhibitAnyPolicy decodes the extension value.
func ParseInhibitAnyPolicy(der []byte) (InhibitAnyPolicy, error) {
	var v int
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return 0, fmt.Errorf("x509: InhibitAnyPolicy: %w", err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("%w: InhibitAnyPolicy", ErrTrailingData)
	}
	return InhibitAnyPolicy(v), nil
}

// Marshal encodes the extension value.
func (v InhibitAnyPolicy) Marshal() ([]byte, error) {
	out, err := asn1.Marshal(int(v))
	if err != nil {
		return nil, fmt.Errorf("x509: InhibitAnyPolicy marshal: %w", err)
	}
	return out, nil
}

// =============================================================================
// ExtKeyUsage (id-ce 37) — SEQUENCE OF OID.  cryptobyte.
// =============================================================================

// ExtKeyUsage is ExtKeyUsageSyntax: an ordered list of KeyPurposeId OIDs
// (rfc5280.txt:7246).
type ExtKeyUsage []asn1.ObjectIdentifier

// ParseExtKeyUsage decodes the extension value.
func ParseExtKeyUsage(der []byte) (ExtKeyUsage, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: ExtKeyUsage SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: ExtKeyUsage", ErrTrailingData)
	}
	var eku ExtKeyUsage
	for !seq.Empty() {
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&oid) {
			return nil, fmt.Errorf("%w: ExtKeyUsage KeyPurposeId", ErrTruncated)
		}
		eku = append(eku, oid)
	}
	return eku, nil
}

// Marshal encodes the extension value.
func (eku ExtKeyUsage) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, oid := range eku {
			c.AddASN1ObjectIdentifier(oid)
		}
	})
	return b.Bytes()
}

// =============================================================================
// SubjectKeyIdentifier (id-ce 14) — OCTET STRING.  cryptobyte.
// =============================================================================

// SubjectKeyIdentifier is the KeyIdentifier OCTET STRING (rfc5280.txt:7011).
type SubjectKeyIdentifier []byte

// ParseSubjectKeyIdentifier decodes the extension value.
func ParseSubjectKeyIdentifier(der []byte) (SubjectKeyIdentifier, error) {
	in := cryptobyte.String(der)
	var ki cryptobyte.String
	if !in.ReadASN1(&ki, cbasn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: SubjectKeyIdentifier OCTET STRING", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: SubjectKeyIdentifier", ErrTrailingData)
	}
	return SubjectKeyIdentifier(append([]byte(nil), ki...)), nil
}

// Marshal encodes the extension value.
func (ski SubjectKeyIdentifier) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1OctetString(ski)
	return b.Bytes()
}

// =============================================================================
// AuthorityKeyIdentifier (id-ce 35).  cryptobyte (GeneralNames inside).
// =============================================================================

// AuthorityKeyIdentifier models AKI (rfc5280.txt:6985-6990). All three fields
// are optional; presence is tracked so byte-exact round-trip is possible.
type AuthorityKeyIdentifier struct {
	KeyID                     []byte       // [0] KeyIdentifier OPTIONAL
	AuthorityCertIssuer       GeneralNames // [1] GeneralNames OPTIONAL
	AuthorityCertSerialNumber []byte       // [2] CertificateSerialNumber OPTIONAL (INTEGER content)
}

// ParseAuthorityKeyIdentifier decodes the extension value.
func ParseAuthorityKeyIdentifier(der []byte) (*AuthorityKeyIdentifier, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: AKI SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: AKI", ErrTrailingData)
	}
	aki := &AuthorityKeyIdentifier{}
	// [0] keyIdentifier (primitive context).
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()) {
		var ki cryptobyte.String
		if !seq.ReadASN1(&ki, cbasn1.Tag(0).ContextSpecific()) {
			return nil, fmt.Errorf("%w: AKI keyIdentifier", ErrTruncated)
		}
		aki.KeyID = append([]byte(nil), ki...)
	}
	// [1] authorityCertIssuer GeneralNames (constructed context). The content is
	// a SEQUENCE OF GeneralName; wrap it as a SEQUENCE for parseGeneralNames.
	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var gn cryptobyte.String
		if !seq.ReadASN1(&gn, cbasn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, fmt.Errorf("%w: AKI authorityCertIssuer", ErrTruncated)
		}
		names, err := parseGeneralNamesElements(gn, false)
		if err != nil {
			return nil, err
		}
		aki.AuthorityCertIssuer = names
	}
	// [2] authorityCertSerialNumber (primitive context, INTEGER content).
	if seq.PeekASN1Tag(cbasn1.Tag(2).ContextSpecific()) {
		var sn cryptobyte.String
		if !seq.ReadASN1(&sn, cbasn1.Tag(2).ContextSpecific()) {
			return nil, fmt.Errorf("%w: AKI serialNumber", ErrTruncated)
		}
		aki.AuthorityCertSerialNumber = append([]byte(nil), sn...)
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: AKI fields", ErrTrailingData)
	}
	return aki, nil
}

// Marshal encodes the extension value.
func (aki *AuthorityKeyIdentifier) Marshal() ([]byte, error) {
	if aki == nil {
		return nil, fmt.Errorf("%w: nil AKI", ErrTruncated)
	}
	var b cryptobyte.Builder
	var inner error
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		if aki.KeyID != nil {
			addContextImplicit(c, 0, false, func(v *cryptobyte.Builder) { v.AddBytes(aki.KeyID) })
		}
		if len(aki.AuthorityCertIssuer) > 0 {
			c.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(v *cryptobyte.Builder) {
				for _, n := range aki.AuthorityCertIssuer {
					if err := n.encodeInto(v); err != nil {
						inner = err
						return
					}
				}
			})
		}
		if aki.AuthorityCertSerialNumber != nil {
			addContextImplicit(c, 2, false, func(v *cryptobyte.Builder) { v.AddBytes(aki.AuthorityCertSerialNumber) })
		}
	})
	if inner != nil {
		return nil, inner
	}
	return b.Bytes()
}

// parseGeneralNamesElements parses a cryptobyte.String already positioned at the
// CONTENT of a GeneralNames SEQUENCE (i.e. the [1] context tag was stripped, and
// the bytes are a bare sequence of GeneralName elements). It is used where a
// GeneralNames lives implicitly under a context tag (AKI authorityCertIssuer,
// CRL DistributionPoint fullName, etc.).
func parseGeneralNamesElements(elements cryptobyte.String, nameConstraints bool) (GeneralNames, error) {
	var names GeneralNames
	for !elements.Empty() {
		var elem cryptobyte.String
		var tag cbasn1.Tag
		if !elements.ReadAnyASN1Element(&elem, &tag) {
			return nil, fmt.Errorf("%w: GeneralName element", ErrTruncated)
		}
		var raw asn1.RawValue
		if rest, err := asn1.Unmarshal([]byte(elem), &raw); err != nil {
			return nil, fmt.Errorf("%w: GeneralName element: %v", ErrUnexpectedTag, err)
		} else if len(rest) != 0 {
			return nil, fmt.Errorf("%w: GeneralName element", ErrTrailingData)
		}
		gn, err := parseGeneralName(raw, nameConstraints)
		if err != nil {
			return nil, err
		}
		names = append(names, gn)
	}
	return names, nil
}

// =============================================================================
// SubjectAltName (17) / IssuerAltName (18) — delegate to san.go.
// =============================================================================

// ParseSubjectAltName decodes the SubjectAltName extension value into a SAN.
func ParseSubjectAltName(der []byte) (*SAN, error) { return ParseSAN(der) }

// =============================================================================
// NameConstraints (id-ce 30) — cryptobyte; iPAddress uses 8/32-byte variant.
// =============================================================================

// GeneralSubtree is GeneralSubtree (rfc5280.txt:7185-7188). Minimum DEFAULT 0;
// Maximum OPTIONAL. MinimumPresent/MaximumPresent track presence for byte-exact
// round-trip (minimum is normally omitted when 0).
type GeneralSubtree struct {
	Base           GeneralName
	Minimum        int
	MinimumPresent bool
	Maximum        int
	MaximumPresent bool
}

// NameConstraints is NameConstraints (rfc5280.txt:7179-7181). Both subtree lists
// are optional. Within these subtrees, iPAddress arms use the NameConstraints
// 8/32-byte addr+mask encoding (parsed with nameConstraints=true).
type NameConstraints struct {
	Permitted []GeneralSubtree
	Excluded  []GeneralSubtree
}

// ParseNameConstraints decodes the extension value.
func ParseNameConstraints(der []byte) (*NameConstraints, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: NameConstraints SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: NameConstraints", ErrTrailingData)
	}
	nc := &NameConstraints{}
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, fmt.Errorf("%w: permittedSubtrees", ErrTruncated)
		}
		subtrees, err := parseGeneralSubtrees(sub)
		if err != nil {
			return nil, err
		}
		nc.Permitted = subtrees
	}
	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, fmt.Errorf("%w: excludedSubtrees", ErrTruncated)
		}
		subtrees, err := parseGeneralSubtrees(sub)
		if err != nil {
			return nil, err
		}
		nc.Excluded = subtrees
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: NameConstraints fields", ErrTrailingData)
	}
	return nc, nil
}

// parseGeneralSubtrees decodes the content of a GeneralSubtrees SEQUENCE (the
// context tag already stripped). iPAddress arms decode in NameConstraints mode.
func parseGeneralSubtrees(content cryptobyte.String) ([]GeneralSubtree, error) {
	var out []GeneralSubtree
	for !content.Empty() {
		var st cryptobyte.String
		if !content.ReadASN1(&st, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: GeneralSubtree SEQUENCE", ErrTruncated)
		}
		// base GeneralName (first element).
		var baseElem cryptobyte.String
		var baseTag cbasn1.Tag
		if !st.ReadAnyASN1Element(&baseElem, &baseTag) {
			return nil, fmt.Errorf("%w: GeneralSubtree base", ErrTruncated)
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal([]byte(baseElem), &raw); err != nil {
			return nil, fmt.Errorf("%w: GeneralSubtree base: %v", ErrUnexpectedTag, err)
		}
		base, err := parseGeneralName(raw, true)
		if err != nil {
			return nil, err
		}
		gs := GeneralSubtree{Base: base}
		// minimum [0] DEFAULT 0.
		if st.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()) {
			var minS cryptobyte.String
			if !st.ReadASN1(&minS, cbasn1.Tag(0).ContextSpecific()) {
				return nil, fmt.Errorf("%w: GeneralSubtree minimum", ErrTruncated)
			}
			n, err := decodeIntContent(minS)
			if err != nil {
				return nil, err
			}
			gs.Minimum = n
			gs.MinimumPresent = true
		}
		// maximum [1] OPTIONAL.
		if st.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific()) {
			var maxS cryptobyte.String
			if !st.ReadASN1(&maxS, cbasn1.Tag(1).ContextSpecific()) {
				return nil, fmt.Errorf("%w: GeneralSubtree maximum", ErrTruncated)
			}
			n, err := decodeIntContent(maxS)
			if err != nil {
				return nil, err
			}
			gs.Maximum = n
			gs.MaximumPresent = true
		}
		if !st.Empty() {
			return nil, fmt.Errorf("%w: GeneralSubtree fields", ErrTrailingData)
		}
		out = append(out, gs)
	}
	return out, nil
}

// decodeIntContent reads a non-negative INTEGER's content octets (the context
// tag was IMPLICIT over INTEGER, so the bytes are the raw integer content) into
// an int. It re-wraps the content as a universal INTEGER and decodes it through
// cryptobyte so DER integer rules (minimal encoding, sign) are enforced rather
// than hand-rolled. The values it backs — NameConstraints minimum/maximum and
// PolicyConstraints SkipCerts — are non-negative by definition (BaseDistance /
// SkipCerts are INTEGER (0..MAX)); a negative value is rejected.
func decodeIntContent(content cryptobyte.String) (int, error) {
	if len(content) == 0 {
		return 0, fmt.Errorf("%w: empty integer", ErrTruncated)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.INTEGER, func(c *cryptobyte.Builder) { c.AddBytes(content) })
	der, err := b.Bytes()
	if err != nil {
		return 0, err
	}
	in := cryptobyte.String(der)
	var v int64
	if !in.ReadASN1Int64WithTag(&v, cbasn1.INTEGER) {
		return 0, fmt.Errorf("%w: integer content", ErrUnexpectedTag)
	}
	if v < 0 {
		return 0, fmt.Errorf("%w: integer must be non-negative, got %d", ErrUnexpectedTag, v)
	}
	if v > int64(maxIntValue) {
		return 0, fmt.Errorf("%w: integer %d exceeds supported range", ErrUnexpectedTag, v)
	}
	return int(v), nil
}

// maxIntValue bounds decodeIntContent to a value that fits a Go int on all
// platforms (BaseDistance/SkipCerts are tiny in practice; this just prevents an
// implausible giant value from overflowing downstream).
const maxIntValue = int64(^uint32(0) >> 1) // 2^31 - 1

// Marshal encodes the NameConstraints extension value.
func (nc *NameConstraints) Marshal() ([]byte, error) {
	if nc == nil {
		return nil, fmt.Errorf("%w: nil NameConstraints", ErrTruncated)
	}
	var b cryptobyte.Builder
	var inner error
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		if len(nc.Permitted) > 0 {
			c.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(v *cryptobyte.Builder) {
				if err := encodeGeneralSubtrees(v, nc.Permitted); err != nil {
					inner = err
				}
			})
		}
		if len(nc.Excluded) > 0 {
			c.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(v *cryptobyte.Builder) {
				if err := encodeGeneralSubtrees(v, nc.Excluded); err != nil {
					inner = err
				}
			})
		}
	})
	if inner != nil {
		return nil, inner
	}
	return b.Bytes()
}

func encodeGeneralSubtrees(b *cryptobyte.Builder, subtrees []GeneralSubtree) error {
	var inner error
	for _, gs := range subtrees {
		b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
			if gs.Base == nil {
				inner = fmt.Errorf("%w: nil GeneralSubtree base", ErrTruncated)
				return
			}
			if err := gs.Base.encodeInto(c); err != nil {
				inner = err
				return
			}
			if gs.MinimumPresent {
				addContextImplicit(c, 0, false, func(v *cryptobyte.Builder) { v.AddBytes(encodeIntContent(gs.Minimum)) })
			}
			if gs.MaximumPresent {
				addContextImplicit(c, 1, false, func(v *cryptobyte.Builder) { v.AddBytes(encodeIntContent(gs.Maximum)) })
			}
		})
		if inner != nil {
			return inner
		}
	}
	return nil
}

// encodeIntContent produces the minimal big-endian content octets of a
// non-negative integer (matching DER INTEGER content, sign bit assumed clear
// for the small BaseDistance/SkipCerts values used here).
func encodeIntContent(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0xff)}, buf...)
		n >>= 8
	}
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return buf
}

// =============================================================================
// PolicyConstraints (id-ce 36) — cryptobyte.
// =============================================================================

// PolicyConstraints is PolicyConstraints (rfc5280.txt:7196-7198). Both fields
// are optional SkipCerts INTEGERs carried under IMPLICIT context tags.
type PolicyConstraints struct {
	RequireExplicitPolicy        int
	RequireExplicitPolicyPresent bool
	InhibitPolicyMapping         int
	InhibitPolicyMappingPresent  bool
}

// ParsePolicyConstraints decodes the extension value.
func ParsePolicyConstraints(der []byte) (*PolicyConstraints, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: PolicyConstraints SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: PolicyConstraints", ErrTrailingData)
	}
	pc := &PolicyConstraints{}
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()) {
		var s cryptobyte.String
		if !seq.ReadASN1(&s, cbasn1.Tag(0).ContextSpecific()) {
			return nil, fmt.Errorf("%w: requireExplicitPolicy", ErrTruncated)
		}
		n, err := decodeIntContent(s)
		if err != nil {
			return nil, err
		}
		pc.RequireExplicitPolicy = n
		pc.RequireExplicitPolicyPresent = true
	}
	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific()) {
		var s cryptobyte.String
		if !seq.ReadASN1(&s, cbasn1.Tag(1).ContextSpecific()) {
			return nil, fmt.Errorf("%w: inhibitPolicyMapping", ErrTruncated)
		}
		n, err := decodeIntContent(s)
		if err != nil {
			return nil, err
		}
		pc.InhibitPolicyMapping = n
		pc.InhibitPolicyMappingPresent = true
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: PolicyConstraints fields", ErrTrailingData)
	}
	return pc, nil
}

// Marshal encodes the extension value.
func (pc *PolicyConstraints) Marshal() ([]byte, error) {
	if pc == nil {
		return nil, fmt.Errorf("%w: nil PolicyConstraints", ErrTruncated)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		if pc.RequireExplicitPolicyPresent {
			addContextImplicit(c, 0, false, func(v *cryptobyte.Builder) { v.AddBytes(encodeIntContent(pc.RequireExplicitPolicy)) })
		}
		if pc.InhibitPolicyMappingPresent {
			addContextImplicit(c, 1, false, func(v *cryptobyte.Builder) { v.AddBytes(encodeIntContent(pc.InhibitPolicyMapping)) })
		}
	})
	return b.Bytes()
}

// =============================================================================
// PolicyMappings (id-ce 33) — cryptobyte.
// =============================================================================

// PolicyMapping is one issuerDomainPolicy/subjectDomainPolicy pair.
type PolicyMapping struct {
	IssuerDomainPolicy  asn1.ObjectIdentifier
	SubjectDomainPolicy asn1.ObjectIdentifier
}

// PolicyMappings is PolicyMappings (rfc5280.txt:7096-7098).
type PolicyMappings []PolicyMapping

// ParsePolicyMappings decodes the extension value.
func ParsePolicyMappings(der []byte) (PolicyMappings, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: PolicyMappings SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: PolicyMappings", ErrTrailingData)
	}
	var pms PolicyMappings
	for !seq.Empty() {
		var pair cryptobyte.String
		if !seq.ReadASN1(&pair, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: PolicyMapping SEQUENCE", ErrTruncated)
		}
		var pm PolicyMapping
		if !pair.ReadASN1ObjectIdentifier(&pm.IssuerDomainPolicy) ||
			!pair.ReadASN1ObjectIdentifier(&pm.SubjectDomainPolicy) {
			return nil, fmt.Errorf("%w: PolicyMapping OIDs", ErrTruncated)
		}
		if !pair.Empty() {
			return nil, fmt.Errorf("%w: PolicyMapping", ErrTrailingData)
		}
		pms = append(pms, pm)
	}
	return pms, nil
}

// Marshal encodes the extension value.
func (pms PolicyMappings) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, pm := range pms {
			c.AddASN1(cbasn1.SEQUENCE, func(p *cryptobyte.Builder) {
				p.AddASN1ObjectIdentifier(pm.IssuerDomainPolicy)
				p.AddASN1ObjectIdentifier(pm.SubjectDomainPolicy)
			})
		}
	})
	return b.Bytes()
}

// =============================================================================
// CertificatePolicies (id-ce 32) — cryptobyte; qualifiers preserved raw.
// =============================================================================

// PolicyInformation is PolicyInformation (rfc5280.txt:7046-7049). The optional
// policyQualifiers SEQUENCE is preserved verbatim (it carries ANY-typed
// qualifier values) so round-trip is byte-exact.
type PolicyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	// Qualifiers is the raw DER of the policyQualifiers SEQUENCE (including its
	// SEQUENCE tag), or nil when absent.
	Qualifiers []byte
}

// CertificatePolicies is CertificatePolicies (rfc5280.txt:7044).
type CertificatePolicies []PolicyInformation

// ParseCertificatePolicies decodes the extension value.
func ParseCertificatePolicies(der []byte) (CertificatePolicies, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: CertificatePolicies SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: CertificatePolicies", ErrTrailingData)
	}
	var cps CertificatePolicies
	for !seq.Empty() {
		var pi cryptobyte.String
		if !seq.ReadASN1(&pi, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: PolicyInformation SEQUENCE", ErrTruncated)
		}
		var p PolicyInformation
		if !pi.ReadASN1ObjectIdentifier(&p.PolicyIdentifier) {
			return nil, fmt.Errorf("%w: policyIdentifier", ErrTruncated)
		}
		if !pi.Empty() {
			// Remaining bytes are the policyQualifiers SEQUENCE; capture verbatim.
			var quals cryptobyte.String
			if !pi.ReadASN1Element(&quals, cbasn1.SEQUENCE) {
				return nil, fmt.Errorf("%w: policyQualifiers", ErrUnexpectedTag)
			}
			p.Qualifiers = append([]byte(nil), quals...)
			if !pi.Empty() {
				return nil, fmt.Errorf("%w: PolicyInformation", ErrTrailingData)
			}
		}
		cps = append(cps, p)
	}
	return cps, nil
}

// Marshal encodes the extension value.
func (cps CertificatePolicies) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, p := range cps {
			c.AddASN1(cbasn1.SEQUENCE, func(pi *cryptobyte.Builder) {
				pi.AddASN1ObjectIdentifier(p.PolicyIdentifier)
				if p.Qualifiers != nil {
					pi.AddBytes(p.Qualifiers)
				}
			})
		}
	})
	return b.Bytes()
}

// =============================================================================
// CRLDistributionPoints (id-ce 31) / FreshestCRL (id-ce 46) — cryptobyte.
// Each DistributionPoint field is preserved raw for byte-exact round-trip.
// =============================================================================

// DistributionPoint is DistributionPoint (rfc5280.txt:7208-7211). To guarantee
// byte-exact round-trip across the CHOICE-bearing distributionPoint and the
// optional reasons BIT STRING, the three optional fields are preserved as raw
// DER (each including its own context tag) and projected lazily via accessors.
type DistributionPoint struct {
	// DistributionPointName is the raw [0] DistributionPointName element, or nil.
	DistributionPointName []byte
	// Reasons is the raw [1] ReasonFlags element, or nil.
	Reasons []byte
	// CRLIssuer is the raw [2] cRLIssuer GeneralNames element, or nil.
	CRLIssuer []byte
}

// CRLDistributionPoints is CRLDistributionPoints (rfc5280.txt:7206); FreshestCRL
// shares the identical structure.
type CRLDistributionPoints []DistributionPoint

// ParseCRLDistributionPoints decodes the extension value.
func ParseCRLDistributionPoints(der []byte) (CRLDistributionPoints, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: CRLDistributionPoints SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: CRLDistributionPoints", ErrTrailingData)
	}
	var dps CRLDistributionPoints
	for !seq.Empty() {
		var dp cryptobyte.String
		if !seq.ReadASN1(&dp, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: DistributionPoint SEQUENCE", ErrTruncated)
		}
		var d DistributionPoint
		if dp.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
			var raw cryptobyte.String
			if !dp.ReadASN1Element(&raw, cbasn1.Tag(0).ContextSpecific().Constructed()) {
				return nil, fmt.Errorf("%w: distributionPoint", ErrTruncated)
			}
			d.DistributionPointName = append([]byte(nil), raw...)
		}
		if dp.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific()) {
			var raw cryptobyte.String
			if !dp.ReadASN1Element(&raw, cbasn1.Tag(1).ContextSpecific()) {
				return nil, fmt.Errorf("%w: reasons", ErrTruncated)
			}
			d.Reasons = append([]byte(nil), raw...)
		}
		if dp.PeekASN1Tag(cbasn1.Tag(2).ContextSpecific().Constructed()) {
			var raw cryptobyte.String
			if !dp.ReadASN1Element(&raw, cbasn1.Tag(2).ContextSpecific().Constructed()) {
				return nil, fmt.Errorf("%w: cRLIssuer", ErrTruncated)
			}
			d.CRLIssuer = append([]byte(nil), raw...)
		}
		if !dp.Empty() {
			return nil, fmt.Errorf("%w: DistributionPoint fields", ErrTrailingData)
		}
		dps = append(dps, d)
	}
	return dps, nil
}

// Marshal encodes the extension value.
func (dps CRLDistributionPoints) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, d := range dps {
			c.AddASN1(cbasn1.SEQUENCE, func(dp *cryptobyte.Builder) {
				if d.DistributionPointName != nil {
					dp.AddBytes(d.DistributionPointName)
				}
				if d.Reasons != nil {
					dp.AddBytes(d.Reasons)
				}
				if d.CRLIssuer != nil {
					dp.AddBytes(d.CRLIssuer)
				}
			})
		}
	})
	return b.Bytes()
}

// FreshestCRL (id-ce 46) has the identical syntax to CRLDistributionPoints
// (FreshestCRL ::= CRLDistributionPoints, rfc5280.txt:7273). It is a distinct
// named type so the typed accessor / OID dispatch (oidExtensionFreshestCRL) can
// surface it under its own extension, while sharing the decode/encode logic.
type FreshestCRL = CRLDistributionPoints

// ParseFreshestCRL decodes a FreshestCRL (id-ce 46) extension value. It reuses
// the CRLDistributionPoints decoder since the two extensions share a syntax.
func ParseFreshestCRL(der []byte) (FreshestCRL, error) {
	return ParseCRLDistributionPoints(der)
}

// =============================================================================
// AuthorityInfoAccess (id-pe 1) / SubjectInfoAccess (id-pe 11) — cryptobyte.
// =============================================================================

// AccessDescription is AccessDescription (rfc5280.txt:7294-7296).
type AccessDescription struct {
	Method   asn1.ObjectIdentifier
	Location GeneralName
}

// InfoAccess is AuthorityInfoAccessSyntax / SubjectInfoAccessSyntax — both are
// SEQUENCE OF AccessDescription (rfc5280.txt:7291-7303).
type InfoAccess []AccessDescription

// ParseInfoAccess decodes an AuthorityInfoAccess or SubjectInfoAccess value.
func ParseInfoAccess(der []byte) (InfoAccess, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: InfoAccess SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: InfoAccess", ErrTrailingData)
	}
	var ias InfoAccess
	for !seq.Empty() {
		var ad cryptobyte.String
		if !seq.ReadASN1(&ad, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: AccessDescription SEQUENCE", ErrTruncated)
		}
		var a AccessDescription
		if !ad.ReadASN1ObjectIdentifier(&a.Method) {
			return nil, fmt.Errorf("%w: accessMethod", ErrTruncated)
		}
		var locElem cryptobyte.String
		var locTag cbasn1.Tag
		if !ad.ReadAnyASN1Element(&locElem, &locTag) {
			return nil, fmt.Errorf("%w: accessLocation", ErrTruncated)
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal([]byte(locElem), &raw); err != nil {
			return nil, fmt.Errorf("%w: accessLocation: %v", ErrUnexpectedTag, err)
		}
		loc, err := parseGeneralName(raw, false)
		if err != nil {
			return nil, err
		}
		a.Location = loc
		if !ad.Empty() {
			return nil, fmt.Errorf("%w: AccessDescription", ErrTrailingData)
		}
		ias = append(ias, a)
	}
	return ias, nil
}

// Marshal encodes an InfoAccess extension value.
func (ias InfoAccess) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	var inner error
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, a := range ias {
			c.AddASN1(cbasn1.SEQUENCE, func(ad *cryptobyte.Builder) {
				ad.AddASN1ObjectIdentifier(a.Method)
				if a.Location == nil {
					inner = fmt.Errorf("%w: nil accessLocation", ErrTruncated)
					return
				}
				if err := a.Location.encodeInto(ad); err != nil {
					inner = err
				}
			})
			if inner != nil {
				return
			}
		}
	})
	if inner != nil {
		return nil, inner
	}
	return b.Bytes()
}

// =============================================================================
// SubjectDirectoryAttributes (id-ce 9) — cryptobyte; ANY values preserved raw.
// =============================================================================

// Attribute is X.501 Attribute { type OID, values SET OF ANY } as used by
// SubjectDirectoryAttributes (rfc5280.txt:7149). Values are preserved verbatim
// (each element's full TLV) so ANY-typed content round-trips byte-exactly.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue
}

// SubjectDirectoryAttributes is SEQUENCE SIZE (1..MAX) OF Attribute.
type SubjectDirectoryAttributes []Attribute

// ParseSubjectDirectoryAttributes decodes the extension value.
func ParseSubjectDirectoryAttributes(der []byte) (SubjectDirectoryAttributes, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: SubjectDirectoryAttributes SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: SubjectDirectoryAttributes", ErrTrailingData)
	}
	var attrs SubjectDirectoryAttributes
	for !seq.Empty() {
		var at cryptobyte.String
		if !seq.ReadASN1(&at, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: Attribute SEQUENCE", ErrTruncated)
		}
		var a Attribute
		if !at.ReadASN1ObjectIdentifier(&a.Type) {
			return nil, fmt.Errorf("%w: Attribute type", ErrTruncated)
		}
		var set cryptobyte.String
		if !at.ReadASN1(&set, cbasn1.SET) {
			return nil, fmt.Errorf("%w: Attribute values SET", ErrTruncated)
		}
		for !set.Empty() {
			var elem cryptobyte.String
			var tag cbasn1.Tag
			if !set.ReadAnyASN1Element(&elem, &tag) {
				return nil, fmt.Errorf("%w: Attribute value", ErrTruncated)
			}
			a.Values = append(a.Values, asn1.RawValue{FullBytes: append([]byte(nil), []byte(elem)...)})
		}
		if !at.Empty() {
			return nil, fmt.Errorf("%w: Attribute", ErrTrailingData)
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// sortSetOF returns the concatenation of the values' verbatim DER, sorted into
// canonical DER SET OF order (X.690 §11.6): elements are ordered by their full
// encodings compared as octet strings. bytes.Compare gives exactly this order
// (a shorter encoding that is a prefix of a longer one sorts first). Sorting an
// already-sorted input is a no-op, so decode→encode of canonical input stays
// byte-exact while a programmatically built unsorted SET is canonicalized.
func sortSetOF(values []asn1.RawValue) []byte {
	encs := make([][]byte, len(values))
	for i, v := range values {
		encs[i] = v.FullBytes
	}
	sort.Slice(encs, func(i, j int) bool { return bytes.Compare(encs[i], encs[j]) < 0 })
	var out []byte
	for _, e := range encs {
		out = append(out, e...)
	}
	return out
}

// Marshal encodes the extension value.
func (attrs SubjectDirectoryAttributes) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, a := range attrs {
			c.AddASN1(cbasn1.SEQUENCE, func(at *cryptobyte.Builder) {
				at.AddASN1ObjectIdentifier(a.Type)
				at.AddASN1(cbasn1.SET, func(set *cryptobyte.Builder) {
					set.AddBytes(sortSetOF(a.Values))
				})
			})
		}
	})
	return b.Bytes()
}
