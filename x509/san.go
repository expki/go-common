package x509

import (
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName (rfc5280.txt:2091). It
// is an ordered slice; decode and encode preserve element order and count
// exactly. The same structure backs SubjectAltName (id-ce 17),
// IssuerAltName (id-ce 18), and the subtrees within NameConstraints.
type GeneralNames []GeneralName

// parseGeneralNames decodes the content of a GeneralNames SEQUENCE — der is the
// complete SEQUENCE TLV. nameConstraints selects the iPAddress interpretation
// (false → SAN/IAN bare address; true → NameConstraints addr+mask) and is
// threaded down to parseGeneralName for each element. Order and count are
// preserved. Never panics; returns sentinel errors on malformed input.
func parseGeneralNames(der []byte, nameConstraints bool) (GeneralNames, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: GeneralNames SEQUENCE", ErrUnexpectedTag)
	}
	if !in.Empty() {
		return nil, fmt.Errorf("%w: after GeneralNames SEQUENCE", ErrTrailingData)
	}
	var names GeneralNames
	for !seq.Empty() {
		var elem cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&elem, &tag) {
			return nil, fmt.Errorf("%w: GeneralName element", ErrTruncated)
		}
		// Re-read the element bytes as an asn1.RawValue (header preserved,
		// CHOICE bytes intact) so the dispatcher can switch on class/tag.
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

// encodeInto appends the GeneralNames SEQUENCE (its outer SEQUENCE tag plus each
// arm in order) to b. Each arm writes its own context-tagged DER via encodeInto.
func (g GeneralNames) encodeInto(b *cryptobyte.Builder) error {
	var armErr error
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		for _, n := range g {
			if n == nil {
				armErr = fmt.Errorf("%w: nil GeneralName", ErrTruncated)
				c.SetError(armErr)
				return
			}
			if err := n.encodeInto(c); err != nil {
				armErr = err
				return
			}
		}
	})
	return armErr
}

// marshal returns the DER of the GeneralNames SEQUENCE.
func (g GeneralNames) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	if err := g.encodeInto(&b); err != nil {
		return nil, err
	}
	return b.Bytes()
}

// SAN is the typed model of a SubjectAltName / IssuerAltName extension value: an
// ordered list of GeneralName alternatives. It carries the full nine-type
// GeneralName CHOICE, not just the dNSName/iPAddress subset the stdlib exposes.
type SAN struct {
	Names GeneralNames
}

// ParseSAN decodes a SubjectAltName/IssuerAltName extension value (the raw DER
// inside the extension's OCTET STRING) into a typed SAN. The SAN/IAN context
// uses bare iPAddress encoding (4/16 bytes, no mask). Byte-exact round-trip is
// guaranteed for the arms that preserve raw (directoryName, otherName,
// ediPartyName); primitives re-encode canonically and identically.
func ParseSAN(extensionValue []byte) (*SAN, error) {
	names, err := parseGeneralNames(extensionValue, false)
	if err != nil {
		return nil, err
	}
	return &SAN{Names: names}, nil
}

// Marshal encodes the SAN back to a SubjectAltName/IssuerAltName extension value
// (the GeneralNames SEQUENCE DER). For an unmutated decode this is byte-exact
// with the input passed to ParseSAN.
func (s *SAN) Marshal() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil SAN", ErrTruncated)
	}
	return s.Names.marshal()
}

// IssuerAltName is the IssuerAltName (id-ce 18) extension value. Its on-the-wire
// structure is identical to SubjectAltName (GeneralNames), so it shares the SAN
// type and code path.
type IssuerAltName = SAN

// ParseIssuerAltName decodes an IssuerAltName extension value. It is the same
// GeneralNames path as ParseSAN, named for call-site clarity.
func ParseIssuerAltName(extensionValue []byte) (*IssuerAltName, error) {
	return ParseSAN(extensionValue)
}
