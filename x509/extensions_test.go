package x509

import (
	"bytes"
	"encoding/asn1"
	"net"
	"testing"
)

// roundTrip is a helper asserting Marshal(Parse(der)) == der.
func assertByteExact(t *testing.T, label string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s not byte-exact:\n got %x\nwant %x", label, got, want)
	}
}

// --- KeyUsage --------------------------------------------------------

func TestKeyUsageRoundTrip(t *testing.T) {
	// digitalSignature + keyEncipherment: bits 0 and 2 set.
	// BIT STRING 03 02 05 A0 → unused=5, content 0xA0 = 1010 0000.
	der := []byte{0x03, 0x02, 0x05, 0xA0}
	ku, err := ParseKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if ku&KeyUsageDigitalSignature == 0 || ku&KeyUsageKeyEncipherment == 0 {
		t.Errorf("expected digitalSignature+keyEncipherment, got %016b", ku)
	}
	if ku&KeyUsageCRLSign != 0 {
		t.Error("cRLSign should not be set")
	}
	out, err := ku.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "KeyUsage", out, der)
}

func TestKeyUsageKeyCertSign(t *testing.T) {
	// keyCertSign (bit 5) + cRLSign (bit 6): content byte 0000 0110 = 0x06, bitLen 7 → unused 1.
	der := []byte{0x03, 0x02, 0x01, 0x06}
	ku, err := ParseKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if ku&KeyUsageKeyCertSign == 0 || ku&KeyUsageCRLSign == 0 {
		t.Errorf("expected keyCertSign+cRLSign, got %016b", ku)
	}
	out, err := ku.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "KeyUsage keyCertSign", out, der)
}

// --- BasicConstraints ------------------------------------------------

func TestBasicConstraintsCA(t *testing.T) {
	// cA=TRUE, pathLen=0: SEQUENCE { BOOLEAN TRUE, INTEGER 0 }.
	der := []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00}
	bc, err := ParseBasicConstraints(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bc.IsCA || !bc.PathLenValid || bc.PathLen != 0 {
		t.Errorf("got %+v, want IsCA=true PathLen=0 valid", bc)
	}
	out, err := bc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "BasicConstraints CA pathlen0", out, der)
}

func TestBasicConstraintsEndEntity(t *testing.T) {
	// cA=FALSE (omitted): empty SEQUENCE.
	der := []byte{0x30, 0x00}
	bc, err := ParseBasicConstraints(der)
	if err != nil {
		t.Fatal(err)
	}
	if bc.IsCA || bc.PathLenValid {
		t.Errorf("got %+v, want non-CA no pathlen", bc)
	}
	out, err := bc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "BasicConstraints end-entity", out, der)
}

// --- ExtKeyUsage -----------------------------------------------------

func TestExtKeyUsageRoundTrip(t *testing.T) {
	serverAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	clientAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	der, _ := ExtKeyUsage{serverAuth, clientAuth}.Marshal()
	eku, err := ParseExtKeyUsage(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(eku) != 2 || !eku[0].Equal(serverAuth) || !eku[1].Equal(clientAuth) {
		t.Errorf("got %v", eku)
	}
	out, _ := eku.Marshal()
	assertByteExact(t, "ExtKeyUsage", out, der)
}

// --- SubjectAltName --------------------------------------------------

func TestSubjectAltNameExtension(t *testing.T) {
	der := buildGeneralNamesDER(t, DNSName("a.example"), IPAddressName{IP: net.IPv4(10, 0, 0, 5).To4()})
	san, err := ParseSubjectAltName(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(san.Names) != 2 {
		t.Fatalf("count %d", len(san.Names))
	}
	out, _ := san.Marshal()
	assertByteExact(t, "SubjectAltName", out, der)
}

// --- NameConstraints -------------------------------------------------

func TestNameConstraintsRoundTrip(t *testing.T) {
	nc := &NameConstraints{
		Permitted: []GeneralSubtree{
			{Base: DNSName("example.com")},
			{Base: IPAddressName{
				IP:              net.IPv4(192, 0, 2, 0).To4(),
				Mask:            net.IPMask{0xff, 0xff, 0xff, 0x00},
				NameConstraints: true,
			}},
		},
		Excluded: []GeneralSubtree{
			{Base: DNSName("bad.example.com")},
		},
	}
	der, err := nc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNameConstraints(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Permitted) != 2 || len(got.Excluded) != 1 {
		t.Fatalf("got permitted=%d excluded=%d", len(got.Permitted), len(got.Excluded))
	}
	// The iPAddress subtree must decode as NameConstraints variant (8-byte → mask).
	ip, ok := got.Permitted[1].Base.(IPAddressName)
	if !ok || !ip.NameConstraints || len(ip.Mask) != 4 {
		t.Errorf("permitted[1] = %+v, want NameConstraints iPAddress with mask", got.Permitted[1].Base)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "NameConstraints", out, der)
}

// --- PolicyConstraints + InhibitAnyPolicy + PolicyMappings + CertPolicies
func TestPolicyConstraintsRoundTrip(t *testing.T) {
	pc := &PolicyConstraints{RequireExplicitPolicy: 0, RequireExplicitPolicyPresent: true, InhibitPolicyMapping: 3, InhibitPolicyMappingPresent: true}
	der, err := pc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePolicyConstraints(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequireExplicitPolicyPresent || got.RequireExplicitPolicy != 0 ||
		!got.InhibitPolicyMappingPresent || got.InhibitPolicyMapping != 3 {
		t.Errorf("got %+v", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "PolicyConstraints", out, der)
}

func TestInhibitAnyPolicyRoundTrip(t *testing.T) {
	der, _ := InhibitAnyPolicy(2).Marshal()
	v, err := ParseInhibitAnyPolicy(der)
	if err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Errorf("got %d", v)
	}
	out, _ := v.Marshal()
	assertByteExact(t, "InhibitAnyPolicy", out, der)
}

func TestPolicyMappingsRoundTrip(t *testing.T) {
	pms := PolicyMappings{
		{IssuerDomainPolicy: asn1.ObjectIdentifier{2, 5, 29, 32, 0}, SubjectDomainPolicy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99, 1}},
	}
	der, _ := pms.Marshal()
	got, err := ParsePolicyMappings(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].IssuerDomainPolicy.Equal(pms[0].IssuerDomainPolicy) {
		t.Errorf("got %v", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "PolicyMappings", out, der)
}

func TestCertificatePoliciesRoundTrip(t *testing.T) {
	// PolicyInformation with no qualifiers + one with a CPS qualifier.
	cps := CertificatePolicies{
		{PolicyIdentifier: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}},
	}
	der, _ := cps.Marshal()
	got, err := ParseCertificatePolicies(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].PolicyIdentifier.Equal(cps[0].PolicyIdentifier) || got[0].Qualifiers != nil {
		t.Errorf("got %+v", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "CertificatePolicies", out, der)
}

func TestCertificatePoliciesWithQualifiers(t *testing.T) {
	// Build a PolicyInformation with a policyQualifiers SEQUENCE preserved raw.
	// Use a real-ish DER: SEQUENCE { SEQUENCE { OID 2.23.140.1.2.1, SEQUENCE {
	//   SEQUENCE { OID id-qt-cps (1.3.6.1.5.5.7.2.1), IA5String "http://x" } } } }
	cpsURI := []byte("http://cps.example")
	// Inner qualifier: SEQUENCE { OID id-qt-cps, IA5String }
	idQtCps := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	oidDER, _ := asn1.Marshal(idQtCps)
	ia5 := append([]byte{0x16, byte(len(cpsURI))}, cpsURI...)
	qualifier := append(append([]byte{0x30, byte(len(oidDER) + len(ia5))}, oidDER...), ia5...)
	qualifiers := append([]byte{0x30, byte(len(qualifier))}, qualifier...)
	cps := CertificatePolicies{
		{PolicyIdentifier: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}, Qualifiers: qualifiers},
	}
	der, err := cps.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCertificatePolicies(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Qualifiers, qualifiers) {
		t.Errorf("qualifiers not preserved: got %x want %x", got[0].Qualifiers, qualifiers)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "CertificatePolicies+qualifiers", out, der)
}

// --- AKI + SKI + CRLDP + FreshestCRL + SubjectDirAttrs ----------------

func TestSubjectKeyIdentifierRoundTrip(t *testing.T) {
	ki := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	der, _ := SubjectKeyIdentifier(ki).Marshal()
	got, err := ParseSubjectKeyIdentifier(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ki) {
		t.Errorf("got %x", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "SKI", out, der)
}

func TestAuthorityKeyIdentifierRoundTrip(t *testing.T) {
	aki := &AuthorityKeyIdentifier{
		KeyID:                     []byte{0x01, 0x02, 0x03, 0x04},
		AuthorityCertIssuer:       GeneralNames{DNSName("ca.example.com")},
		AuthorityCertSerialNumber: []byte{0x12, 0x34},
	}
	der, err := aki.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAuthorityKeyIdentifier(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.KeyID, aki.KeyID) {
		t.Errorf("KeyID got %x", got.KeyID)
	}
	if len(got.AuthorityCertIssuer) != 1 {
		t.Errorf("issuer count %d", len(got.AuthorityCertIssuer))
	}
	if !bytes.Equal(got.AuthorityCertSerialNumber, aki.AuthorityCertSerialNumber) {
		t.Errorf("serial got %x", got.AuthorityCertSerialNumber)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "AKI", out, der)
}

func TestAuthorityKeyIdentifierKeyIDOnly(t *testing.T) {
	// Most common form: just [0] keyIdentifier.
	aki := &AuthorityKeyIdentifier{KeyID: []byte{0xAA, 0xBB}}
	der, _ := aki.Marshal()
	got, err := ParseAuthorityKeyIdentifier(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.KeyID, aki.KeyID) || len(got.AuthorityCertIssuer) != 0 || got.AuthorityCertSerialNumber != nil {
		t.Errorf("got %+v", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "AKI keyid-only", out, der)
}

func TestCRLDistributionPointsRoundTrip(t *testing.T) {
	// Build a DistributionPoint with fullName=[0]{ [0]{ URI } } raw-preserved.
	// distributionPoint [0] DistributionPointName, where DPN fullName is [0] GeneralNames.
	// We construct the raw [0] element by hand.
	uri := URIName("http://crl.example/ca.crl")
	var inner []byte
	{
		// Encode the URI GeneralName.
		uriDER := encodeName(t, uri) // 0x86 ...
		// fullName [0] GeneralNames = [0] { SEQUENCE OF GeneralName } — but
		// DistributionPointName fullName [0] is IMPLICIT GeneralNames, so the
		// content is the bare GeneralName elements under tag [0] (constructed).
		fullName := append([]byte{0xA0, byte(len(uriDER))}, uriDER...)
		// distributionPoint [0] EXPLICIT DistributionPointName → here [0] wraps
		// the fullName CHOICE; model as the raw [0] element holding fullName.
		inner = append([]byte{0xA0, byte(len(fullName))}, fullName...)
	}
	dp := DistributionPoint{DistributionPointName: inner}
	der, err := CRLDistributionPoints{dp}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCRLDistributionPoints(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].DistributionPointName, inner) {
		t.Errorf("DPN not preserved: got %x want %x", got[0].DistributionPointName, inner)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "CRLDistributionPoints", out, der)
}

func TestSubjectDirectoryAttributesRoundTrip(t *testing.T) {
	// One attribute: type 2.5.4.3 (CN), values SET OF { UTF8String "x" }.
	val := asn1.RawValue{FullBytes: []byte{0x0C, 0x01, 'x'}}
	attrs := SubjectDirectoryAttributes{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Values: []asn1.RawValue{val}},
	}
	der, err := attrs.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSubjectDirectoryAttributes(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Values) != 1 || !bytes.Equal(got[0].Values[0].FullBytes, val.FullBytes) {
		t.Errorf("got %+v", got)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "SubjectDirectoryAttributes", out, der)
}

// --- AuthorityInfoAccess / SubjectInfoAccess -------------------------

func TestInfoAccessRoundTrip(t *testing.T) {
	idAdOCSP := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	idAdCAIssuers := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	ia := InfoAccess{
		{Method: idAdOCSP, Location: URIName("http://ocsp.example")},
		{Method: idAdCAIssuers, Location: URIName("http://ca.example/ca.crt")},
	}
	der, err := ia.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseInfoAccess(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Method.Equal(idAdOCSP) {
		t.Fatalf("got %+v", got)
	}
	if u, ok := got[0].Location.(URIName); !ok || string(u) != "http://ocsp.example" {
		t.Errorf("location[0] = %v", got[0].Location)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "InfoAccess", out, der)
}

// --- malformed input: no panic ----------------------------------------------

func TestExtensionsMalformedNoPanic(t *testing.T) {
	bad := [][]byte{
		nil,
		{0x30},
		{0x30, 0x01},
		{0x05, 0x00},
		{0x30, 0x03, 0x02, 0x01},
	}
	for _, b := range bad {
		_, _ = ParseKeyUsage(b)
		_, _ = ParseBasicConstraints(b)
		_, _ = ParseExtKeyUsage(b)
		_, _ = ParseNameConstraints(b)
		_, _ = ParsePolicyConstraints(b)
		_, _ = ParsePolicyMappings(b)
		_, _ = ParseCertificatePolicies(b)
		_, _ = ParseAuthorityKeyIdentifier(b)
		_, _ = ParseSubjectKeyIdentifier(b)
		_, _ = ParseCRLDistributionPoints(b)
		_, _ = ParseFreshestCRL(b)
		_, _ = ParseInfoAccess(b)
		_, _ = ParseSubjectDirectoryAttributes(b)
		_, _ = ParseInhibitAnyPolicy(b)
	}
}

// --- FreshestCRL wiring ----------------------------------------------

// TestFreshestCRLRoundTrip checks FreshestCRL
// (id-ce 46) shares CRLDistributionPoints syntax and must decode + round-trip.
func TestFreshestCRLRoundTrip(t *testing.T) {
	uri := encodeName(t, URIName("http://crl.example/delta.crl"))
	fullName := append([]byte{0xA0, byte(len(uri))}, uri...)
	dpn := append([]byte{0xA0, byte(len(fullName))}, fullName...)
	dp := DistributionPoint{DistributionPointName: dpn}
	der, err := CRLDistributionPoints{dp}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fc, err := ParseFreshestCRL(der)
	if err != nil {
		t.Fatalf("ParseFreshestCRL: %v", err)
	}
	if len(fc) != 1 || !bytes.Equal(fc[0].DistributionPointName, dpn) {
		t.Errorf("FreshestCRL not preserved: %+v", fc)
	}
	// FreshestCRL is an alias of CRLDistributionPoints, so Marshal is shared.
	out, err := fc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "FreshestCRL", out, der)
	// And the OID is wired (sanity: the constant exists and is id-ce 46).
	if !oidExtensionFreshestCRL.Equal(asn1.ObjectIdentifier{2, 5, 29, 46}) {
		t.Errorf("oidExtensionFreshestCRL = %v", oidExtensionFreshestCRL)
	}
}

// --- SET OF DER sort on build (X.690 §11.6) ---------------------------------

// TestSubjectDirectoryAttributesSetSorted asserts that a programmatically built,
// UNSORTED values SET is canonicalized to DER sort order on Marshal, while an
// already-sorted SET round-trips byte-exact.
func TestSubjectDirectoryAttributesSetSorted(t *testing.T) {
	// Two values deliberately out of DER order: "z" (0x0C 01 7A) before
	// "a" (0x0C 01 61). DER SET OF sorts by encoding, so "a" must come first.
	zVal := asn1.RawValue{FullBytes: []byte{0x0C, 0x01, 'z'}}
	aVal := asn1.RawValue{FullBytes: []byte{0x0C, 0x01, 'a'}}
	attrs := SubjectDirectoryAttributes{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Values: []asn1.RawValue{zVal, aVal}},
	}
	der, err := attrs.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Decode and confirm the SET is now in sorted order ("a" then "z").
	got, err := ParseSubjectDirectoryAttributes(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Values) != 2 {
		t.Fatalf("got %+v", got)
	}
	if !bytes.Equal(got[0].Values[0].FullBytes, aVal.FullBytes) ||
		!bytes.Equal(got[0].Values[1].FullBytes, zVal.FullBytes) {
		t.Errorf("SET not DER-sorted: [0]=%x [1]=%x", got[0].Values[0].FullBytes, got[0].Values[1].FullBytes)
	}
	// Re-marshal of the now-sorted decode must be byte-exact (sort is idempotent).
	out, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertByteExact(t, "SubjectDirectoryAttributes sorted", out, der)
}

// --- decodeIntContent widening / sign validation ----------------------------

func TestNameConstraintsLargeMinMax(t *testing.T) {
	// minimum/maximum larger than one byte (e.g. 300) must round-trip.
	nc := &NameConstraints{
		Permitted: []GeneralSubtree{
			{Base: DNSName("a.example"), Minimum: 300, MinimumPresent: true, Maximum: 70000, MaximumPresent: true},
		},
	}
	der, err := nc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNameConstraints(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Permitted) != 1 {
		t.Fatalf("permitted count %d", len(got.Permitted))
	}
	gs := got.Permitted[0]
	if !gs.MinimumPresent || gs.Minimum != 300 || !gs.MaximumPresent || gs.Maximum != 70000 {
		t.Errorf("min/max not preserved: %+v", gs)
	}
	out, _ := got.Marshal()
	assertByteExact(t, "NameConstraints large min/max", out, der)
}

func TestDecodeIntContentSignAndEmpty(t *testing.T) {
	// Empty content rejected.
	if _, err := decodeIntContent(nil); err == nil {
		t.Error("empty integer content should be rejected")
	}
	// Negative content (high bit set, e.g. 0x80) rejected — these fields are
	// INTEGER (0..MAX).
	if _, err := decodeIntContent([]byte{0x80}); err == nil {
		t.Error("negative integer content should be rejected")
	}
	// Valid small value.
	if n, err := decodeIntContent([]byte{0x05}); err != nil || n != 5 {
		t.Errorf("got (%d, %v), want (5, nil)", n, err)
	}
	// Multi-byte value (0x01 0x2C = 300).
	if n, err := decodeIntContent([]byte{0x01, 0x2C}); err != nil || n != 300 {
		t.Errorf("got (%d, %v), want (300, nil)", n, err)
	}
}
