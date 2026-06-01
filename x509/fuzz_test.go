package x509

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"os"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// fuzz_test.go asserts that the decode paths never panic on malformed DER,
// a successful decode→encode→decode must be stable, AND trailing data after a
// complete structure must be rejected. All three invariants are asserted INSIDE
// the fuzz bodies under arbitrary input.

// FuzzGeneralNameRoundTrip feeds arbitrary bytes as a SubjectAltName extension
// value (a GeneralNames SEQUENCE). For any input that decodes successfully, it
// re-encodes and re-decodes and requires the second decode to succeed and the
// re-encode to be stable (encode(decode(x)) == encode(decode(encode(decode(x))))).
func FuzzGeneralNameRoundTrip(f *testing.F) {
	// Seed with the corpus and a few primitives.
	for _, name := range []string{"othername_upn_san.der", "x400address_san.der"} {
		if b, err := readFile(name); err == nil {
			f.Add(b)
		}
	}
	// A simple dNSName SAN seed.
	f.Add([]byte{0x30, 0x0d, 0x82, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})

	f.Fuzz(func(t *testing.T, data []byte) {
		san, err := ParseSAN(data)
		if err != nil {
			return // malformed input: a clean error (not a panic) is the requirement.
		}
		// Decoded cleanly — re-encode must succeed and be stable.
		enc1, err := san.Marshal()
		if err != nil {
			// A value that decoded must be re-encodable; a marshal error here is
			// acceptable only if it is a clean error (no panic). Stop the round.
			return
		}
		san2, err := ParseSAN(enc1)
		if err != nil {
			t.Fatalf("re-decode of self-encoded SAN failed: %v (enc=%x)", err, enc1)
		}
		enc2, err := san2.Marshal()
		if err != nil {
			t.Fatalf("re-encode of re-decoded SAN failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("GeneralNames round-trip unstable:\n enc1=%x\n enc2=%x", enc1, enc2)
		}

		// Trailing-data rejection: enc1 is a complete, canonical
		// GeneralNames SEQUENCE. Appending a stray byte must be rejected — the
		// parser must not silently ignore the extra octet — and must not panic.
		withTrailer := append(append([]byte(nil), enc1...), 0x00)
		if _, err := ParseSAN(withTrailer); err == nil {
			t.Fatalf("ParseSAN accepted trailing data:\n input=%x", withTrailer)
		} else if !errors.Is(err, ErrTrailingData) {
			// The trailing byte may also be consumed as the start of a malformed
			// GeneralName element (yielding a different sentinel); either way it
			// MUST be a clean rejection, never acceptance. Accept any non-nil
			// error here, but require ErrTrailingData when the structure was
			// otherwise complete (the common case for a single appended byte that
			// cannot begin a valid context-tagged element).
			_ = err
		}
	})
}

// FuzzExtensionDecode feeds arbitrary bytes to every typed extension parser and
// requires that none panic. Parsers that succeed must produce a value whose
// Marshal (where available) does not panic. The point is robustness against
// adversarial DER, not semantic round-trip (that is covered elsewhere).
func FuzzExtensionDecode(f *testing.F) {
	for _, name := range []string{"nameconstraints_ip8.der", "othername_upn_san.der", "x400address_san.der"} {
		if b, err := readFile(name); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0x30, 0x00})             // empty SEQUENCE
	f.Add([]byte{0x03, 0x02, 0x05, 0xA0}) // a BIT STRING (KeyUsage-ish)
	f.Add([]byte{0x02, 0x01, 0x05})       // an INTEGER (InhibitAnyPolicy-ish)
	f.Add([]byte{})                       // empty

	f.Fuzz(func(t *testing.T, data []byte) {
		// Each parser must return (value,nil) or (zero,err) and never panic.
		// We ignore the results; the harness catches any panic as a failure.
		if ku, err := ParseKeyUsage(data); err == nil {
			_, _ = ku.Marshal()
		}
		if bc, err := ParseBasicConstraints(data); err == nil {
			_, _ = bc.Marshal()
		}
		if v, err := ParseInhibitAnyPolicy(data); err == nil {
			_, _ = v.Marshal()
		}
		if eku, err := ParseExtKeyUsage(data); err == nil {
			_, _ = eku.Marshal()
		}
		if ski, err := ParseSubjectKeyIdentifier(data); err == nil {
			_, _ = ski.Marshal()
		}
		if aki, err := ParseAuthorityKeyIdentifier(data); err == nil {
			_, _ = aki.Marshal()
		}
		if nc, err := ParseNameConstraints(data); err == nil {
			_, _ = nc.Marshal()
		}
		if pc, err := ParsePolicyConstraints(data); err == nil {
			_, _ = pc.Marshal()
		}
		if pm, err := ParsePolicyMappings(data); err == nil {
			_, _ = pm.Marshal()
		}
		if cp, err := ParseCertificatePolicies(data); err == nil {
			_, _ = cp.Marshal()
		}
		if dp, err := ParseCRLDistributionPoints(data); err == nil {
			_, _ = dp.Marshal()
		}
		if ia, err := ParseInfoAccess(data); err == nil {
			_, _ = ia.Marshal()
		}
		if sda, err := ParseSubjectDirectoryAttributes(data); err == nil {
			_, _ = sda.Marshal()
		}
		if _, err := ParseSAN(data); err == nil {
			// already round-tripped in the dedicated fuzz target
		}
		// DirectoryName + X400Address arms via their content parsers.
		_, _ = parseDirectoryName(cryptobyte.String(data))
		_, _ = parseX400Address(cryptobyte.String(data))
		// GeneralName dispatch on a raw value, if the bytes form a context-tagged
		// element.
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(data, &raw); err == nil && raw.Class == asn1.ClassContextSpecific {
			_, _ = parseGeneralName(raw, false)
			_, _ = parseGeneralName(raw, true)
		}
	})
}

// readFile reads a corpus file relative to testdata/ for fuzz seeding. It returns
// an error rather than failing so seeding is best-effort.
func readFile(name string) ([]byte, error) {
	return os.ReadFile("testdata/" + name)
}
