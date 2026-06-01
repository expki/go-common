package x509

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// tlv builds a primitive TLV with the given UNIVERSAL tag number and content.
// Content lengths in these tests are < 128 so the short-form length is used,
// matching DER.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag, byte(len(content))}
	return append(out, content...)
}

// encodeDS runs a DirectoryString through encodeInto and returns the DER, or
// fails the test on a builder error.
func encodeDS(t *testing.T, d DirectoryString) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	d.encodeInto(b)
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	return out
}

func TestDirectoryStringRoundTrip(t *testing.T) {
	// "hi" in various encodings.
	bmpHI := []byte{0x00, 'h', 0x00, 'i'}       // UTF-16BE
	uniHI := []byte{0, 0, 0, 'h', 0, 0, 0, 'i'} // UTF-32BE
	cases := []struct {
		name    string
		tagByte byte
		tagNum  int
		content []byte
		want    string
	}{
		{"Teletex", 0x14, directoryStringTagTeletex, []byte("hi"), "hi"},
		{"Printable", 0x13, directoryStringTagPrintable, []byte("hi"), "hi"},
		{"UTF8", 0x0c, directoryStringTagUTF8, []byte("hé"), "hé"},
		{"BMP", 0x1e, directoryStringTagBMP, bmpHI, "hi"},
		{"Universal", 0x1c, directoryStringTagUniversal, uniHI, "hi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der := tlv(tc.tagByte, tc.content)
			s := cryptobyte.String(der)
			d, err := parseDirectoryString(&s)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !s.Empty() {
				t.Fatalf("parse left %d trailing bytes", len(s))
			}
			if d.Tag != tc.tagNum {
				t.Fatalf("Tag = %d, want %d", d.Tag, tc.tagNum)
			}
			if d.String != tc.want {
				t.Fatalf("String = %q, want %q", d.String, tc.want)
			}
			// Unmodified decode re-emits the exact input DER.
			got := encodeDS(t, d)
			if !bytes.Equal(got, der) {
				t.Fatalf("round-trip not byte-exact:\n got %x\nwant %x", got, der)
			}
		})
	}
}

// TestDirectoryStringTeletexNotCollapsed checks the central guarantee: a
// TeletexString (0x14) must NOT re-emit as PrintableString (0x13). This is the
// exact failure mode of the naive pkix.RDNSequence path.
func TestDirectoryStringTeletexNotCollapsed(t *testing.T) {
	der := tlv(0x14, []byte("ACME Co"))
	s := cryptobyte.String(der)
	d, err := parseDirectoryString(&s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := encodeDS(t, d)
	if got[0] != 0x14 {
		t.Fatalf("Teletex collapsed to tag 0x%02x, want 0x14", got[0])
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("not byte-exact: got %x want %x", got, der)
	}
}

// TestDirectoryStringMutated verifies that a mutated/built value canonicalizes
// from Tag+String rather than replaying stale raw bytes.
func TestDirectoryStringMutated(t *testing.T) {
	// Decode a Teletex value, then mutate it.
	der := tlv(0x14, []byte("old"))
	s := cryptobyte.String(der)
	d, err := parseDirectoryString(&s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d.String = "new"
	d.MarkModified()
	got := encodeDS(t, d)
	want := tlv(0x14, []byte("new"))
	if !bytes.Equal(got, want) {
		t.Fatalf("mutated encode = %x, want %x", got, want)
	}

	// A freshly constructed UTF8 value.
	nd := NewDirectoryString(directoryStringTagUTF8, "fresh")
	got = encodeDS(t, nd)
	want = tlv(0x0c, []byte("fresh"))
	if !bytes.Equal(got, want) {
		t.Fatalf("new encode = %x, want %x", got, want)
	}
}

func TestDirectoryStringParseErrors(t *testing.T) {
	// Empty input → truncated.
	empty := cryptobyte.String(nil)
	if _, err := parseDirectoryString(&empty); err != ErrTruncated {
		t.Fatalf("empty: err = %v, want ErrTruncated", err)
	}
	// Wrong tag (IA5String 0x16) → unexpected tag.
	bad := cryptobyte.String(tlv(0x16, []byte("x")))
	if _, err := parseDirectoryString(&bad); err != ErrUnexpectedTag {
		t.Fatalf("ia5: err = %v, want ErrUnexpectedTag", err)
	}
	// BMPString with odd length → error.
	oddBMP := cryptobyte.String(tlv(0x1e, []byte{0x00}))
	if _, err := parseDirectoryString(&oddBMP); err == nil {
		t.Fatal("odd-length BMPString: expected error, got nil")
	}
}

// edipSeq builds an ediPartyName [5] element from optional nameAssigner and a
// partyName DirectoryString TLV. Each member is wrapped in its EXPLICIT
// constructed context tag (0xA0 / 0xA1), then the SEQUENCE body is tagged [5]
// (0xA5).
func edipSeq(assigner, party []byte) []byte {
	var body []byte
	if assigner != nil {
		body = append(body, explicit(0xa0, assigner)...)
	}
	body = append(body, explicit(0xa1, party)...)
	return explicit(0xa5, body)
}

// explicit wraps inner in a constructed context tag (short-form length).
func explicit(tag byte, inner []byte) []byte {
	out := []byte{tag, byte(len(inner))}
	return append(out, inner...)
}

func encodeEDI(t *testing.T, e EDIPartyName) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	if err := e.encodeInto(b); err != nil {
		t.Fatalf("encodeInto: %v", err)
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("builder: %v", err)
	}
	return out
}

func TestEDIPartyNameRoundTrip(t *testing.T) {
	partyTLV := tlv(0x14, []byte("party")) // TeletexString partyName

	t.Run("PartyNameOnly", func(t *testing.T) {
		full := edipSeq(nil, partyTLV)
		// The dispatcher strips the outer [5] tag; parseEDIPartyName gets the body.
		body := stripOuter(t, full)
		edi, err := parseEDIPartyName(body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if edi.NameAssigner != nil {
			t.Fatal("NameAssigner should be nil")
		}
		if edi.PartyName.String != "party" || edi.PartyName.Tag != directoryStringTagTeletex {
			t.Fatalf("PartyName = %+v", edi.PartyName)
		}
		got := encodeEDI(t, edi)
		if !bytes.Equal(got, full) {
			t.Fatalf("round-trip:\n got %x\nwant %x", got, full)
		}
	})

	t.Run("WithNameAssigner", func(t *testing.T) {
		assignerTLV := tlv(0x13, []byte("assigner")) // PrintableString
		full := edipSeq(assignerTLV, partyTLV)
		body := stripOuter(t, full)
		edi, err := parseEDIPartyName(body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if edi.NameAssigner == nil {
			t.Fatal("NameAssigner should be set")
		}
		if edi.NameAssigner.String != "assigner" || edi.NameAssigner.Tag != directoryStringTagPrintable {
			t.Fatalf("NameAssigner = %+v", *edi.NameAssigner)
		}
		if edi.PartyName.Tag != directoryStringTagTeletex {
			t.Fatalf("PartyName tag = %d, want Teletex (TeletexString must survive)", edi.PartyName.Tag)
		}
		got := encodeEDI(t, edi)
		if !bytes.Equal(got, full) {
			t.Fatalf("round-trip:\n got %x\nwant %x", got, full)
		}
	})

	t.Run("TagNumberIsFive", func(t *testing.T) {
		edi := EDIPartyName{PartyName: NewDirectoryString(directoryStringTagUTF8, "x")}
		if edi.tagNumber() != 5 {
			t.Fatalf("tagNumber = %d, want 5", edi.tagNumber())
		}
		got := encodeEDI(t, edi)
		if got[0] != 0xa5 {
			t.Fatalf("outer tag = 0x%02x, want 0xa5", got[0])
		}
	})
}

// stripOuter removes the outer tag+length from a single short-form TLV and
// returns its content, simulating the GeneralName dispatcher handing the [5]
// body to parseEDIPartyName.
func stripOuter(t *testing.T, full []byte) cryptobyte.String {
	t.Helper()
	s := cryptobyte.String(full)
	var inner cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&inner, &tag) {
		t.Fatalf("stripOuter: cannot read element from %x", full)
	}
	return inner
}
