package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestBer2DerParentBoundaries(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		name  string
		input []byte
	}{
		{"primitive content", []byte{0x30, 0x02, 0x04, 0x01, 0x41}},
		{"constructed content", []byte{0x30, 0x02, 0x30, 0x02, 0x05, 0x00}},
		{"overlapping siblings", []byte{0x30, 0x06, 0x30, 0x02, 0x30, 0x02, 0x05, 0x00}},
		{"child length byte", []byte{0x30, 0x01, 0x05, 0x00}},
		{"child high tag", []byte{0x30, 0x02, 0x1f, 0x81, 0x00, 0x00}},
		{"child long length", []byte{0x30, 0x02, 0x04, 0x81, 0x80}},
		{"EOC outside parent", []byte{0x30, 0x02, 0x30, 0x80, 0x00, 0x00}},
		{"EOC split at parent", []byte{0x30, 0x03, 0x30, 0x80, 0x00, 0x00}},
		{"indefinite ancestor", []byte{0x30, 0x80, 0x30, 0x02, 0x04, 0x01, 0x41, 0x00, 0x00}},
		{"32 bit length overflow", []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			if _, err := ber2der(fixture.input); err == nil {
				t.Fatal("ber2der accepted a child outside its parent")
			}
			if _, err := Parse(fixture.input); err == nil || !strings.HasPrefix(err.Error(), "ber2der:") {
				t.Fatalf("Parse did not reject input at the BER boundary: %v", err)
			}
		})
	}
}

func TestBer2DerRejectsBeforeReadingOutsideParent(t *testing.T) {
	t.Parallel()
	// The indefinite child has no content inside the definite parent. Data
	// beyond that boundary must not be traversed, even to find its terminator.
	input := append([]byte{0x30, 0x02}, bytes.Repeat([]byte{0x30, 0x80}, maxNestingDepth+2)...)
	if _, err := ber2der(input); err == nil || !strings.Contains(err.Error(), endOfBERDataError) {
		t.Fatalf("expected immediate end-of-data error, got %v", err)
	}
}

func TestBer2DerBoundaryControls(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		name        string
		input, want []byte
	}{
		{"exact parent end", []byte{0x30, 0x02, 0x05, 0x00}, []byte{0x30, 0x02, 0x05, 0x00}},
		{"empty indefinite", []byte{0x30, 0x80, 0x00, 0x00}, []byte{0x30, 0x00}},
		{"empty indefinite inside definite", []byte{0x30, 0x04, 0x30, 0x80, 0x00, 0x00}, []byte{0x30, 0x02, 0x30, 0x00}},
		{"empty indefinite siblings", []byte{0x30, 0x80, 0x30, 0x80, 0, 0, 0x30, 0x80, 0, 0, 0, 0}, []byte{0x30, 4, 0x30, 0, 0x30, 0}},
		{"zeros inside primitive", []byte{0x30, 0x80, 0x04, 0x02, 0, 0, 0, 0}, []byte{0x30, 4, 0x04, 2, 0, 0}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := ber2der(fixture.input)
			if err != nil || !bytes.Equal(got, fixture.want) {
				t.Fatalf("ber2der = % X, %v; want % X", got, err, fixture.want)
			}
		})
	}
}

func TestBer2DerNestingLimit(t *testing.T) {
	t.Parallel()
	for _, indefinite := range []bool{false, true} {
		for _, depth := range []int{maxNestingDepth, maxNestingDepth + 1} {
			input := []byte{0x05, 0x00}
			for i := 0; i < depth; i++ {
				if indefinite {
					input = append(append([]byte{0x30, 0x80}, input...), 0, 0)
				} else {
					var err error
					input, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: input})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := ber2der(input)
			if depth == maxNestingDepth {
				if err != nil {
					t.Fatalf("indefinite=%v: rejected allowed depth: %v", indefinite, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "maximum nesting depth exceeded") {
				t.Fatalf("indefinite=%v: expected depth error, got %v", indefinite, err)
			}
		}
	}
}
