package pkcs7

import (
	"bytes"
	"errors"
)

// maxNestingDepth bounds recursive descent into constructed BER/DER objects.
// Legitimate PKCS#7/CMS structures do not nest anywhere close to this deep;
// the limit exists purely as defense in depth against malformed or
// adversarial input driving unbounded recursion.
const maxNestingDepth = 500

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
	encodedLen() int
}

type asn1Structured struct {
	tagBytes []byte
	length   int // DER length of the encoded content
	content  []asn1Object
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	// fmt.Printf("%s--> tag: % X\n", strings.Repeat("| ", encodeIndent), s.tagBytes)
	out.Write(s.tagBytes)
	_ = encodeLength(out, s.length)
	for _, obj := range s.content {
		err := obj.EncodeTo(out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s asn1Structured) encodedLen() int {
	return derObjectLen(s.tagBytes, s.length)
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	// fmt.Printf("%s--> tag: % X length: %d\n", strings.Repeat("| ", encodeIndent), p.tagBytes, p.length)
	// fmt.Printf("%s--> content length: %d\n", strings.Repeat("| ", encodeIndent), len(p.content))
	out.Write(p.content)

	return nil
}

func (p asn1Primitive) encodedLen() int {
	return derObjectLen(p.tagBytes, p.length)
}

// derObjectLen returns the size of a DER object with the given tag and content length.
func derObjectLen(tagBytes []byte, length int) int {
	n := len(tagBytes) + 1 + length
	if length >= 128 {
		n += lengthLength(length)
	}
	return n
}

func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	// fmt.Printf("--> ber2der: Transcoding %d bytes\n", len(ber))
	// Already-DER input (the common case) is returned without copying. The
	// result aliases ber, matching encoding/asn1 and crypto/x509 semantics.
	end, isDER, err := derScan(ber, 0, 0)
	if err != nil {
		return nil, err
	}
	if isDER {
		return ber[:end:end], nil
	}
	obj, _, err := readObject(ber, 0, 0)
	if err != nil {
		return nil, err
	}
	out := bytes.NewBuffer(make([]byte, 0, obj.encodedLen()))
	_ = obj.EncodeTo(out)

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//
//	length | byte 1 | bytes n
//	0      | 0x00   | -
//	120    | 0x78   | -
//	200    | 0x81   | 0xC8
//	500    | 0x82   | 0x01 0xF4
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

// berHeader describes the identifier and length octets of one BER object.
type berHeader struct {
	tagStart     int
	tagEnd       int
	contentStart int
	length       int
	constructed  bool
	indefinite   bool
	// canonical reports whether the length octets are already in DER form.
	canonical bool
}

// readHeader parses and validates the identifier and length octets of the
// object at offset without allocating on success.
func readHeader(ber []byte, offset, depth int) (berHeader, error) {
	if depth > maxNestingDepth {
		return berHeader{}, errors.New("ber2der: maximum nesting depth exceeded")
	}
	berLen := len(ber)
	if offset >= berLen {
		return berHeader{}, errors.New("ber2der: offset is after end of ber data")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if offset >= berLen {
		return berHeader{}, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset >= berLen {
				return berHeader{}, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		// jvehent 20170227: this doesn't appear to be used anywhere...
		// tag = tag*128 + ber[offset] - 0x80
		offset++
		if offset >= berLen {
			return berHeader{}, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
	}
	tagEnd := offset

	kind := b & 0x20
	if kind == 0 {
		debugprint("--> Primitive\n")
	} else {
		debugprint("--> Constructed\n")
	}
	// read length
	var length int
	l := ber[offset]
	offset++
	if l >= 0x80 && offset >= berLen {
		// if indefinite or multibyte length, we need to verify there is at least one more byte available
		// otherwise we need to be flexible here for length == 0 conditions
		// validation that the length is available is done after the length is correctly parsed
		return berHeader{}, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	canonical := true
	if l > 0x80 {
		numberOfBytes := int(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return berHeader{}, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && int(ber[offset]) > 0x7F {
			return berHeader{}, errors.New("ber2der: BER tag length is negative")
		}
		if offset+numberOfBytes > berLen {
			// == condition is not checked here, this allows for a more descreptive error when the parsed length is
			// compared with the remaining available bytes (`contentEnd > berLen`)
			return berHeader{}, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
		if int(ber[offset]) == 0x0 && (numberOfBytes == 1 || ber[offset+1] <= 0x7F) {
			// `numberOfBytes == 1` is an important conditional to avoid a potential out of bounds panic with `ber[offset+1]`
			return berHeader{}, errors.New("ber2der: BER tag length has leading zero")
		}
		debugprint("--> (compute length) indicator byte: %x\n", l)
		// debugprint("--> (compute length) length bytes: %x\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + int(ber[offset])
			offset++
		}
		canonical = length >= 128 && numberOfBytes == lengthLength(length)
	} else if l == 0x80 {
		indefinite = true
		canonical = false
	} else {
		length = int(l)
	}
	if length < 0 {
		return berHeader{}, errors.New("ber2der: invalid negative value found in BER tag length")
	}
	// fmt.Printf("--> length        : %d\n", length)
	if length > berLen-offset {
		return berHeader{}, errors.New("ber2der: BER tag length is more than available data")
	}
	debugprint("--> content start : %d\n", offset)
	debugprint("--> content end   : %d\n", offset+length)
	// debugprint("--> content       : %x\n", ber[offset:contentEnd])
	if indefinite && kind == 0 {
		return berHeader{}, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	return berHeader{
		tagStart:     tagStart,
		tagEnd:       tagEnd,
		contentStart: offset,
		length:       length,
		constructed:  kind != 0,
		indefinite:   indefinite,
		canonical:    canonical,
	}, nil
}

// derScan walks the object at offset without allocating. It reports the end
// of the object and whether it is already DER encoded, in which case
// transcoding would reproduce the input unchanged. It stops at the first
// non-DER length so that readObject reports errors in the same order.
func derScan(ber []byte, offset, depth int) (int, bool, error) {
	h, err := readHeader(ber, offset, depth)
	if err != nil || !h.canonical {
		return 0, false, err
	}
	contentEnd := h.contentStart + h.length
	if h.constructed {
		ber = ber[:contentEnd]
		offset = h.contentStart
		for offset < contentEnd {
			var ok bool
			offset, ok, err = derScan(ber, offset, depth+1)
			if err != nil || !ok {
				return 0, false, err
			}
		}
	}
	return contentEnd, true, nil
}

func readObject(ber []byte, offset, depth int) (asn1Object, int, error) {
	h, err := readHeader(ber, offset, depth)
	if err != nil {
		return nil, 0, err
	}
	tagStart, tagEnd, indefinite, length := h.tagStart, h.tagEnd, h.indefinite, h.length
	offset = h.contentStart
	contentEnd := offset + length
	var obj asn1Object
	if !h.constructed {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		subObjectsLen := 0
		// Restrict every descendant, including indefinite-length children, to
		// this object's content before parsing it. A check after recursion
		// would allow work on bytes outside the parent before rejecting them.
		if !indefinite {
			ber = ber[:contentEnd]
		}
		for (offset < contentEnd) || indefinite {
			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}
				if terminated {
					break
				}
			}
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset, depth+1)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)
			subObjectsLen += subObj.encodedLen()
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			length:   subObjectsLen,
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	// An end-of-contents marker terminates the current indefinite-length object
	// only when it begins at the current offset.
	return ber[offset] == 0 && ber[offset+1] == 0, nil
}

func debugprint(format string, a ...interface{}) {
	// fmt.Printf(format, a)
}
