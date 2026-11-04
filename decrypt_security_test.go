package pkcs7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
)

func TestUnpadSecurity(t *testing.T) {
	for _, size := range []int{8, 16} {
		for padlen := 0; padlen < 256; padlen++ {
			data := bytes.Repeat([]byte{byte(padlen)}, size*2)
			got, err := unpad(data, size)
			valid := padlen >= 1 && padlen <= size
			if valid && (err != nil || !bytes.Equal(got, data[:len(data)-padlen])) {
				t.Fatalf("size=%d pad=%d: %x, %v", size, padlen, got, err)
			}
			if !valid && (err == nil || got != nil) {
				t.Fatalf("accepted size=%d pad=%d", size, padlen)
			}
		}
		for pos := 0; pos < size; pos++ {
			data := bytes.Repeat([]byte{byte(size)}, size)
			data[pos] ^= 1
			if got, err := unpad(data, size); err == nil || got != nil {
				t.Fatalf("accepted corrupt padding at %d", pos)
			}
		}
	}
	for _, tc := range []struct {
		data []byte
		size int
	}{{nil, 8}, {[]byte{1}, 8}, {[]byte{1}, 0}, {[]byte{1}, -1}} {
		if got, err := unpad(tc.data, tc.size); err == nil || got != nil {
			t.Fatal("accepted malformed input")
		}
	}
}

func TestCBCPaddingSecurity(t *testing.T) {
	algorithms := []struct {
		name  string
		oid   asn1.ObjectIdentifier
		key   []byte
		block cipher.Block
	}{
		{name: "DES", oid: OIDEncryptionAlgorithmDESCBC, key: make([]byte, 8)},
		{name: "3DES", oid: OIDEncryptionAlgorithmDESEDE3CBC, key: make([]byte, 24)},
		{name: "AES128", oid: OIDEncryptionAlgorithmAES128CBC, key: make([]byte, 16)},
		{name: "AES256", oid: OIDEncryptionAlgorithmAES256CBC, key: make([]byte, 32)},
	}
	for _, alg := range algorithms {
		var err error
		switch alg.name {
		case "DES":
			alg.block, err = des.NewCipher(alg.key)
		case "3DES":
			alg.block, err = des.NewTripleDESCipher(alg.key)
		default:
			alg.block, err = aes.NewCipher(alg.key)
		}
		if err != nil {
			t.Fatal(err)
		}
		size := alg.block.BlockSize()
		for _, compound := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/constructed=%v", alg.name, compound), func(t *testing.T) {
				for padlen := 0; padlen < 256; padlen++ {
					plain := bytes.Repeat([]byte{byte(padlen)}, size)
					ciphertext := make([]byte, size)
					// #nosec G407 -- A fixed IV is intentional for synthetic padding-validation fixtures.
					cipher.NewCBCEncrypter(alg.block, make([]byte, size)).CryptBlocks(ciphertext, plain)
					eci := encryptedContentInfo{ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg.oid, Parameters: asn1.RawValue{Bytes: make([]byte, size)}}, EncryptedContent: asn1.RawValue{Bytes: ciphertext}}
					if compound {
						encoded, e := asn1.Marshal(ciphertext)
						if e != nil {
							t.Fatal(e)
						}
						eci.EncryptedContent = asn1.RawValue{IsCompound: true, Bytes: encoded}
					}
					p7 := PKCS7{raw: encryptedData{EncryptedContentInfo: eci}}
					got, e := p7.DecryptUsingPSK(alg.key)
					valid := padlen >= 1 && padlen <= size
					if valid && (e != nil || !bytes.Equal(got, plain[:size-padlen])) {
						t.Fatalf("pad=%d: %x, %v", padlen, got, e)
					}
					if !valid && (e == nil || got != nil || e.Error() != "invalid padding") {
						t.Fatalf("pad=%d: %x, %v", padlen, got, e)
					}
				}
				for _, length := range []int{0, 1, size - 1, size + 1} {
					eci := encryptedContentInfo{ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg.oid, Parameters: asn1.RawValue{Bytes: make([]byte, size)}}, EncryptedContent: asn1.RawValue{Bytes: make([]byte, length)}}
					if compound {
						encoded, e := asn1.Marshal(eci.EncryptedContent.Bytes)
						if e != nil {
							t.Fatal(e)
						}
						eci.EncryptedContent = asn1.RawValue{IsCompound: true, Bytes: encoded}
					}
					if got, e := eci.decrypt(alg.key); e == nil || got != nil {
						t.Fatalf("accepted ciphertext length %d", length)
					}
				}
			})
		}
	}
}
