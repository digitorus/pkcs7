package pkcs7

import (
	"bytes"
	"crypto/des"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128CBC,
		EncryptionAlgorithmAES256CBC,
		EncryptionAlgorithmAES128GCM,
		EncryptionAlgorithmAES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			ContentEncryptionAlgorithm = mode

			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptUsingPSK(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch mode {
		case EncryptionAlgorithmDESCBC:
			key = []byte("64BitKey")
		case EncryptionAlgorithmAES128GCM:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded := appendPadded(nil, test.Original, test.BlockSize)
		if !bytes.Equal(test.Expected, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

func TestEncryptCBCDoesNotWriteIntoSpareCapacity(t *testing.T) {
	block, err := des.NewCipher([]byte("64BitKey"))
	if err != nil {
		t.Fatal(err)
	}
	backing := []byte{1, 2, 3, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	// #nosec G407 -- The IV is irrelevant; this only checks which memory encryptCBC writes.
	encryptCBC(block, make([]byte, des.BlockSize), backing[:3])
	if !bytes.Equal(backing, []byte{1, 2, 3, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}) {
		t.Fatalf("encryptCBC modified the caller's backing array: % X", backing)
	}
}

func TestNewOctetStringMatchesASN1Marshal(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1<<24 - 1, 1 << 24} {
		content := bytes.Repeat([]byte{0xAB}, n)
		want, err := asn1.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		out := newOctetString(n)
		if c := cap(out); c != len(want) {
			t.Errorf("n=%d: cap %d, want %d", n, c, len(want))
		}
		if got := append(out, content...); !bytes.Equal(got, want) {
			t.Errorf("n=%d: header % X, want % X", n, got[:len(out)], want[:len(want)-n])
		}
	}
}
