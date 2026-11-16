package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if !bytes.Equal(content, expected) {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

// echo -n "This is a test" > test.txt
// openssl cms -encrypt -in test.txt cert.pem
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBGgYJKoZIhvcNAQcDoIIBCzCCAQcCAQAxgcwwgckCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMA0GCSqGSIb3
DQEBAQUABIGAyFz7bfI2noUs4FpmYfztm1pVjGyB00p9x0H3gGHEYNXdqlq8VG8d
iq36poWtEkatnwsOlURWZYECSi0g5IAL0U9sj82EN0xssZNaK0S5FTGnB3DPvYgt
HJvcKq7YvNLKMh4oqd17C6GB4oXyEBDj0vZnL7SUoCAOAWELPeC8CTUwMwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhEowTkot3a7oAQFD//J/IhFnk+JbkH7HZQFA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

// fragmentEncryptedContent re-encodes the single OCTET STRING in eci's
// EncryptedContent as OCTET STRING fragments of at most size bytes, followed
// by extra.
func fragmentEncryptedContent(t *testing.T, eci *encryptedContentInfo, size int, extra []byte) {
	t.Helper()
	var whole asn1.RawValue
	if _, err := asn1.Unmarshal(eci.EncryptedContent.Bytes, &whole); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for ct := whole.Bytes; len(ct) > 0; {
		n := min(size, len(ct))
		b, err := asn1.Marshal(ct[:n])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
		ct = ct[n:]
	}
	eci.EncryptedContent.Bytes = append(out, extra...)
}

func encryptForFragmentTest(t *testing.T, mode int, plaintext []byte) ([]byte, *encryptedContentInfo) {
	t.Helper()
	saved := ContentEncryptionAlgorithm
	t.Cleanup(func() { ContentEncryptionAlgorithm = saved })
	ContentEncryptionAlgorithm = mode
	var (
		key []byte
		eci *encryptedContentInfo
		err error
	)
	switch mode {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(plaintext, nil)
	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAESGCM(plaintext, nil)
	default:
		t.Fatalf("unsupported mode %d", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key, eci
}

var fragmentTestModes = map[string]int{
	"DES-CBC":    EncryptionAlgorithmDESCBC,
	"AES128-GCM": EncryptionAlgorithmAES128GCM,
}

func TestDecryptFragmentedEncryptedContent(t *testing.T) {
	plaintext := bytes.Repeat([]byte("fragmented content "), 10)
	for name, mode := range fragmentTestModes {
		t.Run(name, func(t *testing.T) {
			key, eci := encryptForFragmentTest(t, mode, plaintext)
			fragmentEncryptedContent(t, eci, 40, nil)
			got, err := eci.decrypt(key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("got %q, want %q", got, plaintext)
			}
		})
	}
}

func TestDecryptRejectsMalformedEncryptedContent(t *testing.T) {
	plaintext := bytes.Repeat([]byte("fragmented content "), 10)
	tests := []struct {
		name  string
		size  int
		extra []byte
		first []byte
	}{
		{name: "trailing garbage", size: 1 << 20, extra: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{name: "trailing non OCTET STRING", size: 40, extra: []byte{0x02, 0x01, 0x05}},
		{name: "constructed child", size: 40, extra: []byte{0x24, 0x02, 0x04, 0x00}},
		{name: "truncated later fragment", size: 40, extra: []byte{0x04, 0x05, 0x01}},
		{name: "malformed first child", first: []byte{0x04, 0x7F, 0x00}},
	}
	for name, mode := range fragmentTestModes {
		for _, tc := range tests {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				key, eci := encryptForFragmentTest(t, mode, plaintext)
				if tc.first != nil {
					eci.EncryptedContent.Bytes = tc.first
				} else {
					fragmentEncryptedContent(t, eci, tc.size, tc.extra)
				}
				got, err := eci.decrypt(key)
				if err == nil {
					t.Fatalf("decrypt succeeded with %d bytes", len(got))
				}
				if !strings.Contains(err.Error(), "EncryptedContent") {
					t.Fatalf("got %q, want an EncryptedContent parse error", err)
				}
			})
		}
	}
}
