package pkcs7

import (
	"bytes"
	"crypto/x509"
	"testing"
)

var benchSigAlgs = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA,
	x509.ECDSAWithSHA256,
	x509.PureEd25519,
}

func benchContent(size int) []byte { return bytes.Repeat([]byte{'a'}, size) }

func benchSign(b *testing.B, pair certKeyPair, content []byte) []byte {
	sd, err := NewSignedData(content)
	if err != nil {
		b.Fatal(err)
	}
	dig, _ := GetDigestOIDForSignatureAlgorithm(pair.Certificate.SignatureAlgorithm)
	sd.SetDigestAlgorithm(dig)
	if err := sd.AddSigner(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		b.Fatal(err)
	}
	out, err := sd.Finish()
	if err != nil {
		b.Fatal(err)
	}
	return out
}

func BenchmarkSign(b *testing.B) {
	for _, alg := range benchSigAlgs {
		pair, err := createTestCertificate(alg)
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{1 << 10, 1 << 20} {
			content := benchContent(size)
			b.Run(alg.String()+"/"+sizeName(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					benchSign(b, pair, content)
				}
			})
		}
	}
}

func BenchmarkParse(b *testing.B) {
	pair, _ := createTestCertificate(x509.SHA256WithRSA)
	for _, size := range []int{1 << 10, 1 << 20} {
		signed := benchSign(b, pair, benchContent(size))
		b.Run(sizeName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(signed)))
			for b.Loop() {
				if _, err := Parse(signed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParseAndVerify(b *testing.B) {
	for _, alg := range benchSigAlgs {
		pair, err := createTestCertificate(alg)
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{1 << 10, 1 << 20} {
			signed := benchSign(b, pair, benchContent(size))
			b.Run(alg.String()+"/"+sizeName(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					p7, err := Parse(signed)
					if err != nil {
						b.Fatal(err)
					}
					if err := p7.Verify(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	saved := ContentEncryptionAlgorithm
	defer func() { ContentEncryptionAlgorithm = saved }()
	pair, _ := createTestCertificate(x509.SHA256WithRSA)
	modes := map[string]int{
		"AES128CBC": EncryptionAlgorithmAES128CBC,
		"AES256CBC": EncryptionAlgorithmAES256CBC,
		"AES128GCM": EncryptionAlgorithmAES128GCM,
		"AES256GCM": EncryptionAlgorithmAES256GCM,
	}
	for _, name := range []string{"AES128CBC", "AES256CBC", "AES128GCM", "AES256GCM"} {
		ContentEncryptionAlgorithm = modes[name]
		for _, size := range []int{1 << 10, 1 << 20} {
			content := benchContent(size)
			b.Run("Encrypt/"+name+"/"+sizeName(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if _, err := Encrypt(content, []*x509.Certificate{pair.Certificate}); err != nil {
						b.Fatal(err)
					}
				}
			})
			enc, err := Encrypt(content, []*x509.Certificate{pair.Certificate})
			if err != nil {
				b.Fatal(err)
			}
			b.Run("ParseDecrypt/"+name+"/"+sizeName(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					p7, err := Parse(enc)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := p7.Decrypt(pair.Certificate, *pair.PrivateKey); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkBer2Der(b *testing.B) {
	pair, _ := createTestCertificate(x509.SHA256WithRSA)
	signed := benchSign(b, pair, benchContent(1<<20))
	b.ReportAllocs()
	b.SetBytes(int64(len(signed)))
	for b.Loop() {
		if _, err := ber2der(signed); err != nil {
			b.Fatal(err)
		}
	}
}

func sizeName(n int) string {
	if n >= 1<<20 {
		return "1MiB"
	}
	return "1KiB"
}
