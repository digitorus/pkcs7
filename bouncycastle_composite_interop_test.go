package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBouncyCastleCompositeInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_BOUNCY_CASTLE_INTEROP") == "" {
		t.Skip("set PKCS7_BOUNCY_CASTLE_INTEROP to run Bouncy Castle interoperability tests")
	}
	classpath := os.Getenv("PKCS7_BOUNCY_CASTLE_CLASSPATH")
	if classpath == "" {
		t.Fatal("PKCS7_BOUNCY_CASTLE_CLASSPATH is required")
	}

	algorithms := []struct {
		name   string
		arc    int
		sha256 bool
	}{
		{"MLDSA44-RSA2048-PSS-SHA256", 37, true},
		{"MLDSA44-RSA2048-PKCS15-SHA256", 38, true},
		{"MLDSA44-Ed25519-SHA512", 39, false},
		{"MLDSA44-ECDSA-P256-SHA256", 40, true},
		{"MLDSA65-RSA3072-PSS-SHA512", 41, false},
		{"MLDSA65-RSA3072-PKCS15-SHA512", 42, false},
		{"MLDSA65-RSA4096-PSS-SHA512", 43, false},
		{"MLDSA65-RSA4096-PKCS15-SHA512", 44, false},
		{"MLDSA65-ECDSA-P256-SHA512", 45, false},
		{"MLDSA65-ECDSA-P384-SHA512", 46, false},
		{"MLDSA65-Ed25519-SHA512", 48, false},
		{"MLDSA87-ECDSA-P384-SHA512", 49, false},
		{"MLDSA87-RSA3072-PSS-SHA512", 52, false},
		{"MLDSA87-RSA4096-PSS-SHA512", 53, false},
		{"MLDSA87-ECDSA-P521-SHA512", 54, false},
	}

	content := []byte("Bouncy Castle and Go agree on RFC 10073 / RFC 10082 composite CMS")
	for _, algorithm := range algorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			dir := t.TempDir()
			contentPath := filepath.Join(dir, "content.bin")
			writeTestFile(t, contentPath, content)

			runBouncyCastleCommand(t, classpath, "composite-sign", algorithm.name, contentPath, dir)

			for _, detached := range []bool{false, true} {
				for _, direct := range []bool{false, true} {
					name := interopCaseName(detached, direct)
					t.Run("Bouncy_Castle_to_Go/"+name, func(t *testing.T) {
						contentMode := "embedded"
						if detached {
							contentMode = "detached"
						}
						attributeMode := "attributes"
						if direct {
							attributeMode = "direct"
						}
						cmsPath := filepath.Join(dir, fmt.Sprintf("%s-%s.der", contentMode, attributeMode))

						load := func() *PKCS7 {
							t.Helper()
							der, err := os.ReadFile(cmsPath)
							if err != nil {
								t.Fatal(err)
							}
							p7, err := Parse(der)
							if err != nil {
								t.Fatalf("Parse: %v", err)
							}
							if len(p7.Signers) != 1 || len(p7.Certificates) != 1 {
								t.Fatalf("got %d signers and %d certificates; want one each",
									len(p7.Signers), len(p7.Certificates))
							}
							signer := p7.Signers[0]
							wantOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, algorithm.arc}
							if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(wantOID) {
								t.Fatalf("signature OID = %s; want %s",
									signer.DigestEncryptionAlgorithm.Algorithm, wantOID)
							}
							wantDigest := OIDDigestAlgorithmSHA512
							if algorithm.sha256 {
								wantDigest = OIDDigestAlgorithmSHA256
							}
							if !signer.DigestAlgorithm.Algorithm.Equal(wantDigest) {
								t.Fatalf("CMS digest OID = %s; want %s",
									signer.DigestAlgorithm.Algorithm, wantDigest)
							}
							if (len(signer.AuthenticatedAttributes) == 0) != direct {
								t.Fatalf("unexpected signed attribute presence: direct=%t", direct)
							}
							if detached {
								if len(p7.Content) != 0 {
									t.Fatal("detached CMS unexpectedly includes content")
								}
								p7.Content = bytes.Clone(content)
							} else if !bytes.Equal(p7.Content, content) {
								t.Fatal("embedded CMS content mismatch")
							}
							return p7
						}

						p7 := load()
						if err := p7.Verify(); err != nil {
							t.Fatalf("Verify: %v", err)
						}
						if err := p7.VerifyWithOpts(x509.VerifyOptions{
							CurrentTime: time.Now(),
						}); err != nil {
							t.Fatalf("VerifyWithOpts: %v", err)
						}

						t.Run("modified_content", func(t *testing.T) {
							p7 := load()
							p7.Content[0] ^= 1
							if err := p7.Verify(); err == nil {
								t.Fatal("verified modified CMS content")
							}
						})
						t.Run("modified_ml_dsa_signature", func(t *testing.T) {
							p7 := load()
							p7.Signers[0].EncryptedDigest[0] ^= 1
							if err := p7.Verify(); err == nil {
								t.Fatal("verified corrupted ML-DSA component")
							}
						})
						t.Run("modified_traditional_signature", func(t *testing.T) {
							p7 := load()
							sig := p7.Signers[0].EncryptedDigest
							sig[len(sig)-1] ^= 1
							if err := p7.Verify(); err == nil {
								t.Fatal("verified corrupted traditional component")
							}
						})
					})
				}
			}
		})
	}
}
