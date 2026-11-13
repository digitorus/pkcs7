package pkcs7

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	dir := t.TempDir()
	contentPath := filepath.Join(dir, "content.bin")
	content := []byte("Bouncy Castle and Go agree on RFC 10073 / RFC 10082 composite CMS")
	writeTestFile(t, contentPath, content)

	args := []string{"composite-sign-batch", contentPath, dir}
	for _, algorithm := range compositeAlgorithms {
		name := strings.TrimPrefix(algorithm.label, "COMPSIG-")
		args = append(args, name)
	}
	runBouncyCastleCommand(t, classpath, args...)

	for _, algorithm := range compositeAlgorithms {
		name := strings.TrimPrefix(algorithm.label, "COMPSIG-")

		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(dir, name)

			issuerDER, err := os.ReadFile(filepath.Join(dir, "issuer.der"))
			if err != nil {
				t.Fatal(err)
			}

			issuerCert, err := x509.ParseCertificate(issuerDER)
			if err != nil {
				t.Fatal(err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(issuerCert)

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

						load := func(t *testing.T) *PKCS7 {
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
							if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(algorithm.oid) {
								t.Fatalf("signature OID = %s; want %s",
									signer.DigestEncryptionAlgorithm.Algorithm, algorithm.oid)
							}

							if !signer.DigestAlgorithm.Algorithm.Equal(algorithm.digestOID) {
								t.Fatalf("CMS digest OID = %s; want %s",
									signer.DigestAlgorithm.Algorithm, algorithm.digestOID)
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

						p7 := load(t)
						if err := p7.Verify(); err != nil {
							t.Fatalf("Verify: %v", err)
						}
						if err := p7.VerifyWithChain(roots); err != nil {
							t.Fatalf("VerifyWithChain: %v", err)
						}
						if err := p7.VerifyWithChain(x509.NewCertPool()); err == nil {
							t.Fatal("accepted composite signer with no trusted CA")
						}
						if err := p7.VerifyWithOpts(x509.VerifyOptions{
							CurrentTime: time.Now(),
						}); err != nil {
							t.Fatalf("VerifyWithOpts: %v", err)
						}

						t.Run("modified_content", func(t *testing.T) {
							p7 := load(t)
							p7.Content[0] ^= 1
							if err := p7.Verify(); err == nil {
								t.Fatal("verified modified CMS content")
							}
						})
						t.Run("modified_ml_dsa_signature", func(t *testing.T) {
							p7 := load(t)
							p7.Signers[0].EncryptedDigest[0] ^= 1
							if err := p7.Verify(); err == nil {
								t.Fatal("verified corrupted ML-DSA component")
							}
						})
						t.Run("modified_traditional_signature", func(t *testing.T) {
							p7 := load(t)
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
