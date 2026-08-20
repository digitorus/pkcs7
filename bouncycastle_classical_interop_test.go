package pkcs7

import (
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBouncyCastleClassicalInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_BOUNCY_CASTLE_INTEROP") == "" {
		t.Skip("set PKCS7_BOUNCY_CASTLE_INTEROP to run Bouncy Castle interoperability tests")
	}
	classpath := os.Getenv("PKCS7_BOUNCY_CASTLE_CLASSPATH")
	if classpath == "" {
		t.Fatal("PKCS7_BOUNCY_CASTLE_CLASSPATH is required")
	}

	content := []byte("Bouncy Castle and Go agree on classical CMS signatures")
	for _, algorithm := range classicalInteropAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			pair, err := createTestCertificate(algorithm.certificateSignatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			privateKey, ok := (*pair.PrivateKey).(crypto.Signer)
			if !ok {
				t.Fatalf("private key type = %T, want crypto.Signer", *pair.PrivateKey)
			}
			dir := t.TempDir()
			certificatePath := filepath.Join(dir, "certificate.der")
			keyPath := filepath.Join(dir, "private-key.der")
			contentPath := filepath.Join(dir, "content.bin")
			writeTestFile(t, certificatePath, pair.Certificate.Raw)
			keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, keyPath, keyDER)
			writeTestFile(t, contentPath, content)

			for _, detached := range []bool{false, true} {
				for _, direct := range []bool{false, true} {
					name := interopCaseName(detached, direct)
					t.Run("Go_to_Bouncy_Castle/"+name, func(t *testing.T) {
						signedData, err := NewSignedData(content)
						if err != nil {
							t.Fatal(err)
						}
						signedData.SetDigestAlgorithm(algorithm.digestOID)
						if direct {
							err = signedData.SignWithoutAttr(pair.Certificate, privateKey, SignerInfoConfig{})
						} else {
							err = signedData.AddSigner(pair.Certificate, privateKey, SignerInfoConfig{})
						}
						if err != nil {
							t.Fatal(err)
						}
						if detached {
							signedData.Detach()
						}
						cmsDER, err := signedData.Finish()
						if err != nil {
							t.Fatal(err)
						}
						cmsPath := filepath.Join(dir, "go-"+strings.ReplaceAll(name, "/", "-")+".der")
						writeTestFile(t, cmsPath, cmsDER)
						runBouncyCastleCommand(t, classpath, "verify", cmsPath, contentPath, strconv.FormatBool(detached))
					})

					t.Run("Bouncy_Castle_to_Go/"+name, func(t *testing.T) {
						cmsPath := filepath.Join(dir, "bc-"+strings.ReplaceAll(name, "/", "-")+".der")
						runBouncyCastleCommand(t, classpath, "sign", certificatePath, keyPath, contentPath,
							cmsPath, strconv.FormatBool(detached), strconv.FormatBool(direct),
							algorithm.bouncyCastleKeyAlgorithm, algorithm.bouncyCastleSignatureAlgorithm)
						cmsDER, err := os.ReadFile(cmsPath)
						if err != nil {
							t.Fatal(err)
						}
						parsed, err := Parse(cmsDER)
						if err != nil {
							t.Fatal(err)
						}
						if detached {
							parsed.Content = content
						}
						assertClassicalStructure(t, parsed, algorithm.digestOID,
							algorithm.bouncyCastleSignatureOID, !direct)
						if err := parsed.Verify(); err != nil {
							t.Fatalf("Go verification failed: %v", err)
						}
					})
				}
			}
		})
	}
}
