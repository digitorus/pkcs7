package pkcs7

import (
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBouncyCastleMLDSAInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_BOUNCY_CASTLE_INTEROP") == "" {
		t.Skip("set PKCS7_BOUNCY_CASTLE_INTEROP to run Bouncy Castle interoperability tests")
	}
	classpath := os.Getenv("PKCS7_BOUNCY_CASTLE_CLASSPATH")
	if classpath == "" {
		t.Fatal("PKCS7_BOUNCY_CASTLE_CLASSPATH is required")
	}

	content := []byte("Bouncy Castle and Go agree on RFC 9882 ML-DSA CMS")
	for _, algorithm := range mlDSATestCases {
		t.Run(algorithm.name, func(t *testing.T) {
			certificate, privateKey := createMLDSATestCertificate(t, algorithm)
			dir := t.TempDir()
			certificatePath := filepath.Join(dir, "certificate.der")
			keyPath := filepath.Join(dir, "private-key.der")
			contentPath := filepath.Join(dir, "content.bin")
			writeTestFile(t, certificatePath, certificate.Raw)
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
						if direct {
							err = signedData.SignWithoutAttr(certificate, privateKey, SignerInfoConfig{})
						} else {
							err = signedData.AddSigner(certificate, privateKey, SignerInfoConfig{})
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
							cmsPath, strconv.FormatBool(detached), strconv.FormatBool(direct), "ML-DSA", "ML-DSA")
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
						assertMLDSAStructure(t, parsed, algorithm, !direct)
						if err := parsed.Verify(); err != nil {
							t.Fatalf("Go verification failed: %v", err)
						}
					})
				}
			}
		})
	}
}

func runBouncyCastleCommand(t *testing.T, classpath string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-cp", classpath, "BouncyCastleInterop"}, args...)
	// #nosec G702 -- this opt-in test harness intentionally runs the configured Java runtime and classpath.
	output, err := exec.Command("java", commandArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("Bouncy Castle %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func interopCaseName(detached, direct bool) string {
	contentMode := embeddedContentTestName
	if detached {
		contentMode = detachedContentTestName
	}
	attributeMode := "signed_attributes"
	if direct {
		attributeMode = "without_attributes"
	}
	return contentMode + "/" + attributeMode
}

func writeTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
