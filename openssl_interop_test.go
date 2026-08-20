package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSSLMLKEMInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_OPENSSL_INTEROP") == "" {
		t.Skip("set PKCS7_OPENSSL_INTEROP to run interoperability tests with openssl from PATH")
	}
	requireOpenSSLMLKEM(t)

	for _, test := range mlKEMInteropCases {
		t.Run(test.name, func(t *testing.T) {
			privateKey, seed, publicKey := newMLKEMInteropKey(t, test)
			certificate := newMLKEMInteropCertificate(t, test, publicKey)

			dir := t.TempDir()
			privateKeyPath := filepath.Join(dir, "recipient-key.pem")
			publicKeyPath := filepath.Join(dir, "recipient-public.pem")
			certificatePath := filepath.Join(dir, "recipient-cert.pem")
			writeMLKEMInteropKeys(t, test, seed, publicKey, privateKeyPath, publicKeyPath)
			writeTestFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))

			plaintext := []byte("OpenSSL and Go agree on RFC 9629/9936 ML-KEM CMS")
			plaintextPath := filepath.Join(dir, "plaintext.bin")
			if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
				t.Fatal(err)
			}

			t.Run("Go to OpenSSL", func(t *testing.T) {
				withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
				cmsDER, err := Encrypt(plaintext, []*x509.Certificate{certificate})
				if err != nil {
					t.Fatal(err)
				}
				cmsPath := filepath.Join(dir, "go-enveloped.der")
				decryptedPath := filepath.Join(dir, "openssl-decrypted.bin")
				if err := os.WriteFile(cmsPath, cmsDER, 0o600); err != nil {
					t.Fatal(err)
				}
				runOpenSSL(t, "cms", "-decrypt", "-binary", "-inform", "DER",
					"-in", cmsPath, "-recip", certificatePath, "-inkey", privateKeyPath,
					"-out", decryptedPath)
				decrypted, err := os.ReadFile(decryptedPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("OpenSSL decrypted %q, want %q", decrypted, plaintext)
				}
			})

			t.Run("OpenSSL to Go", func(t *testing.T) {
				cmsPath := filepath.Join(dir, "openssl-enveloped.der")
				runOpenSSL(t, "cms", "-encrypt", "-binary", "-in", plaintextPath,
					"-outform", "DER", "-out", cmsPath, "-aes256", "-aes256-wrap", certificatePath)
				cmsDER, err := os.ReadFile(cmsPath)
				if err != nil {
					t.Fatal(err)
				}
				p7, err := Parse(cmsDER)
				if err != nil {
					t.Fatal(err)
				}
				decrypted, err := p7.Decrypt(certificate, privateKey)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("Go decrypted %q, want %q", decrypted, plaintext)
				}
			})
		})
	}
}

func requireOpenSSLMLKEM(t *testing.T) {
	t.Helper()
	version := runOpenSSL(t, "version")
	algorithms := runOpenSSL(t, "list", "-kem-algorithms")
	if !strings.Contains(algorithms, "ML-KEM-768") || !strings.Contains(algorithms, "ML-KEM-1024") {
		t.Fatalf("%s does not provide ML-KEM-768 and ML-KEM-1024", strings.TrimSpace(version))
	}
}

func runOpenSSL(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command("openssl", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
