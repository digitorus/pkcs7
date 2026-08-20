package pkcs7

import (
	"bytes"
	"crypto/mlkem"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

	tests := []struct {
		name       string
		oid        asn1.ObjectIdentifier
		newKey     func([]byte) (any, []byte, error)
		seedOffset byte
	}{
		{
			name: "ML-KEM-768",
			oid:  OIDKeyAlgorithmMLKEM768,
			newKey: func(seed []byte) (any, []byte, error) {
				key, err := mlkem.NewDecapsulationKey768(seed)
				if err != nil {
					return nil, nil, err
				}
				return key, key.EncapsulationKey().Bytes(), nil
			},
			seedOffset: 0,
		},
		{
			name: "ML-KEM-1024",
			oid:  OIDKeyAlgorithmMLKEM1024,
			newKey: func(seed []byte) (any, []byte, error) {
				key, err := mlkem.NewDecapsulationKey1024(seed)
				if err != nil {
					return nil, nil, err
				}
				return key, key.EncapsulationKey().Bytes(), nil
			},
			seedOffset: 64,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := make([]byte, 64)
			for i := range seed {
				seed[i] = byte(i) + test.seedOffset
			}
			privateKey, publicKey, err := test.newKey(seed)
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			privateKeyPath := filepath.Join(dir, "recipient-key.pem")
			publicKeyPath := filepath.Join(dir, "recipient-public.pem")
			certificatePath := filepath.Join(dir, "recipient-cert.pem")
			writeOpenSSLMLKEMKeys(t, test.oid, seed, publicKey, privateKeyPath, publicKeyPath)
			issueOpenSSLMLKEMCertificate(t, publicKeyPath, certificatePath, dir)
			certificate := readPEMCertificate(t, certificatePath)

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

func writeOpenSSLMLKEMKeys(t *testing.T, oid asn1.ObjectIdentifier, seed, publicKey []byte, privateKeyPath, publicKeyPath string) {
	t.Helper()
	type privateKeyInfo struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	seedChoice := append([]byte{0x80, 0x40}, seed...)
	privateDER, err := asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: seedChoice,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func issueOpenSSLMLKEMCertificate(t *testing.T, publicKeyPath, certificatePath, dir string) {
	t.Helper()
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	caCertificatePath := filepath.Join(dir, "ca-cert.pem")
	extensionsPath := filepath.Join(dir, "extensions.cnf")
	extensions := []byte("basicConstraints = critical, CA:false\nkeyUsage = critical, keyEncipherment\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n")
	if err := os.WriteFile(extensionsPath, extensions, 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", caKeyPath, "-out", caCertificatePath, "-subj", "/CN=pkcs7 ML-KEM test CA",
		"-days", "1", "-sha256")
	runOpenSSL(t, "x509", "-new", "-force_pubkey", publicKeyPath,
		"-subj", "/CN=pkcs7 ML-KEM recipient", "-CA", caCertificatePath, "-CAkey", caKeyPath,
		"-set_serial", "1", "-days", "1", "-extfile", extensionsPath, "-out", certificatePath)
}

func readPEMCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s does not contain a certificate", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
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
