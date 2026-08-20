package pkcs7

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOpenSSLMLDSAInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_OPENSSL_INTEROP") == "" {
		t.Skip("set PKCS7_OPENSSL_INTEROP to run interoperability tests with openssl from PATH")
	}
	openSSLMajor := requireOpenSSLMLDSA(t)

	content := []byte("OpenSSL and Go agree on RFC 9882 ML-DSA CMS")
	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "signer-key.pem")
			goKeyPath := filepath.Join(dir, "signer-seed-key.pem")
			certificatePath := filepath.Join(dir, "signer-cert.pem")
			contentPath := filepath.Join(dir, "content.bin")
			if err := os.WriteFile(contentPath, content, 0o600); err != nil {
				t.Fatal(err)
			}
			runOpenSSLCommand(t, "req", "-new", "-x509", "-newkey", test.name, "-nodes",
				"-keyout", keyPath, "-out", certificatePath, "-subj", "/CN="+test.name+" CMS interop",
				"-days", "1")
			runOpenSSLCommand(t, "pkey", "-in", keyPath, "-out", goKeyPath,
				"-provparam", "ml-dsa.output_formats=seed-only")
			certificate := readOpenSSLCertificate(t, certificatePath)
			privateKey := readOpenSSLMLDSAPrivateKey(t, goKeyPath)

			goToOpenSSL(t, certificate, privateKey, content, contentPath, dir, openSSLMajor)
			openSSLToGo(t, test, certificatePath, keyPath, content, contentPath, dir, openSSLMajor)
		})
	}
}

func goToOpenSSL(t *testing.T, certificate *x509.Certificate, privateKey *mldsa.PrivateKey, content []byte, contentPath, dir string, openSSLMajor int) {
	t.Helper()
	tests := []struct {
		name        string
		detached    bool
		withoutAttr bool
	}{
		{embeddedContentTestName + "/signed_attributes", false, false},
		{detachedContentTestName + "/signed_attributes", true, false},
		{embeddedContentTestName + "/without_attributes", false, true},
		{detachedContentTestName + "/without_attributes", true, true},
	}

	for _, test := range tests {
		t.Run("Go_to_OpenSSL/"+test.name, func(t *testing.T) {
			if test.withoutAttr && openSSLMajor < 4 {
				t.Skip("OpenSSL before 4.0 does not support pure ML-DSA CMS signatures without signed attributes")
			}
			signedData, err := NewSignedData(content)
			if err != nil {
				t.Fatal(err)
			}
			if test.withoutAttr {
				err = signedData.SignWithoutAttr(certificate, privateKey, SignerInfoConfig{})
			} else {
				err = signedData.AddSigner(certificate, privateKey, SignerInfoConfig{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.detached {
				signedData.Detach()
			}
			cmsDER, err := signedData.Finish()
			if err != nil {
				t.Fatal(err)
			}
			cmsPath := filepath.Join(dir, "go-"+strings.ReplaceAll(test.name, "/", "-")+".der")
			outputPath := filepath.Join(dir, "openssl-"+strings.ReplaceAll(test.name, "/", "-")+".bin")
			if err := os.WriteFile(cmsPath, cmsDER, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"cms", "-verify", "-binary", "-inform", "DER", "-in", cmsPath, "-noverify", "-out", outputPath}
			if test.detached || test.withoutAttr {
				// OpenSSL 4.0.1's CMS verifier requires an explicit content BIO for
				// pure ML-DSA signatures, even when eContent is embedded.
				args = append(args, "-content", contentPath)
			}
			runOpenSSLCommand(t, args...)
			verified, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(verified, content) {
				t.Fatalf("OpenSSL verified content %q, want %q", verified, content)
			}
		})
	}
}

func openSSLToGo(t *testing.T, algorithm mlDSATestCase, certificatePath, keyPath string, content []byte, contentPath, dir string, openSSLMajor int) {
	t.Helper()
	tests := []struct {
		name        string
		detached    bool
		withoutAttr bool
	}{
		{detachedContentTestName + "/signed_attributes", true, false},
		{embeddedContentTestName + "/signed_attributes", false, false},
		{detachedContentTestName + "/without_attributes", true, true},
		{embeddedContentTestName + "/without_attributes", false, true},
	}

	for _, test := range tests {
		t.Run("OpenSSL_to_Go/"+test.name, func(t *testing.T) {
			if test.withoutAttr && openSSLMajor < 4 {
				t.Skip("OpenSSL before 4.0 does not support pure ML-DSA CMS signatures without signed attributes")
			}
			cmsPath := filepath.Join(dir, "openssl-"+strings.ReplaceAll(test.name, "/", "-")+".der")
			args := []string{
				"cms", "-sign", "-binary", "-md", "sha512", "-in", contentPath,
				"-signer", certificatePath, "-inkey", keyPath, "-outform", "DER", "-out", cmsPath,
			}
			if !test.detached {
				args = append(args, "-nodetach")
			}
			if test.withoutAttr {
				args = append(args, "-noattr")
			}
			runOpenSSLCommand(t, args...)

			cmsDER, err := os.ReadFile(cmsPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(cmsDER)
			if err != nil {
				t.Fatal(err)
			}
			if test.detached {
				parsed.Content = content
			}
			assertMLDSAStructure(t, parsed, algorithm, !test.withoutAttr)
			if err := parsed.Verify(); err != nil {
				t.Fatalf("Go verification failed: %v", err)
			}
		})
	}
}

func requireOpenSSLMLDSA(t *testing.T) int {
	t.Helper()
	version := runOpenSSLCommand(t, "version")
	algorithms := runOpenSSLCommand(t, "list", "-signature-algorithms")
	for _, algorithm := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if !strings.Contains(algorithms, algorithm) {
			t.Fatalf("%s does not provide %s", strings.TrimSpace(version), algorithm)
		}
	}
	fields := strings.Fields(version)
	if len(fields) < 2 {
		t.Fatalf("unexpected openssl version output %q", strings.TrimSpace(version))
	}
	majorText, _, _ := strings.Cut(fields[1], ".")
	major, err := strconv.Atoi(majorText)
	if err != nil {
		t.Fatalf("parse openssl version %q: %v", fields[1], err)
	}
	return major
}

func readOpenSSLCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	block := readOpenSSLPEMBlock(t, path, "CERTIFICATE")
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func readOpenSSLMLDSAPrivateKey(t *testing.T, path string) *mldsa.PrivateKey {
	t.Helper()
	block := readOpenSSLPEMBlock(t, path, "PRIVATE KEY")
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	mldsaKey, ok := privateKey.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("OpenSSL private key type = %T, want *mldsa.PrivateKey", privateKey)
	}
	return mldsaKey
}

func readOpenSSLPEMBlock(t *testing.T, path, blockType string) *pem.Block {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != blockType {
		t.Fatalf("%s does not contain a %s block", path, blockType)
	}
	return block
}

func runOpenSSLCommand(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command("openssl", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
