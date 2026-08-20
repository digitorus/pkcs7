package pkcs7

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestBouncyCastleMLKEMInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_BOUNCY_CASTLE_INTEROP") == "" {
		t.Skip("set PKCS7_BOUNCY_CASTLE_INTEROP to run Bouncy Castle interoperability tests")
	}
	classpath := os.Getenv("PKCS7_BOUNCY_CASTLE_CLASSPATH")
	if classpath == "" {
		t.Fatal("PKCS7_BOUNCY_CASTLE_CLASSPATH is required")
	}

	content := []byte("Bouncy Castle and Go agree on RFC 9629/9936 ML-KEM CMS")
	for _, test := range mlKEMInteropCases {
		t.Run(test.name, func(t *testing.T) {
			privateKey, seed, publicKey := newMLKEMInteropKey(t, test)
			certificate := newMLKEMInteropCertificate(t, test, publicKey)
			dir := t.TempDir()
			certificatePath := filepath.Join(dir, "recipient-certificate.der")
			privateKeyPath := filepath.Join(dir, "recipient-key.der")
			contentPath := filepath.Join(dir, "content.bin")
			writeTestFile(t, certificatePath, certificate.Raw)
			writeTestFile(t, privateKeyPath, marshalMLKEMInteropPrivateKey(t, test, seed))
			writeTestFile(t, contentPath, content)

			t.Run("Go_to_Bouncy_Castle", func(t *testing.T) {
				withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
				cmsDER, err := Encrypt(content, []*x509.Certificate{certificate})
				if err != nil {
					t.Fatal(err)
				}
				cmsPath := filepath.Join(dir, "go-enveloped.der")
				decryptedPath := filepath.Join(dir, "bouncycastle-decrypted.bin")
				writeTestFile(t, cmsPath, cmsDER)
				runBouncyCastleCommand(t, classpath, "decrypt", certificatePath, privateKeyPath,
					cmsPath, decryptedPath)
				decrypted, err := os.ReadFile(decryptedPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decrypted, content) {
					t.Fatalf("Bouncy Castle decrypted content %q, want %q", decrypted, content)
				}
			})

			t.Run("Bouncy_Castle_to_Go", func(t *testing.T) {
				cmsPath := filepath.Join(dir, "bouncycastle-enveloped.der")
				runBouncyCastleCommand(t, classpath, "encrypt", certificatePath, contentPath, cmsPath)
				cmsDER, err := os.ReadFile(cmsPath)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := Parse(cmsDER)
				if err != nil {
					t.Fatal(err)
				}
				assertMLKEMStructure(t, parsed, test)
				decrypted, err := parsed.Decrypt(certificate, privateKey)
				if err != nil {
					t.Fatalf("Go decryption failed: %v", err)
				}
				if !bytes.Equal(decrypted, content) {
					t.Fatalf("Go decrypted content %q, want %q", decrypted, content)
				}
			})
		})
	}
}

func assertMLKEMStructure(t *testing.T, parsed *PKCS7, test mlKEMInteropCase) {
	t.Helper()
	envelope, ok := parsed.raw.(envelopedData)
	if !ok {
		t.Fatalf("parsed CMS payload type = %T, want envelopedData", parsed.raw)
	}
	if envelope.Version != 3 {
		t.Errorf("EnvelopedData version = %d, want 3", envelope.Version)
	}
	if len(envelope.RecipientInfos) != 1 {
		t.Fatalf("recipient count = %d, want 1", len(envelope.RecipientInfos))
	}
	if !envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmAES256CBC) {
		t.Errorf("content encryption OID = %s, want %s",
			envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm, OIDEncryptionAlgorithmAES256CBC)
	}
	info := decodeKEMRecipientInfo(t, envelope.RecipientInfos[0])
	if !info.KEM.Algorithm.Equal(test.oid) || algorithmIdentifierHasParameters(info.KEM) {
		t.Errorf("KEM AlgorithmIdentifier = %+v, want parameterless %s", info.KEM, test.oid)
	}
	if len(info.Ciphertext) != test.ciphertext {
		t.Errorf("ML-KEM ciphertext length = %d, want %d", len(info.Ciphertext), test.ciphertext)
	}
	if !info.KDF.Algorithm.Equal(OIDKDFHKDFSHA256) || algorithmIdentifierHasParameters(info.KDF) {
		t.Errorf("KDF AlgorithmIdentifier = %+v, want parameterless %s", info.KDF, OIDKDFHKDFSHA256)
	}
	if !info.Wrap.Algorithm.Equal(OIDKeyWrapAES256) || algorithmIdentifierHasParameters(info.Wrap) {
		t.Errorf("wrap AlgorithmIdentifier = %+v, want parameterless %s", info.Wrap, OIDKeyWrapAES256)
	}
	if info.KEKLength != mlKEMKEKLength {
		t.Errorf("KEK length = %d, want %d", info.KEKLength, mlKEMKEKLength)
	}
}
