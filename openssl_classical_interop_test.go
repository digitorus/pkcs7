package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	ed25519InteropName = "Ed25519"
	openSSLBinaryArg   = "-binary"
	openSSLCMSCommand  = "cms"
	openSSLDERFormat   = "DER"
	openSSLInArg       = "-in"
	openSSLOutArg      = "-out"
)

type classicalInteropAlgorithm struct {
	name                           string
	openSSLKeyArgs                 []string
	digestName                     string
	digestOID                      asn1.ObjectIdentifier
	signatureOID                   asn1.ObjectIdentifier
	certificateSignatureAlgorithm  x509.SignatureAlgorithm
	bouncyCastleKeyAlgorithm       string
	bouncyCastleSignatureAlgorithm string
	bouncyCastleSignatureOID       asn1.ObjectIdentifier
	requiresMessageAPI             bool
}

var classicalInteropAlgorithms = []classicalInteropAlgorithm{
	{
		name:                           "RSA",
		openSSLKeyArgs:                 []string{"rsa:2048"},
		digestName:                     "sha256",
		digestOID:                      OIDDigestAlgorithmSHA256,
		signatureOID:                   OIDEncryptionAlgorithmRSA,
		certificateSignatureAlgorithm:  x509.SHA256WithRSA,
		bouncyCastleKeyAlgorithm:       "RSA",
		bouncyCastleSignatureAlgorithm: "SHA256withRSA",
		bouncyCastleSignatureOID:       OIDEncryptionAlgorithmRSASHA256,
	},
	{
		name:                           "ECDSA",
		openSSLKeyArgs:                 []string{"ec", "-pkeyopt", "ec_paramgen_curve:P-256"},
		digestName:                     "sha256",
		digestOID:                      OIDDigestAlgorithmSHA256,
		signatureOID:                   OIDDigestAlgorithmECDSASHA256,
		certificateSignatureAlgorithm:  x509.ECDSAWithSHA256,
		bouncyCastleKeyAlgorithm:       "EC",
		bouncyCastleSignatureAlgorithm: "SHA256withECDSA",
		bouncyCastleSignatureOID:       OIDDigestAlgorithmECDSASHA256,
	},
	{
		name:                           ed25519InteropName,
		openSSLKeyArgs:                 []string{"ED25519"},
		digestName:                     "sha512",
		digestOID:                      OIDDigestAlgorithmSHA512,
		signatureOID:                   OIDEncryptionAlgorithmEDDSA25519,
		certificateSignatureAlgorithm:  x509.PureEd25519,
		bouncyCastleKeyAlgorithm:       ed25519InteropName,
		bouncyCastleSignatureAlgorithm: ed25519InteropName,
		bouncyCastleSignatureOID:       OIDEncryptionAlgorithmEDDSA25519,
		requiresMessageAPI:             true,
	},
}

func TestOpenSSLClassicalInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_OPENSSL_INTEROP") == "" {
		t.Skip("set PKCS7_OPENSSL_INTEROP to run interoperability tests with openssl from PATH")
	}
	openSSLMajor := openSSLMajorVersion(t)
	content := []byte("OpenSSL and Go agree on classical CMS signatures")

	for _, algorithm := range classicalInteropAlgorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "signer-key.pem")
			keyDERPath := filepath.Join(dir, "signer-key.der")
			certificatePath := filepath.Join(dir, "signer-cert.pem")
			contentPath := filepath.Join(dir, "content.bin")
			writeTestFile(t, contentPath, content)

			args := append([]string{"req", "-new", "-x509", "-newkey"}, algorithm.openSSLKeyArgs...)
			args = append(args, "-nodes", "-keyout", keyPath, "-out", certificatePath,
				"-subj", "/CN="+algorithm.name+" CMS interop", "-days", "1")
			runOpenSSLCommand(t, args...)
			runOpenSSLCommand(t, "pkcs8", "-topk8", "-nocrypt", "-in", keyPath,
				"-outform", "DER", "-out", keyDERPath)
			certificate := readOpenSSLCertificate(t, certificatePath)
			privateKey := readOpenSSLPrivateKey(t, keyDERPath)

			for _, detached := range []bool{false, true} {
				for _, direct := range []bool{false, true} {
					name := interopCaseName(detached, direct)
					if direct && algorithm.requiresMessageAPI && openSSLMajor < 4 {
						t.Run("Go_to_OpenSSL/"+name, func(t *testing.T) {
							t.Skip("OpenSSL before 4.0 does not support direct Ed25519 CMS signatures")
						})
						t.Run("OpenSSL_to_Go/"+name, func(t *testing.T) {
							t.Skip("OpenSSL before 4.0 does not support direct Ed25519 CMS signatures")
						})
						continue
					}

					t.Run("Go_to_OpenSSL/"+name, func(t *testing.T) {
						signedData, err := NewSignedData(content)
						if err != nil {
							t.Fatal(err)
						}
						signedData.SetDigestAlgorithm(algorithm.digestOID)
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
						outputPath := filepath.Join(dir, "openssl-"+strings.ReplaceAll(name, "/", "-")+".bin")
						writeTestFile(t, cmsPath, cmsDER)
						verifyArgs := []string{
							openSSLCMSCommand, "-verify", openSSLBinaryArg, "-inform", openSSLDERFormat, openSSLInArg, cmsPath,
							"-noverify", openSSLOutArg, outputPath,
						}
						if detached || (direct && algorithm.requiresMessageAPI) {
							verifyArgs = append(verifyArgs, "-content", contentPath)
						}
						runOpenSSLCommand(t, verifyArgs...)
						verified, err := os.ReadFile(outputPath)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(verified, content) {
							t.Fatalf("OpenSSL verified content %q, want %q", verified, content)
						}
					})

					t.Run("OpenSSL_to_Go/"+name, func(t *testing.T) {
						cmsPath := filepath.Join(dir, "openssl-"+strings.ReplaceAll(name, "/", "-")+".der")
						signArgs := []string{
							openSSLCMSCommand, "-sign", openSSLBinaryArg, "-md", algorithm.digestName,
							openSSLInArg, contentPath, "-signer", certificatePath, "-inkey", keyPath,
							"-outform", openSSLDERFormat, openSSLOutArg, cmsPath,
						}
						if !detached {
							signArgs = append(signArgs, "-nodetach")
						}
						if direct {
							signArgs = append(signArgs, "-noattr")
						}
						runOpenSSLCommand(t, signArgs...)
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
						assertClassicalStructure(t, parsed, algorithm.digestOID, algorithm.signatureOID, !direct)
						if err := parsed.Verify(); err != nil {
							t.Fatalf("Go verification failed: %v", err)
						}
					})
				}
			}
		})
	}
}

func TestOpenSSLEnvelopedDataInteroperability(t *testing.T) {
	if os.Getenv("PKCS7_OPENSSL_INTEROP") == "" {
		t.Skip("set PKCS7_OPENSSL_INTEROP to run interoperability tests with openssl from PATH")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "recipient-key.pem")
	keyDERPath := filepath.Join(dir, "recipient-key.der")
	certificatePath := filepath.Join(dir, "recipient-cert.pem")
	contentPath := filepath.Join(dir, "content.bin")
	content := []byte("OpenSSL and Go agree on RSA key transport CMS EnvelopedData")
	writeTestFile(t, contentPath, content)
	runOpenSSLCommand(t, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certificatePath, "-subj", "/CN=CMS EnvelopedData interop", "-days", "1")
	runOpenSSLCommand(t, "pkcs8", "-topk8", "-nocrypt", "-in", keyPath,
		"-outform", "DER", "-out", keyDERPath)
	certificate := readOpenSSLCertificate(t, certificatePath)
	privateKey := readOpenSSLPrivateKey(t, keyDERPath)

	algorithms := []struct {
		name       string
		goValue    int
		openSSLArg string
		oid        asn1.ObjectIdentifier
	}{
		{"AES-128-CBC", EncryptionAlgorithmAES128CBC, "-aes-128-cbc", OIDEncryptionAlgorithmAES128CBC},
		{"AES-256-CBC", EncryptionAlgorithmAES256CBC, "-aes-256-cbc", OIDEncryptionAlgorithmAES256CBC},
	}
	previousAlgorithm := ContentEncryptionAlgorithm
	t.Cleanup(func() { ContentEncryptionAlgorithm = previousAlgorithm })

	for _, algorithm := range algorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			ContentEncryptionAlgorithm = algorithm.goValue

			t.Run("Go_to_OpenSSL", func(t *testing.T) {
				cmsDER, err := Encrypt(content, []*x509.Certificate{certificate})
				if err != nil {
					t.Fatal(err)
				}
				cmsPath := filepath.Join(dir, "go-"+algorithm.name+".der")
				outputPath := filepath.Join(dir, "openssl-"+algorithm.name+".bin")
				writeTestFile(t, cmsPath, cmsDER)
				runOpenSSLCommand(t, openSSLCMSCommand, "-decrypt", openSSLBinaryArg, "-inform", openSSLDERFormat, openSSLInArg, cmsPath,
					"-recip", certificatePath, "-inkey", keyPath, openSSLOutArg, outputPath)
				decrypted, err := os.ReadFile(outputPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decrypted, content) {
					t.Fatalf("OpenSSL decrypted content %q, want %q", decrypted, content)
				}
			})

			t.Run("OpenSSL_to_Go", func(t *testing.T) {
				cmsPath := filepath.Join(dir, "openssl-"+algorithm.name+".der")
				runOpenSSLCommand(t, openSSLCMSCommand, "-encrypt", openSSLBinaryArg, algorithm.openSSLArg,
					openSSLInArg, contentPath, "-outform", openSSLDERFormat, openSSLOutArg, cmsPath, certificatePath)
				cmsDER, err := os.ReadFile(cmsPath)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := Parse(cmsDER)
				if err != nil {
					t.Fatal(err)
				}
				assertEnvelopedDataStructure(t, parsed, algorithm.oid)
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

func readOpenSSLPrivateKey(t *testing.T, path string) crypto.Signer {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(contents)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("OpenSSL private key type = %T, want crypto.Signer", privateKey)
	}
	return signer
}

func assertClassicalStructure(t *testing.T, parsed *PKCS7, digestOID, signatureOID asn1.ObjectIdentifier, withSignedAttributes bool) {
	t.Helper()
	if len(parsed.Signers) != 1 {
		t.Fatalf("signer count = %d, want 1", len(parsed.Signers))
	}
	signer := parsed.Signers[0]
	if !signer.DigestAlgorithm.Algorithm.Equal(digestOID) {
		t.Errorf("digest OID = %s, want %s", signer.DigestAlgorithm.Algorithm, digestOID)
	}
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(signatureOID) {
		t.Errorf("signature OID = %s, want %s", signer.DigestEncryptionAlgorithm.Algorithm, signatureOID)
	}
	if got := len(signer.AuthenticatedAttributes) > 0; got != withSignedAttributes {
		t.Errorf("signed attributes present = %t, want %t", got, withSignedAttributes)
	}
}

func assertEnvelopedDataStructure(t *testing.T, parsed *PKCS7, contentEncryptionOID asn1.ObjectIdentifier) {
	t.Helper()
	envelope, ok := parsed.raw.(envelopedData)
	if !ok {
		t.Fatalf("parsed CMS payload type = %T, want envelopedData", parsed.raw)
	}
	if len(envelope.RecipientInfos) != 1 {
		t.Fatalf("recipient count = %d, want 1", len(envelope.RecipientInfos))
	}
	if !envelope.RecipientInfos[0].KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSA) {
		t.Errorf("key encryption OID = %s, want %s",
			envelope.RecipientInfos[0].KeyEncryptionAlgorithm.Algorithm, OIDEncryptionAlgorithmRSA)
	}
	if !envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(contentEncryptionOID) {
		t.Errorf("content encryption OID = %s, want %s",
			envelope.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm, contentEncryptionOID)
	}
}

func openSSLMajorVersion(t *testing.T) int {
	t.Helper()
	version := runOpenSSLCommand(t, "version")
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
