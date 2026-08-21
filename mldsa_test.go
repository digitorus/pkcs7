package pkcs7

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

type mlDSATestCase struct {
	name               string
	parameters         mldsa.Parameters
	signatureAlgorithm x509.SignatureAlgorithm
	signatureOID       asn1.ObjectIdentifier
}

var mlDSATestCases = []mlDSATestCase{
	{"ML-DSA-44", mldsa.MLDSA44(), x509.MLDSA44, OIDSignatureAlgorithmMLDSA44},
	{"ML-DSA-65", mldsa.MLDSA65(), x509.MLDSA65, OIDSignatureAlgorithmMLDSA65},
	{"ML-DSA-87", mldsa.MLDSA87(), x509.MLDSA87, OIDSignatureAlgorithmMLDSA87},
}

const (
	embeddedContentTestName = "embedded"
	detachedContentTestName = "detached"
)

func TestMLDSASignAndVerify(t *testing.T) {
	content := []byte("CMS ML-DSA pure-mode test content")

	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			certificate, privateKey := createMLDSATestCertificate(t, test)
			roots := x509.NewCertPool()
			roots.AddCert(certificate)

			for _, withSignedAttributes := range []bool{true, false} {
				attributeName := "signed-attributes"
				if !withSignedAttributes {
					attributeName = "without-signed-attributes"
				}
				for _, detached := range []bool{false, true} {
					contentName := embeddedContentTestName
					if detached {
						contentName = detachedContentTestName
					}
					t.Run(attributeName+"/"+contentName, func(t *testing.T) {
						signedData, err := NewSignedData(content)
						if err != nil {
							t.Fatal(err)
						}

						// ML-DSA must override incompatible caller-selected algorithms.
						signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA1)
						signedData.SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSA)
						if withSignedAttributes {
							err = signedData.AddSigner(certificate, privateKey, SignerInfoConfig{})
						} else {
							err = signedData.SignWithoutAttr(certificate, privateKey, SignerInfoConfig{})
						}
						if err != nil {
							t.Fatalf("signing failed: %v", err)
						}
						if detached {
							signedData.Detach()
						}

						der, err := signedData.Finish()
						if err != nil {
							t.Fatal(err)
						}
						parsed, err := Parse(der)
						if err != nil {
							t.Fatal(err)
						}
						if detached {
							if len(parsed.Content) != 0 {
								t.Fatalf("detached CMS contains %d content bytes", len(parsed.Content))
							}
							parsed.Content = content
						} else if !bytes.Equal(parsed.Content, content) {
							t.Fatalf("embedded content = %q, want %q", parsed.Content, content)
						}

						assertMLDSAStructure(t, parsed, test, withSignedAttributes)
						if err := parsed.VerifyWithChain(roots); err != nil {
							t.Fatalf("verification failed: %v", err)
						}
						assertPureMLDSASignature(t, parsed, privateKey.PublicKey(), content)
					})
				}
			}
		})
	}
}

func TestMLDSASkipSigningTime(t *testing.T) {
	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			certificate, privateKey := createMLDSATestCertificate(t, test)
			signedData, err := NewSignedData([]byte("CMS ML-DSA without signing-time"))
			if err != nil {
				t.Fatal(err)
			}
			if err := signedData.AddSigner(certificate, privateKey, SignerInfoConfig{SkipSigningTime: true}); err != nil {
				t.Fatal(err)
			}
			der, err := signedData.Finish()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if n := countSigningTimeAttributes(parsed); n != 0 {
				t.Fatalf("signing-time attribute count = %d, want 0", n)
			}
			if err := parsed.Verify(); err != nil {
				t.Fatalf("verification failed: %v", err)
			}
		})
	}
}

func TestMLDSARejectsSignatureAlgorithmParameters(t *testing.T) {
	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			certificate, privateKey := createMLDSATestCertificate(t, test)
			signedData, err := NewSignedData([]byte("malformed AlgorithmIdentifier"))
			if err != nil {
				t.Fatal(err)
			}
			if err := signedData.AddSigner(certificate, privateKey, SignerInfoConfig{}); err != nil {
				t.Fatal(err)
			}
			signedData.sd.SignerInfos[0].DigestEncryptionAlgorithm.Parameters = asn1.NullRawValue

			der, err := signedData.Finish()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			err = parsed.Verify()
			if err == nil || !strings.Contains(err.Error(), "ML-DSA AlgorithmIdentifier parameters must be absent") {
				t.Fatalf("Verify() error = %v, want absent-parameters error", err)
			}
		})
	}
}

func TestGetDigestOIDForMLDSA(t *testing.T) {
	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			digestOID, err := GetDigestOIDForSignatureAlgorithm(test.signatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			if !digestOID.Equal(OIDDigestAlgorithmSHA512) {
				t.Fatalf("digest OID = %s, want %s", digestOID, OIDDigestAlgorithmSHA512)
			}
		})
	}
}

func createMLDSATestCertificate(t *testing.T, test mlDSATestCase) (*x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	privateKey, err := mldsa.GenerateKey(test.parameters)
	if err != nil {
		t.Fatalf("generate %s key: %v", test.name, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: test.name + " CMS test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    test.signatureAlgorithm,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.PublicKey(), privateKey)
	if err != nil {
		t.Fatalf("create %s certificate: %v", test.name, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s certificate: %v", test.name, err)
	}
	return certificate, privateKey
}

func assertMLDSAStructure(t *testing.T, parsed *PKCS7, test mlDSATestCase, withSignedAttributes bool) {
	t.Helper()
	if len(parsed.Signers) != 1 {
		t.Fatalf("signer count = %d, want 1", len(parsed.Signers))
	}
	signer := parsed.Signers[0]
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(test.signatureOID) {
		t.Errorf("signature OID = %s, want %s", signer.DigestEncryptionAlgorithm.Algorithm, test.signatureOID)
	}
	if len(signer.DigestEncryptionAlgorithm.Parameters.FullBytes) != 0 {
		t.Errorf("ML-DSA signature AlgorithmIdentifier parameters are present: %x", signer.DigestEncryptionAlgorithm.Parameters.FullBytes)
	}
	if !signer.DigestAlgorithm.Algorithm.Equal(OIDDigestAlgorithmSHA512) {
		t.Errorf("digest OID = %s, want %s", signer.DigestAlgorithm.Algorithm, OIDDigestAlgorithmSHA512)
	}
	if len(signer.DigestAlgorithm.Parameters.FullBytes) != 0 {
		t.Errorf("SHA-512 AlgorithmIdentifier parameters are present: %x", signer.DigestAlgorithm.Parameters.FullBytes)
	}
	if withSignedAttributes != (len(signer.AuthenticatedAttributes) > 0) {
		t.Errorf("signed attributes present = %t, want %t", len(signer.AuthenticatedAttributes) > 0, withSignedAttributes)
	}

	rawSignedData := parsed.raw.(signedData)
	if len(rawSignedData.DigestAlgorithmIdentifiers) != 1 {
		t.Fatalf("SignedData digest algorithm count = %d, want 1", len(rawSignedData.DigestAlgorithmIdentifiers))
	}
	digestAlgorithm := rawSignedData.DigestAlgorithmIdentifiers[0]
	if !digestAlgorithm.Algorithm.Equal(OIDDigestAlgorithmSHA512) || len(digestAlgorithm.Parameters.FullBytes) != 0 {
		t.Errorf("SignedData digest AlgorithmIdentifier = %+v, want SHA-512 with absent parameters", digestAlgorithm)
	}

	if withSignedAttributes {
		var messageDigest []byte
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &messageDigest); err != nil {
			t.Fatal(err)
		}
		expectedDigest := sha512.Sum512(parsed.Content)
		if !bytes.Equal(messageDigest, expectedDigest[:]) {
			t.Errorf("message-digest attribute = %x, want %x", messageDigest, expectedDigest)
		}
	}
}

func assertPureMLDSASignature(t *testing.T, parsed *PKCS7, publicKey *mldsa.PublicKey, content []byte) {
	t.Helper()
	signer := parsed.Signers[0]
	signed := content
	if len(signer.AuthenticatedAttributes) > 0 {
		var err error
		signed, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := mldsa.Verify(publicKey, signed, signer.EncryptedDigest, &mldsa.Options{}); err != nil {
		t.Fatalf("pure-mode verification failed: %v", err)
	}
	preHash := sha512.Sum512(signed)
	if err := mldsa.Verify(publicKey, preHash[:], signer.EncryptedDigest, &mldsa.Options{}); err == nil {
		t.Fatal("signature unexpectedly verified over a SHA-512 digest instead of the CMS signed bytes")
	}
}
