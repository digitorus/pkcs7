//go:build legacy

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"testing"
)

func TestLegacySign(t *testing.T) {
	testLegacySign(t, []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
	}, true)
}

func TestLegacySignWithoutAttributes(t *testing.T) {
	testLegacySign(t, []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
	}, false)
}

func testLegacySign(t *testing.T, signatureAlgorithms []x509.SignatureAlgorithm, withSignedAttributes bool) {
	t.Helper()
	content := []byte("legacy SHA-1 CMS signature")
	for _, signatureAlgorithm := range signatureAlgorithms {
		t.Run(signatureAlgorithm.String(), func(t *testing.T) {
			certificate, err := createTestCertificate(signatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			digestOID, err := GetDigestOIDForSignatureAlgorithm(signatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			for _, detached := range []bool{false, true} {
				signedData, err := NewSignedData(content)
				if err != nil {
					t.Fatal(err)
				}
				signedData.SetDigestAlgorithm(digestOID)
				privateKey := (*certificate.PrivateKey).(crypto.Signer)
				if withSignedAttributes {
					err = signedData.AddSigner(certificate.Certificate, privateKey, SignerInfoConfig{})
				} else {
					err = signedData.SignWithoutAttr(certificate.Certificate, privateKey, SignerInfoConfig{})
				}
				if err != nil {
					t.Fatal(err)
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
					parsed.Content = content
				}
				if !bytes.Equal(parsed.Content, content) {
					t.Fatalf("content = %q, want %q", parsed.Content, content)
				}
				// Go 1.27 no longer permits SHA-1 certificate-chain validation,
				// but low-level CMS signature verification remains supported.
				if err := parsed.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
