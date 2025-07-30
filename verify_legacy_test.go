//go:build legacy

package pkcs7

import (
	"crypto/x509"
	"testing"
)

func TestLegacySignWithOpenSSLAndVerify(t *testing.T) {
	testSign(t, []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
	})
}
