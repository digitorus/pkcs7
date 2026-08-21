package pkcs7

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type mlKEMInteropCase struct {
	name       string
	oid        asn1.ObjectIdentifier
	newKey     func([]byte) (any, []byte, error)
	seedOffset byte
	ciphertext int
}

var mlKEMInteropCases = []mlKEMInteropCase{
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
		ciphertext: 1088,
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
		ciphertext: 1568,
	},
}

func newMLKEMInteropKey(t *testing.T, test mlKEMInteropCase) (any, []byte, []byte) {
	t.Helper()
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i) + test.seedOffset
	}
	privateKey, publicKey, err := test.newKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, seed, publicKey
}

func newMLKEMInteropCertificate(t *testing.T, test mlKEMInteropCase, publicKey []byte) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(test.seedOffset) + 1),
		Subject:      pkix.Name{CommonName: test.name + " CMS interop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		SubjectKeyId: []byte(test.name + "-interop-key-id"),
	}
	classicalDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &test2048Key.PublicKey, test2048Key)
	if err != nil {
		t.Fatal(err)
	}
	certificateDER := replaceCertificateSPKI(
		t, classicalDER, marshalMLKEMSPKI(t, test.oid, publicKey, false))
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func writeMLKEMInteropKeys(t *testing.T, test mlKEMInteropCase, seed, publicKey []byte, privateKeyPath, publicKeyPath string) {
	t.Helper()
	privateDER := marshalMLKEMInteropPrivateKey(t, test, seed)
	publicDER := marshalMLKEMSPKI(t, test.oid, publicKey, false)
	writeTestFile(t, privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	writeTestFile(t, publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
}

func marshalMLKEMInteropPrivateKey(t *testing.T, test mlKEMInteropCase, seed []byte) []byte {
	t.Helper()
	type privateKeyInfo struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	seedChoice := append([]byte{0x80, 0x40}, seed...)
	privateDER, err := asn1.Marshal(privateKeyInfo{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: test.oid},
		PrivateKey: seedChoice,
	})
	if err != nil {
		t.Fatal(err)
	}
	return privateDER
}
