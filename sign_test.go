package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	testSign(t, []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.PureEd25519,
	})
}

func testSign(t *testing.T, sigalgs []x509.SignatureAlgorithm) {
	content := []byte("Hello World")
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			parents := []*x509.Certificate{interCert.Certificate}
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}

					// Set the digest to match the end entity cert
					signerDigest, _ := GetDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
					toBeSigned.SetDigestAlgorithm(signerDigest)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						p7.Content = content
					}
					if !bytes.Equal(content, p7.Content) {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
							sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
					}
				}
			}
		}
	}
}

func TestDSASignAndVerifyWithOpenSSL(t *testing.T) {
	content := []byte("Hello World")
	// write the content to a temp file
	tmpContentFile, err := os.CreateTemp("", "TestDSASignAndVerifyWithOpenSSL_content")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpContentFile.Name(), content, 0o755); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(dsaPublicCert)
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}

	// write the signer cert to a temp file
	tmpSignerCertFile, err := os.CreateTemp("", "TestDSASignAndVerifyWithOpenSSL_signer")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpSignerCertFile.Name(), dsaPublicCert, 0o755); err != nil {
		t.Fatal(err)
	}

	priv := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: fromHex("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7"),
				Q: fromHex("9760508F15230BCCB292B982A2EB840BF0581CF5"),
				G: fromHex("F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A"),
			},
		},
		X: fromHex("7D6E1A3DD4019FD809669D8AB8DA73807CEF7EC1"),
	}
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("test case: cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.SignWithoutAttr(signerCert, &priv, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.Detach()
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("test case: cannot finish signing data: %s", err)
	}

	// write the signature to a temp file
	tmpSignatureFile, err := os.CreateTemp("", "TestDSASignAndVerifyWithOpenSSL_signature")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpSignatureFile.Name(), pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS7, Bytes: signed}), 0o755); err != nil {
		t.Fatal(err)
	}

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify", "-noverify",
		"-in", tmpSignatureFile.Name(), "-inform", "PEM",
		"-content", tmpContentFile.Name())
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("test case: openssl command failed with %s: %s", err, out)
	}
	os.Remove(tmpSignatureFile.Name())  // clean up
	os.Remove(tmpContentFile.Name())    // clean up
	os.Remove(tmpSignerCertFile.Name()) // clean up
}

func TestSignWithoutAttributes(t *testing.T) {
	testSignWithoutAttributes(t, []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.PureEd25519,
	})
}

func testSignWithoutAttributes(t *testing.T, sigalgs []x509.SignatureAlgorithm) {
	content := []byte("Hello World")

	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalgsigner := range sigalgs {
			signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", rootCert, sigalgsigner, false)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate signer cert: %s", sigalgroot, sigalgsigner, err)
			}
			for _, testDetach := range []bool{false, true} {
				toBeSigned, err := NewSignedData(content)
				if err != nil {
					t.Fatalf("test %s/%s: cannot initialize signed data: %s", sigalgroot, sigalgsigner, err)
				}

				// Set the digest to match the end entity cert
				signerDigest, _ := GetDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
				toBeSigned.SetDigestAlgorithm(signerDigest)

				if err := toBeSigned.SignWithoutAttr(signerCert.Certificate, (*signerCert.PrivateKey).(crypto.Signer), SignerInfoConfig{}); err != nil {
					t.Fatalf("test %s/%s: cannot add signer: %s", sigalgroot, sigalgsigner, err)
				}
				if testDetach {
					toBeSigned.Detach()
				}
				signed, err := toBeSigned.Finish()
				if err != nil {
					t.Fatalf("test %s/%s: cannot finish signing data: %s", sigalgroot, sigalgsigner, err)
				}
				p7, err := Parse(signed)
				if err != nil {
					t.Fatalf("test %s/%s: cannot parse signed data: %s", sigalgroot, sigalgsigner, err)
				}
				if testDetach {
					p7.Content = content
				}
				if !bytes.Equal(content, p7.Content) {
					t.Errorf("test %s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalgsigner, content, p7.Content)
				}
				if err := p7.VerifyWithChain(truststore); err != nil {
					t.Errorf("test %s/%s: cannot verify signed data: %s", sigalgroot, sigalgsigner, err)
				}
				if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
					t.Errorf("test %s/%s: expected digest algorithm %q but got %q",
						sigalgroot, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
				}
			}
		}
	}
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	_, err = signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
}

func TestSetContentType(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("Cannot create test certificates: %s", err)
	}

	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	idctTSTInfo := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	signedData.SetContentType(idctTSTInfo)

	if err := signedData.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}

	_, err = signedData.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}

	sd := signedData.GetSignedData()
	if !sd.ContentInfo.ContentType.Equal(idctTSTInfo) {
		t.Fatalf("Unexpected content type: %s", err)
	}
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
}

func TestSkipCertificates(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		SkipCertificates: true,
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	if len(p7.Certificates) > 0 {
		t.Fatalf("Got %d certificate(s), exected none", len(p7.Certificates))
	}
}

func signAndParseWithConfig(t *testing.T, config SignerInfoConfig) *PKCS7 {
	t.Helper()
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned, err := NewSignedData([]byte("Hello World"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, config); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("Cannot verify signed data: %s", err)
	}
	return p7
}

func countSigningTimeAttributes(p7 *PKCS7) int {
	count := 0
	for _, attr := range p7.Signers[0].AuthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeSigningTime) {
			count++
		}
	}
	return count
}

func TestSkipSigningTime(t *testing.T) {
	p7 := signAndParseWithConfig(t, SignerInfoConfig{
		SkipSigningTime: true,
	})
	if n := countSigningTimeAttributes(p7); n != 0 {
		t.Fatalf("Got %d signing-time signed attribute(s), expected none", n)
	}
}

func TestSkipSigningTimeFiltersExtraSignedAttributes(t *testing.T) {
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	const testValue = "preserved"
	p7 := signAndParseWithConfig(t, SignerInfoConfig{
		SkipSigningTime: true,
		ExtraSignedAttributes: []Attribute{
			{Type: OIDAttributeSigningTime, Value: time.Now().UTC()},
			{Type: oidTest, Value: testValue},
		},
	})
	if n := countSigningTimeAttributes(p7); n != 0 {
		t.Fatalf("Got %d signing-time signed attribute(s), expected none", n)
	}
	var actual string
	if err := p7.UnmarshalSignedAttribute(oidTest, &actual); err != nil {
		t.Fatalf("Cannot unmarshal preserved signed attribute: %s", err)
	}
	if actual != testValue {
		t.Fatalf("Got preserved signed attribute %q, expected %q", actual, testValue)
	}
}

func TestDefaultSigningTimeIsPreserved(t *testing.T) {
	p7 := signAndParseWithConfig(t, SignerInfoConfig{})
	if n := countSigningTimeAttributes(p7); n != 1 {
		t.Fatalf("Got %d signing-time signed attribute(s), expected exactly one", n)
	}
}

func TestExplicitSigningTimeReplacesDefault(t *testing.T) {
	explicitSigningTime := time.Now().UTC().Truncate(time.Second)
	p7 := signAndParseWithConfig(t, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{Type: OIDAttributeSigningTime, Value: explicitSigningTime},
		},
	})
	if n := countSigningTimeAttributes(p7); n != 1 {
		t.Fatalf("Got %d signing-time signed attribute(s), expected exactly one", n)
	}
	var signingTime time.Time
	if err := p7.UnmarshalSignedAttribute(OIDAttributeSigningTime, &signingTime); err != nil {
		t.Fatalf("Cannot unmarshal signing-time attribute: %s", err)
	}
	if !signingTime.Equal(explicitSigningTime) {
		t.Fatalf("Got signing time %s, expected %s", signingTime, explicitSigningTime)
	}
}

func TestMultipleExplicitSigningTimesUseFirst(t *testing.T) {
	firstSigningTime := time.Now().UTC().Truncate(time.Second)
	p7 := signAndParseWithConfig(t, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{Type: OIDAttributeSigningTime, Value: firstSigningTime},
			{Type: OIDAttributeSigningTime, Value: firstSigningTime.Add(time.Hour)},
		},
	})
	if n := countSigningTimeAttributes(p7); n != 1 {
		t.Fatalf("Got %d signing-time signed attribute(s), expected exactly one", n)
	}
	var signingTime time.Time
	if err := p7.UnmarshalSignedAttribute(OIDAttributeSigningTime, &signingTime); err != nil {
		t.Fatalf("Cannot unmarshal signing-time attribute: %s", err)
	}
	if !signingTime.Equal(firstSigningTime) {
		t.Fatalf("Got signing time %s, expected first explicit value %s", signingTime, firstSigningTime)
	}
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := os.CreateTemp("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}
}

func fromHex(s string) *big.Int {
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return result
}

// messageOnlySigner signs only through SignMessage, as a remote signing
// service that hashes the data itself does.
type messageOnlySigner struct {
	key *rsa.PrivateKey
}

func (s messageOnlySigner) Public() crypto.PublicKey { return s.key.Public() }

func (s messageOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("Sign called with a digest, expected SignMessage")
}

func (s messageOnlySigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	h := opts.HashFunc().New()
	h.Write(msg)
	return s.key.Sign(rand, h.Sum(nil), opts)
}

func TestSignHandsMessageSignerTheData(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned, err := NewSignedData([]byte("Hello World"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	signer := messageOnlySigner{key: (*cert.PrivateKey).(*rsa.PrivateKey)}
	if err := toBeSigned.AddSigner(cert.Certificate, signer, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("Cannot verify signed data: %s", err)
	}
}

// algorithmSigner reports the signature algorithm it signs with.
type algorithmSigner struct {
	crypto.Signer
	algorithm x509.SignatureAlgorithm
}

func (s algorithmSigner) X509SignatureAlgorithm() x509.SignatureAlgorithm { return s.algorithm }

// pssOnlySigner signs RSASSA-PSS whatever it is asked for, as an HSM with an
// RSASSA-PSS key does.
type pssOnlySigner struct {
	crypto.Signer
}

func (s pssOnlySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Signer.Sign(rand, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()})
}

// pkcs1OnlySigner signs PKCS #1 v1.5 whatever it is asked for, as an HSM
// with a PKCS #1 v1.5 key does.
type pkcs1OnlySigner struct {
	crypto.Signer
}

func (s pkcs1OnlySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Signer.Sign(rand, digest, opts.HashFunc())
}

func TestSignRSAPSS(t *testing.T) {
	tests := map[string]struct {
		certSigAlg x509.SignatureAlgorithm
		digestOID  asn1.ObjectIdentifier
		pssOnly    bool
		pkcs1Only  bool
		reports    x509.SignatureAlgorithm
		wantSigAlg x509.SignatureAlgorithm
		wantErr    bool
	}{
		"reports PSS, SHA-256 digest":               {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, reports: x509.SHA256WithRSAPSS, wantSigAlg: x509.SHA256WithRSAPSS},
		"reports PSS, SHA-384 digest":               {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA384, reports: x509.SHA384WithRSAPSS, wantSigAlg: x509.SHA384WithRSAPSS},
		"reports PSS, SHA-512 digest":               {certSigAlg: x509.SHA512WithRSA, digestOID: OIDDigestAlgorithmSHA512, reports: x509.SHA512WithRSAPSS, wantSigAlg: x509.SHA512WithRSAPSS},
		"PSS-only signer that reports PSS":          {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, pssOnly: true, reports: x509.SHA256WithRSAPSS, wantSigAlg: x509.SHA256WithRSAPSS},
		"reports nothing":                           {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, wantSigAlg: x509.SHA256WithRSA},
		"reports PKCS #1 v1.5":                      {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, reports: x509.SHA256WithRSA, wantSigAlg: x509.SHA256WithRSA},
		"PSS-only signer that reports nothing":      {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, pssOnly: true, wantErr: true},
		"reports PSS with another hash":             {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA384, reports: x509.SHA256WithRSAPSS, wantErr: true},
		"PKCS #1 v1.5-only signer that reports PSS": {certSigAlg: x509.SHA256WithRSA, digestOID: OIDDigestAlgorithmSHA256, pkcs1Only: true, reports: x509.SHA256WithRSAPSS, wantErr: true},
		"ECDSA key that reports PSS":                {certSigAlg: x509.ECDSAWithSHA256, digestOID: OIDDigestAlgorithmSHA256, reports: x509.SHA256WithRSAPSS, wantErr: true},
	}
	for name, test := range tests {
		for _, withoutAttributes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, without attributes %t", name, withoutAttributes), func(t *testing.T) {
				cert, err := createTestCertificate(test.certSigAlg)
				if err != nil {
					t.Fatal(err)
				}
				signer := (*cert.PrivateKey).(crypto.Signer)
				if test.pssOnly {
					signer = pssOnlySigner{Signer: signer}
				}
				if test.pkcs1Only {
					signer = pkcs1OnlySigner{Signer: signer}
				}
				if test.reports != x509.UnknownSignatureAlgorithm {
					signer = algorithmSigner{Signer: signer, algorithm: test.reports}
				}
				toBeSigned, err := NewSignedData([]byte("Hello World"))
				if err != nil {
					t.Fatalf("Cannot initialize signed data: %s", err)
				}
				toBeSigned.SetDigestAlgorithm(test.digestOID)
				if withoutAttributes {
					err = toBeSigned.SignWithoutAttr(cert.Certificate, signer, SignerInfoConfig{})
				} else {
					err = toBeSigned.AddSigner(cert.Certificate, signer, SignerInfoConfig{})
				}
				if test.wantErr {
					if err == nil {
						t.Fatal("Added the signer, expected an error")
					}
					return
				}
				if err != nil {
					t.Fatalf("Cannot add signer: %s", err)
				}
				signed, err := toBeSigned.Finish()
				if err != nil {
					t.Fatalf("Cannot finish signing data: %s", err)
				}
				p7, err := Parse(signed)
				if err != nil {
					t.Fatalf("Cannot parse signed data: %v", err)
				}
				signerInfo := p7.Signers[0]
				sigAlg, err := getSignatureAlgorithm(signerInfo.DigestEncryptionAlgorithm, signerInfo.DigestAlgorithm)
				if err != nil {
					t.Fatalf("Cannot read the signature algorithm: %s", err)
				}
				if sigAlg != test.wantSigAlg {
					t.Fatalf("Got signature algorithm %s, expected %s", sigAlg, test.wantSigAlg)
				}
				if err := p7.Verify(); err != nil {
					t.Fatalf("Cannot verify signed data: %s", err)
				}
			})
		}
	}
}
