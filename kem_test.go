package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestMLKEMEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		oid        asn1.ObjectIdentifier
		generate   func() (any, []byte, error)
		ciphertext int
	}{
		{
			name: "ML-KEM-768",
			oid:  OIDKeyAlgorithmMLKEM768,
			generate: func() (any, []byte, error) {
				key, err := mlkem.GenerateKey768()
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
			generate: func() (any, []byte, error) {
				key, err := mlkem.GenerateKey1024()
				if err != nil {
					return nil, nil, err
				}
				return key, key.EncapsulationKey().Bytes(), nil
			},
			ciphertext: 1568,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privateKey, publicKey, err := test.generate()
			if err != nil {
				t.Fatal(err)
			}
			cert := newMLKEMTestCertificate(t, test.oid, publicKey)
			plaintext := []byte("post-quantum CMS EnvelopedData")
			withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)

			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatal(err)
			}
			result, err := p7.Decrypt(cert, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result, plaintext) {
				t.Fatalf("decrypted content mismatch: got %q, want %q", result, plaintext)
			}

			envelope := p7.raw.(envelopedData)
			if envelope.Version != 3 {
				t.Fatalf("EnvelopedData version = %d, want 3", envelope.Version)
			}
			if len(envelope.RecipientInfos) != 1 {
				t.Fatalf("RecipientInfos length = %d, want 1", len(envelope.RecipientInfos))
			}
			raw := envelope.RecipientInfos[0]
			if raw.Class != 2 || raw.Tag != 4 || !raw.IsCompound {
				t.Fatalf("RecipientInfo tag = class %d tag %d compound %t, want [4] constructed", raw.Class, raw.Tag, raw.IsCompound)
			}
			info := decodeKEMRecipientInfo(t, raw)
			if info.Version != 0 {
				t.Errorf("KEMRecipientInfo version = %d, want 0", info.Version)
			}
			if !info.KEM.Algorithm.Equal(test.oid) {
				t.Errorf("KEM OID = %s, want %s", info.KEM.Algorithm, test.oid)
			}
			if algorithmIdentifierHasParameters(info.KEM) {
				t.Error("ML-KEM AlgorithmIdentifier parameters are present")
			}
			if len(info.Ciphertext) != test.ciphertext {
				t.Errorf("ML-KEM ciphertext length = %d, want %d", len(info.Ciphertext), test.ciphertext)
			}
			if !info.KDF.Algorithm.Equal(OIDKDFHKDFSHA256) || algorithmIdentifierHasParameters(info.KDF) {
				t.Errorf("KDF AlgorithmIdentifier = %+v, want HKDF-SHA256 with absent parameters", info.KDF)
			}
			if !info.Wrap.Algorithm.Equal(OIDKeyWrapAES256) || algorithmIdentifierHasParameters(info.Wrap) {
				t.Errorf("wrap AlgorithmIdentifier = %+v, want AES-Wrap-256 with absent parameters", info.Wrap)
			}
			if info.KEKLength != 32 {
				t.Errorf("KEK length = %d, want 32", info.KEKLength)
			}
			if info.RecipientID.Class != 0 || info.RecipientID.Tag != asn1.TagSequence {
				t.Errorf("recipient identifier is not issuerAndSerialNumber")
			}
		})
	}
}

func TestMLKEMAndRSARecipients(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	kemCert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, privateKey.EncapsulationKey().Bytes())
	rsaPair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)
	plaintext := []byte("one message for classical and post-quantum recipients")

	encrypted, err := Encrypt(plaintext, []*x509.Certificate{rsaPair.Certificate, kemCert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	envelope := p7.raw.(envelopedData)
	if envelope.Version != 3 {
		t.Fatalf("mixed-recipient EnvelopedData version = %d, want 3", envelope.Version)
	}
	if len(envelope.RecipientInfos) != 2 {
		t.Fatalf("RecipientInfos length = %d, want 2", len(envelope.RecipientInfos))
	}

	decryptedRSA, err := p7.Decrypt(rsaPair.Certificate, *rsaPair.PrivateKey)
	if err != nil {
		t.Fatalf("RSA recipient decrypt: %v", err)
	}
	decryptedKEM, err := p7.Decrypt(kemCert, privateKey)
	if err != nil {
		t.Fatalf("ML-KEM recipient decrypt: %v", err)
	}
	if !bytes.Equal(decryptedRSA, plaintext) || !bytes.Equal(decryptedKEM, plaintext) {
		t.Fatal("mixed recipients did not recover the same plaintext")
	}
}

func TestMLKEMRFC9935Certificate(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	spki := marshalMLKEMSPKI(t, OIDKeyAlgorithmMLKEM768, privateKey.EncapsulationKey().Bytes(), false)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2026),
		Subject:      pkix.Name{CommonName: "ML-KEM-768 recipient"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		SubjectKeyId: []byte("rfc9935-test-key-id"),
	}
	classicalDER, err := x509.CreateCertificate(rand.Reader, template, template, &test2048Key.PublicKey, test2048Key)
	if err != nil {
		t.Fatal(err)
	}
	certDER := replaceCertificateSPKI(t, classicalDER, spki)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Go x509 rejected an RFC 9935 SubjectPublicKeyInfo: %v", err)
	}
	digest := sha256.Sum256(cert.RawTBSCertificate)
	if err := rsa.VerifyPKCS1v15(&test2048Key.PublicKey, crypto.SHA256, digest[:], cert.Signature); err != nil {
		t.Fatalf("generated RFC 9935 certificate signature is invalid: %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || cert.PublicKey != nil {
		t.Fatalf("unexpected Go x509 ML-KEM public-key representation: algorithm %v, key %T", cert.PublicKeyAlgorithm, cert.PublicKey)
	}

	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
	encrypted, err := Encrypt([]byte("RFC 9935 certificate"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := p7.Decrypt(cert, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "RFC 9935 certificate" {
		t.Fatalf("decrypted content = %q", plaintext)
	}
}

func TestMLKEMSubjectKeyIdentifierRecipient(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, privateKey.EncapsulationKey().Bytes())
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
	encrypted, err := Encrypt([]byte("subject key identifier"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	envelope := p7.raw.(envelopedData)
	info := decodeKEMRecipientInfo(t, envelope.RecipientInfos[0])
	info.RecipientID = asn1.RawValue{Class: 2, Tag: 0, Bytes: cert.SubjectKeyId}
	envelope.RecipientInfos[0] = encodeKEMRecipientInfo(t, info)
	p7.raw = envelope

	plaintext, err := p7.Decrypt(cert, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "subject key identifier" {
		t.Fatalf("decrypted content = %q", plaintext)
	}
}

func TestMLKEMRejectsMalformedAlgorithmIdentifiers(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, privateKey.EncapsulationKey().Bytes())
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
	encrypted, err := Encrypt([]byte("parameters must be absent"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*kemRecipientInfo)
		want   string
	}{
		{"ML-KEM parameters", func(info *kemRecipientInfo) { info.KEM.Parameters = asn1.RawValue{Tag: asn1.TagNull} }, "ML-KEM AlgorithmIdentifier parameters"},
		{"KDF parameters", func(info *kemRecipientInfo) { info.KDF.Parameters = asn1.RawValue{Tag: asn1.TagNull} }, "KEMRecipientInfo KDF"},
		{"wrap parameters", func(info *kemRecipientInfo) { info.Wrap.Parameters = asn1.RawValue{Tag: asn1.TagNull} }, "KEMRecipientInfo key wrap"},
		{"wrong version", func(info *kemRecipientInfo) { info.Version = 1 }, "version must be 0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatal(err)
			}
			envelope := p7.raw.(envelopedData)
			info := decodeKEMRecipientInfo(t, envelope.RecipientInfos[0])
			test.mutate(&info)
			envelope.RecipientInfos[0] = encodeKEMRecipientInfo(t, info)
			p7.raw = envelope
			_, err = p7.Decrypt(cert, privateKey)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Decrypt error = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestMLKEMEncryptionRequirements(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.EncapsulationKey().Bytes()

	t.Run("requires AES content encryption", func(t *testing.T) {
		cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, publicKey)
		withContentEncryptionAlgorithm(t, EncryptionAlgorithmDESCBC)
		_, err := Encrypt([]byte("content"), []*x509.Certificate{cert})
		if err == nil || !strings.Contains(err.Error(), "requires AES-CBC") {
			t.Fatalf("Encrypt error = %v", err)
		}
	})

	t.Run("requires keyEncipherment when key usage is present", func(t *testing.T) {
		cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, publicKey)
		cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
		_, err := Encrypt([]byte("content"), []*x509.Certificate{cert})
		if err == nil || !strings.Contains(err.Error(), "only keyEncipherment") {
			t.Fatalf("Encrypt error = %v", err)
		}
	})

	t.Run("rejects SubjectPublicKeyInfo parameters", func(t *testing.T) {
		cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, publicKey)
		cert.RawSubjectPublicKeyInfo = marshalMLKEMSPKI(t, OIDKeyAlgorithmMLKEM768, publicKey, true)
		withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
		_, err := Encrypt([]byte("content"), []*x509.Certificate{cert})
		if err == nil || !strings.Contains(err.Error(), "parameters must be absent") {
			t.Fatalf("Encrypt error = %v", err)
		}
	})

	t.Run("reports unavailable ML-KEM-512", func(t *testing.T) {
		cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM512, make([]byte, 800))
		withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
		_, err := Encrypt([]byte("content"), []*x509.Certificate{cert})
		if err == nil || !strings.Contains(err.Error(), "not supported by Go 1.27") {
			t.Fatalf("Encrypt error = %v", err)
		}
	})
}

func TestAESKeyWrapRFC3394(t *testing.T) {
	kek := mustDecodeHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plaintext := mustDecodeHex(t, "00112233445566778899AABBCCDDEEFF")
	want := mustDecodeHex(t, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

	wrapped, err := aesKeyWrap(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("wrapped key = %X, want %X", wrapped, want)
	}
	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, plaintext) {
		t.Fatalf("unwrapped key = %X, want %X", unwrapped, plaintext)
	}

	wrapped[len(wrapped)-1] ^= 1
	if _, err := aesKeyUnwrap(kek, wrapped); err == nil {
		t.Fatal("tampered wrapped key was accepted")
	}
}

func TestKEMKeyDerivationRFC9936(t *testing.T) {
	sharedSecret := mustDecodeHex(t, "7DF12D412AE299A24FDE6D7C3BB8E3194C80AD3C733DCF2775E09FE8BEDB86D8")
	wrap := pkix.AlgorithmIdentifier{Algorithm: OIDKeyWrapAES128}
	kek, err := deriveKEMKey(sharedSecret, wrap, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantKEK := mustDecodeHex(t, "CF453A3E2BAE0A78701B8206C185A008")
	if !bytes.Equal(kek, wantKEK) {
		t.Fatalf("derived KEK = %X, want %X", kek, wantKEK)
	}

	contentKey := mustDecodeHex(t, "C5153005588269A0A59F3C01943FDD56")
	wrapped, err := aesKeyWrap(kek, contentKey)
	if err != nil {
		t.Fatal(err)
	}
	wantWrapped := mustDecodeHex(t, "C050E4392F9C14DD0AC2220203F317D701F94F9DD92778F5")
	if !bytes.Equal(wrapped, wantWrapped) {
		t.Fatalf("wrapped content key = %X, want %X", wrapped, wantWrapped)
	}
}

func newMLKEMTestCertificate(t *testing.T, oid asn1.ObjectIdentifier, publicKey []byte) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		RawIssuer:               []byte{0x30, 0x00},
		RawSubjectPublicKeyInfo: marshalMLKEMSPKI(t, oid, publicKey, false),
		SerialNumber:            big.NewInt(42),
		SubjectKeyId:            []byte("ml-kem-test-key-id"),
		KeyUsage:                x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm:      x509.UnknownPublicKeyAlgorithm,
	}
}

func marshalMLKEMSPKI(t *testing.T, oid asn1.ObjectIdentifier, publicKey []byte, withNullParameters bool) []byte {
	t.Helper()
	algorithm := pkix.AlgorithmIdentifier{Algorithm: oid}
	if withNullParameters {
		algorithm.Parameters = asn1.RawValue{Tag: asn1.TagNull}
	}
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithm,
		PublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func decodeKEMRecipientInfo(t *testing.T, raw asn1.RawValue) kemRecipientInfo {
	t.Helper()
	other, err := parseOtherRecipientInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !other.Type.Equal(OIDOtherRecipientInfoKEM) {
		t.Fatalf("OtherRecipientInfo OID = %s, want %s", other.Type, OIDOtherRecipientInfoKEM)
	}
	var info kemRecipientInfo
	rest, err := asn1.Unmarshal(other.Value.FullBytes, &info)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decode KEMRecipientInfo: %v", err)
	}
	return info
}

func encodeKEMRecipientInfo(t *testing.T, info kemRecipientInfo) asn1.RawValue {
	t.Helper()
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalOtherRecipientInfo(OIDOtherRecipientInfoKEM, der)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withContentEncryptionAlgorithm(t *testing.T, algorithm int) {
	t.Helper()
	previous := ContentEncryptionAlgorithm
	ContentEncryptionAlgorithm = algorithm
	t.Cleanup(func() { ContentEncryptionAlgorithm = previous })
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func replaceCertificateSPKI(t *testing.T, certificateDER, spkiDER []byte) []byte {
	t.Helper()
	type certificate struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	var parsed certificate
	rest, err := asn1.Unmarshal(certificateDER, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("parse test certificate: %v", err)
	}

	var fields []asn1.RawValue
	remaining := parsed.TBSCertificate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			t.Fatalf("parse TBSCertificate: %v", err)
		}
		fields = append(fields, field)
	}
	if len(fields) < 7 || fields[0].Class != 2 || fields[0].Tag != 0 {
		t.Fatal("unexpected TBSCertificate layout")
	}
	var spki asn1.RawValue
	if rest, err = asn1.Unmarshal(spkiDER, &spki); err != nil || len(rest) != 0 {
		t.Fatalf("parse replacement SubjectPublicKeyInfo: %v", err)
	}
	fields[6] = spki

	tbsContents := make([]byte, 0, len(parsed.TBSCertificate.Bytes))
	for _, field := range fields {
		tbsContents = append(tbsContents, field.FullBytes...)
	}
	tbsDER, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: tbsContents})
	if err != nil {
		t.Fatal(err)
	}
	parsed.TBSCertificate = asn1.RawValue{FullBytes: tbsDER}
	digest := sha256.Sum256(tbsDER)
	signature, err := rsa.SignPKCS1v15(rand.Reader, test2048Key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	parsed.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	modified, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return modified
}
