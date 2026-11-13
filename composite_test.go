package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// These tests exercise the two real PKCS7 verification dispatch paths without
// requiring support for producing composite-signed X.509 certificates.
// The certificate is a minimal test stand-in with a genuine DER-encoded SPKI.
func TestCompositeVerify(t *testing.T) {
	var idctTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	msg := []byte("Composite ML-DSA CMS verification")
	rsaKeys := map[int]*rsa.PrivateKey{}
	for _, arc := range []int{37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 48, 49, 52, 53, 54} {
		a, ok := compositeAlgorithmForOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arc})
		if !ok {
			t.Fatalf("missing OID arc %d", arc)
		}
		t.Run(a.label, func(t *testing.T) {
			pq, err := mldsa.GenerateKey(a.ml)
			if err != nil {
				t.Fatal(err)
			}
			var tradKey []byte
			var signer func([]byte) ([]byte, error)
			switch a.traditional {
			case compositePSS, compositePKCS1:
				key := rsaKeys[a.bits]
				if key == nil {
					key, err = rsa.GenerateKey(rand.Reader, a.bits)
					if err != nil {
						t.Fatal(err)
					}
					rsaKeys[a.bits] = key
				}
				tradKey = x509.MarshalPKCS1PublicKey(&key.PublicKey)
				signer = func(rep []byte) ([]byte, error) {
					h := a.tradHash.New()
					h.Write(rep)
					digest := h.Sum(nil)
					if a.traditional == compositePSS {
						return rsa.SignPSS(rand.Reader, key, a.tradHash, digest,
							&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
					}
					return rsa.SignPKCS1v15(rand.Reader, key, a.tradHash, digest)
				}

			case compositeECDSA:
				key, err := ecdsa.GenerateKey(a.curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				tradKey, err = key.PublicKey.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				signer = func(rep []byte) ([]byte, error) {
					h := a.tradHash.New()
					h.Write(rep)
					return ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
				}

			case compositeEd25519:
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				tradKey = pub
				signer = func(rep []byte) ([]byte, error) {
					return ed25519.Sign(key, rep), nil
				}

			default:
				t.Fatal("unsupported test algorithm")
			}

			pub := append(append([]byte{}, pq.PublicKey().Bytes()...), tradKey...)
			oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arc}
			spki, err := asn1.Marshal(subjectPublicKeyInfo{
				Algorithm: pkix.AlgorithmIdentifier{
					Algorithm: oid,
				},
				PublicKey: asn1.BitString{
					Bytes:     pub,
					BitLength: len(pub) * 8,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{
				RawSubjectPublicKeyInfo: spki,
				RawIssuer:               []byte{0x30, 0x00}, // empty but valid DER Name
				SerialNumber:            big.NewInt(1),
				NotBefore:               time.Now().Add(-time.Hour),
				NotAfter:                time.Now().Add(time.Hour),
			}
			for _, attrs := range []bool{false, true} {
				name := "no-attributes"
				if attrs {
					name = "signed-attributes"
				}
				t.Run(name, func(t *testing.T) {
					cms := &PKCS7{Content: append([]byte(nil), msg...), Certificates: []*x509.Certificate{cert},
						raw: signedData{ContentInfo: contentInfo{ContentType: OIDData}}}
					sign := signerInfo{
						IssuerAndSerialNumber:     issuerAndSerial{IssuerName: asn1.RawValue{FullBytes: cert.RawIssuer}, SerialNumber: cert.SerialNumber},
						DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
					}
					if a.preHash == crypto.SHA256 {
						sign.DigestAlgorithm.Algorithm = OIDDigestAlgorithmSHA256
					} else {
						sign.DigestAlgorithm.Algorithm = OIDDigestAlgorithmSHA512
					}
					toSign := msg
					if attrs {
						h := a.preHash.New()
						h.Write(msg)
						set := &attributes{}
						set.Add(OIDAttributeContentType, OIDData)
						set.Add(OIDAttributeMessageDigest, h.Sum(nil))
						sign.AuthenticatedAttributes, err = set.ForMarshalling()
						if err != nil {
							t.Fatal(err)
						}
						toSign, err = marshalAttributes(sign.AuthenticatedAttributes)
						if err != nil {
							t.Fatal(err)
						}
					}
					// Construct M' independently of the implementation under test.
					h := a.preHash.New()
					h.Write(toSign)
					rep := append([]byte("CompositeAlgorithmSignatures2025"), []byte(a.label)...)
					rep = append(rep, 0) // RFC 10082: empty composite application context
					rep = append(rep, h.Sum(nil)...)
					pqSig, err := pq.Sign(nil, rep, &mldsa.Options{Context: a.label})
					if err != nil {
						t.Fatal(err)
					}
					tradSig, err := signer(rep)
					if err != nil {
						t.Fatal(err)
					}
					sign.EncryptedDigest = append(pqSig, tradSig...)
					cms.Signers = []signerInfo{sign}
					if err := cms.Verify(); err != nil {
						t.Fatalf("Verify: %v", err)
					}
					if err := cms.VerifyWithOpts(x509.VerifyOptions{CurrentTime: time.Now()}); err != nil {
						t.Fatalf("VerifyWithOpts(CurrentTime): %v", err)
					}
					// Mutations must fail even when the other component remains valid.
					type mutation struct {
						name   string
						mutate func(*PKCS7)
					}
					tests := []mutation{
						{"changed-content", func(p *PKCS7) { p.Content[0] ^= 1 }},
						{"bad-ml-dsa", func(p *PKCS7) { p.Signers[0].EncryptedDigest[0] ^= 1 }},
						{"bad-traditional", func(p *PKCS7) { p.Signers[0].EncryptedDigest[len(p.Signers[0].EncryptedDigest)-1] ^= 1 }},
						{"truncated-signature", func(p *PKCS7) { p.Signers[0].EncryptedDigest = p.Signers[0].EncryptedDigest[:a.ml.SignatureSize()-1] }},
						{"wrong-digest-oid", func(p *PKCS7) {
							if a.preHash == crypto.SHA256 {
								p.Signers[0].DigestAlgorithm.Algorithm = OIDDigestAlgorithmSHA512
							} else {
								p.Signers[0].DigestAlgorithm.Algorithm = OIDDigestAlgorithmSHA256
							}
						}},
						{"signature-parameters-null", func(p *PKCS7) { p.Signers[0].DigestEncryptionAlgorithm.Parameters = asn1.NullRawValue }},
						{"digest-parameters-null", func(p *PKCS7) { p.Signers[0].DigestAlgorithm.Parameters = asn1.NullRawValue }},
						{"malformed-spki", func(p *PKCS7) {
							badCert := *cert
							badCert.RawSubjectPublicKeyInfo = []byte{0x00}
							p.Certificates = []*x509.Certificate{&badCert}
						}},
						{"signature-oid-key-mismatch", func(p *PKCS7) {
							other := 38
							if arc == 38 {
								other = 37
							}
							p.Signers[0].DigestEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, other}
						}},
					}
					if attrs {
						tests = append(tests,
							mutation{"missing-content-type", func(p *PKCS7) {
								var filtered []attribute
								for _, attr := range p.Signers[0].AuthenticatedAttributes {
									if !attr.Type.Equal(OIDAttributeContentType) {
										filtered = append(filtered, attr)
									}
								}
								p.Signers[0].AuthenticatedAttributes = filtered
							}},
							mutation{"duplicate-message-digest", func(p *PKCS7) {
								for _, attr := range p.Signers[0].AuthenticatedAttributes {
									if attr.Type.Equal(OIDAttributeMessageDigest) {
										p.Signers[0].AuthenticatedAttributes = append(p.Signers[0].AuthenticatedAttributes, attr)
										return
									}
								}
							}},
							mutation{"wrong-attribute-set-class", func(p *PKCS7) {
								for i := range p.Signers[0].AuthenticatedAttributes {
									attr := &p.Signers[0].AuthenticatedAttributes[i]
									if attr.Type.Equal(OIDAttributeMessageDigest) {
										attr.Value.Class = asn1.ClassContextSpecific
										return
									}
								}
							}},
							mutation{"primitive-attribute-set", func(p *PKCS7) {
								for i := range p.Signers[0].AuthenticatedAttributes {
									attr := &p.Signers[0].AuthenticatedAttributes[i]
									if attr.Type.Equal(OIDAttributeMessageDigest) {
										attr.Value.IsCompound = false
										return
									}
								}
							}},
						)
					}
					if !attrs {
						tests = append(tests, mutation{
							name: "non-data-without-attributes",
							mutate: func(p *PKCS7) {
								sd := p.raw.(signedData)
								sd.ContentInfo.ContentType = idctTSTInfo
								p.raw = sd
							},
						})
					}
					for _, tc := range tests {
						t.Run(tc.name, func(t *testing.T) {
							bad := *cms
							bad.Content = bytes.Clone(cms.Content)
							bad.Signers = append([]signerInfo(nil), cms.Signers...)
							bad.Signers[0].EncryptedDigest = bytes.Clone(cms.Signers[0].EncryptedDigest)
							bad.Signers[0].AuthenticatedAttributes = append([]attribute(nil), cms.Signers[0].AuthenticatedAttributes...)
							tc.mutate(&bad)
							if err := bad.Verify(); err == nil {
								t.Fatal("accepted invalid composite signature")
							}
						})
					}
				})
			}
		})
	}
}
