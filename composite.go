package pkcs7

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type compositeTraditional uint8

const (
	compositePSS compositeTraditional = iota
	compositePKCS1
	compositeECDSA
	compositeEd25519
)

type compositeAlgorithm struct {
	arc         int
	label       string
	ml          mldsa.Parameters
	preHash     crypto.Hash
	traditional compositeTraditional
	tradHash    crypto.Hash
	bits        int
	curve       elliptic.Curve
}

// RFC 10073 Section 6.
// Brainpool (47, 50) and Ed448 (51) are unsupported.
var compositeAlgorithms = [...]compositeAlgorithm{
	{37, "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", mldsa.MLDSA44(), crypto.SHA256, compositePSS, crypto.SHA256, 2048, nil},
	{38, "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", mldsa.MLDSA44(), crypto.SHA256, compositePKCS1, crypto.SHA256, 2048, nil},
	{39, "COMPSIG-MLDSA44-Ed25519-SHA512", mldsa.MLDSA44(), crypto.SHA512, compositeEd25519, 0, 0, nil},
	{40, "COMPSIG-MLDSA44-ECDSA-P256-SHA256", mldsa.MLDSA44(), crypto.SHA256, compositeECDSA, crypto.SHA256, 0, elliptic.P256()},
	{41, "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositePSS, crypto.SHA256, 3072, nil},
	{42, "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositePKCS1, crypto.SHA256, 3072, nil},
	{43, "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositePSS, crypto.SHA384, 4096, nil},
	{44, "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositePKCS1, crypto.SHA384, 4096, nil},
	{45, "COMPSIG-MLDSA65-ECDSA-P256-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositeECDSA, crypto.SHA256, 0, elliptic.P256()},
	{46, "COMPSIG-MLDSA65-ECDSA-P384-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositeECDSA, crypto.SHA384, 0, elliptic.P384()},
	{48, "COMPSIG-MLDSA65-Ed25519-SHA512", mldsa.MLDSA65(), crypto.SHA512, compositeEd25519, 0, 0, nil},
	{49, "COMPSIG-MLDSA87-ECDSA-P384-SHA512", mldsa.MLDSA87(), crypto.SHA512, compositeECDSA, crypto.SHA384, 0, elliptic.P384()},
	{52, "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", mldsa.MLDSA87(), crypto.SHA512, compositePSS, crypto.SHA256, 3072, nil},
	{53, "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", mldsa.MLDSA87(), crypto.SHA512, compositePSS, crypto.SHA384, 4096, nil},
	{54, "COMPSIG-MLDSA87-ECDSA-P521-SHA512", mldsa.MLDSA87(), crypto.SHA512, compositeECDSA, crypto.SHA512, 0, elliptic.P521()},
}

func compositeAlgorithmForOID(oid asn1.ObjectIdentifier) (compositeAlgorithm, bool) {
	for _, algorithm := range compositeAlgorithms {
		if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, algorithm.arc}) {
			return algorithm, true
		}
	}
	return compositeAlgorithm{}, false
}

func verifyCompositeSignature(
	p7 *PKCS7,
	cert *x509.Certificate,
	signer signerInfo,
	message []byte,
	algorithm compositeAlgorithm,
) error {
	// RFC 10082: AlgorithmIdentifier parameters must be absent.
	if algorithmIdentifierParametersPresent(signer.DigestEncryptionAlgorithm.Parameters) ||
		algorithmIdentifierParametersPresent(signer.DigestAlgorithm.Parameters) {
		return errors.New("pkcs7: composite CMS algorithm parameters must be absent")
	}

	digestOID := OIDDigestAlgorithmSHA512
	if algorithm.preHash == crypto.SHA256 {
		digestOID = OIDDigestAlgorithmSHA256
	}
	if !signer.DigestAlgorithm.Algorithm.Equal(digestOID) {
		return errors.New("pkcs7: composite CMS digest algorithm mismatch")
	}

	// Keep these checks limited to composite signatures.
	if len(signer.AuthenticatedAttributes) > 0 {
		var digestCount, typeCount int
		for _, attr := range signer.AuthenticatedAttributes {

			isDigest := attr.Type.Equal(OIDAttributeMessageDigest)
			isContentType := attr.Type.Equal(OIDAttributeContentType)
			if !isDigest && !isContentType {
				continue
			}

			if attr.Value.Class != asn1.ClassUniversal || attr.Value.Tag != asn1.TagSet || !attr.Value.IsCompound {
				return errors.New("pkcs7: malformed composite signed attribute")
			}

			var value asn1.RawValue
			rest, err := asn1.Unmarshal(attr.Value.Bytes, &value)
			if err != nil || len(rest) != 0 || value.Class != asn1.ClassUniversal || value.IsCompound {
				return errors.New("pkcs7: malformed composite signed attribute")
			}

			switch {
			case isDigest:
				if value.Tag != asn1.TagOctetString {
					return errors.New("pkcs7: invalid message-digest attribute type")
				}
				digestCount++
			case isContentType:
				if value.Tag != asn1.TagOID {
					return errors.New("pkcs7: invalid content-type attribute type")
				}
				typeCount++
			}
		}
		if digestCount != 1 || typeCount != 1 {
			return errors.New("pkcs7: composite signed attributes must contain exactly one content-type and message-digest")
		}

		var contentType asn1.ObjectIdentifier
		if err := unmarshalAttribute(
			signer.AuthenticatedAttributes,
			OIDAttributeContentType,
			&contentType,
		); err != nil {
			return err
		}
		sd, ok := p7.raw.(signedData)
		if !ok || !contentType.Equal(sd.ContentInfo.ContentType) {
			return errors.New("pkcs7: composite content-type attribute mismatch")
		}
	} else {
		sd, ok := p7.raw.(signedData)
		if !ok || !sd.ContentInfo.ContentType.Equal(OIDData) {
			return errors.New("pkcs7: composite signatures without signed attributes require id-data")
		}
	}

	// Go's x509.Certificate.PublicKey is not decoded for unknown
	// composite OIDs. Read the original SPKI instead.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil || len(rest) != 0 {
		return errors.New("pkcs7: invalid composite SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(signer.DigestEncryptionAlgorithm.Algorithm) ||
		algorithmIdentifierParametersPresent(spki.Algorithm.Parameters) ||
		spki.PublicKey.BitLength != 8*len(spki.PublicKey.Bytes) {
		return errors.New("pkcs7: invalid composite certificate public-key algorithm or encoding")
	}

	publicKey := spki.PublicKey.Bytes
	signature := signer.EncryptedDigest

	if len(publicKey) <= algorithm.ml.PublicKeySize() ||
		len(signature) <= algorithm.ml.SignatureSize() {
		return errors.New("pkcs7: truncated composite key or signature")
	}

	pqKey, err := mldsa.NewPublicKey(
		algorithm.ml,
		publicKey[:algorithm.ml.PublicKeySize()],
	)
	if err != nil {
		return fmt.Errorf("pkcs7: invalid composite ML-DSA key: %w", err)
	}

	pqSignature := signature[:algorithm.ml.SignatureSize()]
	tradKey := publicKey[algorithm.ml.PublicKeySize():]
	tradSignature := signature[algorithm.ml.SignatureSize():]

	// M' = Prefix || Label || 0x00 || PH(M)
	// CMS sets the application context to empty.
	h := algorithm.preHash.New()
	_, _ = h.Write(message)

	// RFC 10073 Section 2.2 has this static.
	const compositePrefix = "CompositeAlgorithmSignatures2025"
	representative := make([]byte, 0, len(compositePrefix)+len(algorithm.label)+1+h.Size())
	representative = append(representative, compositePrefix...)
	representative = append(representative, algorithm.label...)
	representative = append(representative, 0)
	representative = h.Sum(representative)

	// The underlying ML-DSA context IS the algorithm label.
	if err := mldsa.Verify(
		pqKey,
		representative,
		pqSignature,
		&mldsa.Options{
			Context: algorithm.label,
		},
	); err != nil {
		return fmt.Errorf("pkcs7: invalid composite ML-DSA signature: %w", err)
	}

	if algorithm.traditional == compositeEd25519 {
		if len(tradKey) != ed25519.PublicKeySize ||
			len(tradSignature) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(tradKey), representative, tradSignature) {
			return errors.New("pkcs7: invalid composite Ed25519 signature")
		}
		return nil
	}

	// Traditional components hash M' independently, using their
	// algorithm-specific hash, not necessarily the CMS pre-hash.
	h = algorithm.tradHash.New()
	_, _ = h.Write(representative)
	tradDigest := h.Sum(nil)

	switch algorithm.traditional {
	case compositePSS, compositePKCS1:
		key, err := x509.ParsePKCS1PublicKey(tradKey)
		if err != nil || key.N.BitLen() != algorithm.bits {
			return errors.New("pkcs7: invalid composite RSA key")
		}

		if algorithm.traditional == compositePSS {
			err = rsa.VerifyPSS(
				key,
				algorithm.tradHash,
				tradDigest,
				tradSignature,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
			)
		} else {
			err = rsa.VerifyPKCS1v15(
				key,
				algorithm.tradHash,
				tradDigest,
				tradSignature,
			)
		}
		if err != nil {
			return fmt.Errorf("pkcs7: invalid composite RSA signature: %w", err)
		}

	case compositeECDSA:
		key, err := ecdsa.ParseUncompressedPublicKey(algorithm.curve, tradKey)
		if err != nil {
			return fmt.Errorf("pkcs7: invalid composite ECDSA key: %w", err)
		}

		if !ecdsa.VerifyASN1(key, tradDigest, tradSignature) {
			return errors.New("pkcs7: invalid composite ECDSA signature")
		}

	default:
		return errors.New("pkcs7: unsupported composite traditional algorithm")
	}

	return nil
}
