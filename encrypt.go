package pkcs7

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC = iota

	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM encryption algorithm
	EncryptionAlgorithmAES256GCM
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, and AES-GCM supported")

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAESGCM(content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128GCM:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128GCM
	case EncryptionAlgorithmAES256GCM:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256GCM
	default:
		return nil, nil, fmt.Errorf("invalid ContentEncryptionAlgorithm in encryptAESGCM: %d", ContentEncryptionAlgorithm)
	}
	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create nonce
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Seal directly after the OCTET STRING header so the ciphertext is not
	// copied again when it is wrapped.
	ciphertext := gcm.Seal(newOctetString(len(content)+gcm.Overhead()), nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algID,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	if key == nil {
		// Create DES key
		key = make([]byte, 8)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create CBC IV
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	cyphertext := encryptCBC(block, iv, content)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptAESCBC(content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmAES128CBC:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128CBC
	case EncryptionAlgorithmAES256CBC:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256CBC
	default:
		return nil, nil, fmt.Errorf("invalid ContentEncryptionAlgorithm in encryptAESCBC: %d", ContentEncryptionAlgorithm)
	}

	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create CBC IV
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	cyphertext := encryptCBC(block, iv, content)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  algID,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an enveloped-data PKCS7 structure with encrypted
// recipient keys for each recipient public key. RSA certificates use CMS key
// transport. RFC 9935 ML-KEM-768 and ML-KEM-1024 certificates use the RFC 9629
// KEMRecipientInfo structure and require an AES-CBC content-encryption algorithm.
//
// The algorithm used to perform encryption is determined by the current value
// of the global ContentEncryptionAlgorithm package variable. By default, the
// value is EncryptionAlgorithmDESCBC. To use a different algorithm, change the
// value before calling Encrypt(). For example:
//
//	ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func Encrypt(content []byte, recipients []*x509.Certificate) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content, nil)
	case EncryptionAlgorithmAES128CBC:
		fallthrough
	case EncryptionAlgorithmAES256CBC:
		key, eci, err = encryptAESCBC(content, nil)
	case EncryptionAlgorithmAES128GCM:
		fallthrough
	case EncryptionAlgorithmAES256GCM:
		key, eci, err = encryptAESGCM(content, nil)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	defer clear(key)

	// Prepare each recipient's encrypted cipher key. RecipientInfo is a CHOICE:
	// RSA uses KeyTransRecipientInfo, while KEM recipients use the
	// OtherRecipientInfo alternative defined by RFC 9629.
	recipientInfos := make([]asn1.RawValue, len(recipients))
	envelopeVersion := 0
	for i, recipient := range recipients {
		info, usesOtherRecipientInfo, err := makeRecipientInfo(key, recipient)
		if err != nil {
			return nil, err
		}
		if usesOtherRecipientInfo {
			envelopeVersion = 3
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              envelopeVersion,
		RecipientInfos:       recipientInfos,
	}
	return asn1.Marshal(contentInfoOf[envelopedData]{ContentType: OIDEnvelopedData, Content: envelope})
}

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(content []byte, key []byte) ([]byte, error) {
	var eci *encryptedContentInfo
	var err error

	if key == nil {
		return nil, ErrPSKNotProvided
	}

	// Apply chosen symmetric encryption method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		_, eci, err = encryptDESCBC(content, key)

	case EncryptionAlgorithmAES128GCM:
		fallthrough
	case EncryptionAlgorithmAES256GCM:
		_, eci, err = encryptAESGCM(content, key)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version:              0,
		EncryptedContentInfo: *eci,
	}
	return asn1.Marshal(contentInfoOf[encryptedData]{ContentType: OIDEncryptedData, Content: ed})
}

// marshalEncryptedContent wraps a DER encoded OCTET STRING as the [0]
// EncryptedContent field without copying it.
func marshalEncryptedContent(octetString []byte) asn1.RawValue {
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: octetString, IsCompound: true}
}

// newOctetString returns a buffer holding the DER header of an OCTET STRING
// with n content bytes and enough capacity to append the content.
func newOctetString(n int) []byte {
	header := 2
	if n >= 128 {
		header += lengthLength(n)
	}
	out := make([]byte, 0, header+n)
	out = append(out, asn1.TagOctetString)
	if n < 128 {
		return append(out, byte(n))
	}
	l := lengthLength(n)
	out = append(out, 0x80|byte(l))
	for ; l > 0; l-- {
		out = append(out, byte(n>>uint((l-1)*8)))
	}
	return out
}

// encryptCBC pads and encrypts content in place inside a single DER OCTET
// STRING buffer and returns that encoding.
func encryptCBC(block cipher.Block, iv, content []byte) []byte {
	blockSize := block.BlockSize()
	out := newOctetString(len(content) + blockSize - len(content)%blockSize)
	start := len(out)
	out, _ = appendPadded(out, content, blockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[start:], out[start:])
	return out
}

func makeRecipientInfo(key []byte, recipient *x509.Certificate) (asn1.RawValue, bool, error) {
	if pub, ok := recipient.PublicKey.(*rsa.PublicKey); ok {
		//nolint:staticcheck // PKCS #1 v1.5 is required by the existing CMS RSA key-transport format.
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
		if err != nil {
			return asn1.RawValue{}, false, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: cert2issuerAndSerial(recipient),
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDEncryptionAlgorithmRSA,
			},
			EncryptedKey: encrypted,
		}
		raw, err := marshalRecipientInfo(info)
		return raw, false, err
	}

	raw, err := makeKEMRecipientInfo(key, recipient)
	return raw, true, err
}

func pad(data []byte, blocklen int) ([]byte, error) {
	return appendPadded(nil, data, blocklen)
}

// appendPadded appends data followed by its PKCS#7 padding to dst. It never
// writes into data's spare capacity.
func appendPadded(dst, data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	dst = slices.Grow(dst, len(data)+padlen)
	dst = append(dst, data...)
	for range padlen {
		dst = append(dst, byte(padlen))
	}
	return dst, nil
}
