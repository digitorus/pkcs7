# pkcs7

[![Go Reference](https://pkg.go.dev/badge/github.com/digitorus/pkcs7.svg)](https://pkg.go.dev/github.com/digitorus/pkcs7)
[![CI](https://github.com/digitorus/pkcs7/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/digitorus/pkcs7/actions/workflows/ci.yml)

pkcs7 implements parsing and creating signed and enveloped messages.

The module requires Go 1.27 or later.

```go
import "github.com/digitorus/pkcs7"
```

## Post-quantum cryptography

CMS SignedData supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 using Go's
`crypto/mldsa` and `crypto/x509` packages. Signing and verification follow
[RFC 9882](https://www.rfc-editor.org/rfc/rfc9882.html), including pure-mode
signatures, an empty ML-DSA context, SHA-512 CMS digest identifiers, and absent
ML-DSA AlgorithmIdentifier parameters.

ML-KEM EnvelopedData is not supported. Correct CMS ML-KEM support requires the
KEMRecipientInfo architecture defined by
[RFC 9629](https://www.rfc-editor.org/rfc/rfc9629.html) and used by
[RFC 9936](https://www.rfc-editor.org/rfc/rfc9936.html); it cannot be added to
the existing key-transport recipient path. SLH-DSA is standardized for CMS by
[RFC 9814](https://www.rfc-editor.org/rfc/rfc9814.html), but is not supported
because Go's standard library does not currently provide an SLH-DSA
implementation.

Future work includes KEMRecipientInfo and ML-KEM support, CMS signed-attribute
and EUF-CMA hardening, CMSAlgorithmProtection, SLH-DSA when an appropriate Go
implementation is available, and composite ML-DSA or ML-KEM only after the
relevant IETF specifications stabilize.

```go
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/digitorus/pkcs7"
)

func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		err = fmt.Errorf("Cannot initialize signed data: %s", err)
		return
	}
	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{}); err != nil {
		err = fmt.Errorf("Cannot add signer: %s", err)
		return
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		err = fmt.Errorf("Cannot finish signing data: %s", err)
		return
	}

	// Verify the signature
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		err = fmt.Errorf("Cannot parse our signed data: %s", err)
		return
	}

	// since the signature was detached, reattach the content here
	p7.Content = content

	if bytes.Compare(content, p7.Content) != 0 {
		err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		return
	}
	if err = p7.Verify(); err != nil {
		err = fmt.Errorf("Cannot verify our signed data: %s", err)
		return
	}

	return signed, nil
}
```



## Credits
This is a fork of [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7)
