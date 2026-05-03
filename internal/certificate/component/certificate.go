package component

import (
	"crypto"
	"crypto/x509"
)

type Certificate struct {
	Ca   *x509.Certificate
	Cert *x509.Certificate
	Key  crypto.Signer
}
