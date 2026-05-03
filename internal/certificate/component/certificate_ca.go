package component

import (
	"crypto"
	"crypto/x509"
)

type CertificateCa struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}
