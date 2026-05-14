package certificate

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/samber/oops"
)

func SerializeCert(cert x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func SerializeKey(key crypto.Signer) ([]byte, error) {
	keyDER, errMarshal := x509.MarshalPKCS8PrivateKey(key)
	if errMarshal != nil {
		return nil, oops.Wrapf(errMarshal, "failed to marshal key")
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return keyPEM, nil
}
