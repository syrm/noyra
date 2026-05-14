package certificate

import (
	"crypto"
	"crypto/x509"
	"os"

	"github.com/samber/oops"
)

func SaveCert(cert x509.Certificate, file string) error {
	certBytes := SerializeCert(cert)
	errWrite := os.WriteFile(file, certBytes, 0600)

	if errWrite != nil {
		return oops.With("file", file).Wrapf(errWrite, "failed to save certificate to file")
	}

	return nil
}

func SaveKey(cert crypto.Signer, file string) error {
	keyBytes, errKTB := SerializeKey(cert)

	if errKTB != nil {
		return oops.Wrapf(errKTB, "failed to transform key to bytes: %s", file)
	}

	errWrite := os.WriteFile(file, keyBytes, 0600)

	if errWrite != nil {
		return oops.With("file", file).Wrapf(errWrite, "failed to save key to file")
	}

	return nil
}
