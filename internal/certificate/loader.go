package certificate

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/samber/oops"
)

func LoadCert(file string) (x509.Certificate, error) {
	data, errRead := os.ReadFile(file)
	if errRead != nil {
		return x509.Certificate{}, oops.With("file", file).Wrapf(errRead, "failed to read file")
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return x509.Certificate{}, oops.With("file", file).New("failed to decode PEM block")
	}

	cert, errParse := x509.ParseCertificate(block.Bytes)
	if errParse != nil {
		return x509.Certificate{}, oops.With("file", file).Wrapf(errParse, "failed to parse certificate")
	}

	return *cert, nil
}

func LoadKey(file string) (crypto.PrivateKey, error) {
	data, errRead := os.ReadFile(file)
	if errRead != nil {
		return nil, oops.With("file", file).Wrapf(errRead, "failed to read file")
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, oops.With("file", file).New("failed to decode PEM block")
	}

	key, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errParse != nil {
		return nil, oops.With("file", file).Wrapf(errParse, "failed to parse key")
	}

	return key, nil
}
