package certificate

import (
	cryptoRand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/samber/oops"

	"blackprism.org/noyra/internal/certificate/component"
)

type Signer struct {
	caCert component.CertificateCa
	cert   component.Certificate
}

func BuildSigner(caCert component.CertificateCa, cert component.Certificate) Signer {
	return Signer{caCert: caCert, cert: cert}
}

func (s *Signer) Certify(
	identity string,
	extKeyUsage []x509.ExtKeyUsage,
	req component.CertifyRequest,
	duration time.Duration,
) (*component.CertifyResponse, error) {
	block, _ := pem.Decode(req.SigningRequest)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, oops.New("failed to decode PEM block: expected CERTIFICATE REQUEST")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse certificate signing request")
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, oops.Wrapf(err, "invalid CSR signature")
	}

	return s.signCSR(csr, identity, extKeyUsage, duration)
}

func (s *Signer) signCSR(
	csr *x509.CertificateRequest,
	identity string,
	extKeyUsage []x509.ExtKeyUsage,
	duration time.Duration,
) (*component.CertifyResponse, error) {
	serial, errSerial := cryptoRand.Int(
		cryptoRand.Reader,
		new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
	)
	if errSerial != nil {
		return nil, oops.Wrapf(errSerial, "can't generate serial number")
	}

	notAfter := time.Now().Add(duration)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: identity,
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,    // @TODO nop, vient du mTLS
		IPAddresses:           csr.IPAddresses, // @TODO nop, vient du mTLS
		URIs:                  csr.URIs,        // @TODO nop, vient du mTLS
	}

	certDER, errCreate := x509.CreateCertificate(
		cryptoRand.Reader,
		&template,
		s.caCert.Cert,
		csr.PublicKey,
		s.caCert.Key,
	)
	if errCreate != nil {
		return nil, oops.Wrapf(errCreate, "failed to create certificate")
	}

	return &component.CertifyResponse{
		LeafCertificate:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		IntermediateCertificates: [][]byte{}, // pas d'intermédiaires dans ton archi actuelle
		NotAfter:                 notAfter,
	}, nil
}
