package certificate

import (
	"crypto"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/samber/oops"

	"blackprism.org/noyra/internal/certificate/component"
)

const caCertName = "Noyra"
const caCertOrg = "Blackprism Noyra"

/**
Tout ce qui complexifie sans rien apporter en perf, fonctionnalité ou sécurité, je m'en passe
Faudrait ajouter a tes règles : si un truc peut être mal utilisé, je m'en passe
Si c'est une erreur qui casse le programme, je log au plus bas, sinon je log au plus haut...
*/

type Generator struct{}

func (g *Generator) GenerateCACertificate() (*component.CertificateCa, error) {
	caTemplate, errCa := g.generateCertificate(
		true,
		caCertName,
		nil,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		nil,
		nil,
		3650*24*time.Hour, // @TODO 10 ans ? vraiment ?
	)

	if errCa != nil {
		return nil, oops.Wrapf(errCa, "can't generate CA certificate")
	}

	caCert, caKey, errCA := g.generateSelfSignedCACertificate(caTemplate)

	if errCA != nil {
		return nil, oops.Wrapf(errCA, "can't generate ca certificate")
	}

	creds := component.CertificateCa{
		Cert: &caCert,
		Key:  caKey,
	}

	return &creds, nil
}

func (g *Generator) generateCertificate(
	isCA bool,
	commonName string,
	extKeyUsage []x509.ExtKeyUsage,
	keyUsage x509.KeyUsage,
	dnsNames []string,
	ipAddresses []net.IP,
	duration time.Duration,
) (x509.Certificate, error) {
	serial, err := cryptoRand.Int(cryptoRand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil))

	if err != nil {
		return x509.Certificate{}, oops.Wrapf(err, "can't generate serial number for certificate")
	}

	cert := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{caCertOrg},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		IsCA:                  isCA,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	if len(dnsNames) > 0 {
		cert.DNSNames = dnsNames
	}

	if len(ipAddresses) > 0 {
		cert.IPAddresses = ipAddresses
	}

	return cert, nil
}

func (g *Generator) generateSelfSignedCACertificate(
	template x509.Certificate,
) (x509.Certificate, crypto.Signer, error) {
	pubKey, privKey, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't generate ed25519 key")
	}

	certDER, err := x509.CreateCertificate(cryptoRand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "failed to create CA certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't parse CA certificate")
	}

	return *cert, privKey, nil
}

func (g *Generator) generateSignedCertificate(
	template x509.Certificate,
	caCert component.CertificateCa,
) (x509.Certificate, crypto.Signer, error) {
	pubKey, privKey, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't generate ed25519 key")
	}

	certDER, errCreate := x509.CreateCertificate(cryptoRand.Reader, &template, caCert.Cert, pubKey, caCert.Key)
	if errCreate != nil {
		return x509.Certificate{}, nil, oops.Wrapf(errCreate, "failed to create certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't parse certificate")
	}

	return *cert, privKey, nil
}

func (g *Generator) GenerateCertificateServer(caCert component.CertificateCa, client bool, name string) (*component.Certificate, error) {
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	serverTemplate, errServer := g.generateCertificate(
		false,
		caCertName+" "+name,
		extKeyUsage,
		x509.KeyUsageDigitalSignature,
		[]string{"localhost"}, // add a name ? like etcd etc...
		[]net.IP{net.ParseIP("127.0.0.1")},
		20*time.Minute, // 1h ?
	)
	if errServer != nil {
		return nil, oops.Wrapf(errServer, "can't generate server certificate")
	}

	serverCert, serverKey, errServerCert := g.generateSignedCertificate(serverTemplate, caCert)
	if errServerCert != nil {
		return nil, oops.Wrapf(errServerCert, "can't generate signed server certificate")
	}

	return &component.Certificate{
		Ca:   caCert.Cert,
		Cert: &serverCert,
		Key:  serverKey,
	}, nil
}

func (g *Generator) GenerateCertificateClient(caCert component.CertificateCa, name string) (*component.Certificate, error) {
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	clientTemplate, errServer := g.generateCertificate(
		false,
		caCertName+" "+name,
		extKeyUsage,
		x509.KeyUsageDigitalSignature,
		nil,
		nil,
		20*time.Minute, // 1h
	)
	if errServer != nil {
		return nil, oops.Wrapf(errServer, "can't generate client certificate")
	}

	clientCert, clientKey, errClientCert := g.generateSignedCertificate(clientTemplate, caCert)
	_ = clientKey
	if errClientCert != nil {
		return nil, oops.Wrapf(errClientCert, "can't generate signed client certificate")
	}

	return &component.Certificate{
		Ca:   caCert.Cert,
		Cert: &clientCert,
		Key:  clientKey,
	}, nil
}
