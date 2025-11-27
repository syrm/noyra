package tlsrefresher

import (
	"context"
	"crypto"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/samber/oops"
)

const caCertName = "Noyra"
const caCertOrg = "Blackprism Noyra"

const caCertFile = "ca.pem"
const caKeyFile = "ca-key.pem"
const etcdServerCertFile = "etcd-server.pem"
const etcdServerKeyFile = "etcd-server-key.pem"
const etcdClientCertFile = "etcd-client.pem"
const etcdClientKeyFile = "etcd-client-key.pem"

type Certificates struct {
	CaCert     x509.Certificate
	CaKey      crypto.PrivateKey
	ServerCert x509.Certificate
	ServerKey  crypto.PrivateKey
	ClientCert x509.Certificate
	ClientKey  crypto.PrivateKey
}

type Service struct {
	certs       Certificates
	storagePath fs.DirEntry
	logger      *slog.Logger
}

func BuildService(storagePath fs.DirEntry, logger *slog.Logger) *Service {
	return &Service{
		storagePath: storagePath,
		logger:      logger,
	}
}

func (s *Service) Run(ctx context.Context) error {
	return nil
}

func (s *Service) loadCert(file string) (x509.Certificate, error) {
	data, errRead := os.ReadFile(s.storagePath.Name() + "/" + file)
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

func (s *Service) loadKey(file string) (crypto.PrivateKey, error) {
	data, errRead := os.ReadFile(s.storagePath.Name() + "/" + file)
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

func (s *Service) saveCert(cert x509.Certificate, file string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	if err := os.WriteFile(s.storagePath.Name()+"/"+file, certPEM, 0600); err != nil {
		return oops.With("file", file).Wrapf(err, "failed to write cert file")
	}

	return nil
}

func (s *Service) saveKey(key crypto.PrivateKey, file string) error {
	keyDER, errMarshal := x509.MarshalPKCS8PrivateKey(key)
	if errMarshal != nil {
		return oops.With("file", file).Wrapf(errMarshal, "failed to marshal key")
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(s.storagePath.Name()+"/"+file, keyPEM, 0600); err != nil {
		return oops.With("file", file).Wrapf(err, "failed to write key file")
	}

	return nil
}

func (s *Service) generateCACertificate() error {
	caCert, errLoadCert := s.loadCert(caCertFile)

	if errLoadCert != nil && !errors.Is(errLoadCert, fs.ErrNotExist) {
		return oops.
			With("file", caCertFile).
			Wrapf(errLoadCert, "can't load ca certificate")
	}

	caKey, errLoadKey := s.loadKey(caKeyFile)

	if errLoadKey != nil && !errors.Is(errLoadKey, fs.ErrNotExist) {
		return oops.
			With("file", caKeyFile).
			Wrapf(errLoadKey, "can't load ca key")
	}

	if errLoadCert == nil && errLoadKey == nil {
		s.certs.CaCert = caCert
		s.certs.CaKey = caKey

		return nil
	}

	caTemplate, errCa := s.generateCertificate(
		true,
		caCertName,
		nil,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		nil,
		nil,
		3650*24*time.Hour,
	)

	if errCa != nil {
		return oops.Wrapf(errCa, "can't generate CA certificate")
	}

	caCert, caKey, errCA := s.generateSelfSignedCACertificate(caTemplate)

	if errCA != nil {
		return oops.Wrapf(errCA, "can't generate ca certificate")
	}

	s.certs.CaCert = caCert
	s.certs.CaKey = caKey

	errSaveCaCert := s.saveCert(s.certs.CaCert, caCertFile)
	if errSaveCaCert != nil {
		return oops.
			With("file", caCertFile).
			Wrapf(errSaveCaCert, "can't save CA certificate")
	}

	errSaveCaKey := s.saveKey(s.certs.CaKey, caKeyFile)
	if errSaveCaKey != nil {
		return oops.
			With("file", caKeyFile).
			Wrapf(errSaveCaKey, "can't save CA key")
	}

	return nil
}

/**
Tout ce qui complexifie sans rien apporter en perf, fonctionnalité ou sécurité, je m'en passe
Si c'est une erreur qui casse le programme, je log au plus bas, sinon je log au plus haut...
*/

func (s *Service) generateCertificates() error {
	serverTemplate, errServer := s.generateCertificate(
		false,
		caCertName+" etcd",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		x509.KeyUsageDigitalSignature,
		[]string{"localhost", "etcd"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		30*24*time.Hour,
	)
	if errServer != nil {
		return oops.Wrapf(errServer, "can't generate etcd server certificate")
	}

	serverCert, serverKey, errServerCert := s.generateSignedCertificate(serverTemplate, s.certs.CaCert, s.certs.CaKey)

	if errServerCert != nil {
		return oops.Wrapf(errServerCert, "can't generate etcd server certificate")
	}

	s.certs.ServerCert = serverCert
	s.certs.ServerKey = serverKey

	errSaveServerCert := s.saveCert(serverCert, etcdServerCertFile)
	if errSaveServerCert != nil {
		return oops.
			With("file", etcdServerCertFile).
			Wrapf(errSaveServerCert, "can't save etcd server certificate")
	}
	errSaveServerKey := s.saveKey(serverKey, etcdServerKeyFile)
	if errSaveServerKey != nil {
		return oops.
			With("file", etcdServerKeyFile).
			Wrapf(errSaveServerKey, "can't save etcd server key")
	}

	clientTemplate, errClient := s.generateCertificate(
		false,
		"client",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		x509.KeyUsageDigitalSignature,
		nil,
		nil,
		30*24*time.Hour,
	)
	if errClient != nil {
		return oops.Wrapf(errClient, "can't generate etcd client certificate")
	}

	clientCert, clientKey, errClientCert := s.generateSignedCertificate(clientTemplate, s.certs.CaCert, s.certs.CaKey)

	if errClientCert != nil {
		return oops.Wrapf(errClientCert, "can't generate etcd client certificate")
	}

	s.certs.ClientCert = clientCert
	s.certs.ClientKey = clientKey

	errSaveClientCert := s.saveCert(clientCert, etcdClientCertFile)
	if errSaveClientCert != nil {
		return oops.
			With("file", etcdClientCertFile).
			Wrapf(errSaveClientCert, "can't save etcd client certificate")
	}
	errSaveClientKey := s.saveKey(clientKey, etcdClientKeyFile)
	if errSaveClientKey != nil {
		return oops.
			With("file", etcdClientKeyFile).
			Wrapf(errSaveClientKey, "can't save etcd client key")
	}

	return nil
}

func (s *Service) generateCertificate(
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

func (s *Service) generateSelfSignedCACertificate(
	template x509.Certificate,
) (x509.Certificate, crypto.PrivateKey, error) {
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

func (s *Service) generateSignedCertificate(
	template x509.Certificate,
	ca x509.Certificate,
	caKey crypto.PrivateKey,
) (x509.Certificate, crypto.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't generate ed25519 key")
	}

	certDER, errCreate := x509.CreateCertificate(cryptoRand.Reader, &template, &ca, pubKey, caKey)
	if errCreate != nil {
		return x509.Certificate{}, nil, oops.Wrapf(errCreate, "failed to create certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return x509.Certificate{}, nil, oops.Wrapf(err, "can't parse certificate")
	}

	return *cert, privKey, nil
}
