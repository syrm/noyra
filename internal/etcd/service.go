package etcd

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"
)

const certOrg = "Blackprism Noyra"
const certCommonName = "Noyra etcd"

type Certificates struct {
	Cert       []byte
	CertKey    []byte
	ServerCert []byte
	ServerKey  []byte
	ClientCert []byte
	ClientKey  []byte
}

type Service struct {
	certGenerated bool
	certs         Certificates
	path          fs.DirEntry
	logger        *slog.Logger
}

func BuildService(certs Certificates, logger *slog.Logger) *Service {
	return &Service{
		certGenerated: false,
		certs:         certs,
		logger:        logger,
	}
}

//func (s *Service) GetClient() *Client {
//
//}

func (s *Service) StartServer() {

}

func (s *Service) saveCerts() error {
	err := s.saveCert(s.certs.Cert, "cert.pem")
	if err != nil {
		return err
	}

	err = s.saveCert(s.certs.CertKey, "cert.key")
	if err != nil {
		return err
	}

	err = s.saveCert(s.certs.ServerCert, "server.pem")
	if err != nil {
		return err
	}

	err = s.saveCert(s.certs.ServerKey, "server.key")
	if err != nil {
		return err
	}

	err = s.saveCert(s.certs.ClientCert, "client.pem")
	if err != nil {
		return err
	}

	err = s.saveCert(s.certs.ClientKey, "client.key")
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) saveCert(cert []byte, file string) error {
	if err := os.WriteFile(file, cert, 0644); err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelWarn,
			"can't write file",
			slog.String("file", file),
			slog.Any("error", err),
		)
		return err
	}

	return nil
}

/**
Tout ce qui complexifie sans rien apporter en perf, fonctionnalité ou sécurité, je m'en passe

Si c'est une erreur qui casse le programme, je log au plus bas, sinon je log au plus haut...
*/

func (s *Service) generateCertificates() error {
	if s.certGenerated {
		return nil
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1654), // @TODO heu ? nombre au pif ?
		Subject: pkix.Name{
			Organization: []string{certOrg},
			CommonName:   certCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // @TODO cert expiration
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		return err
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate",
			slog.Any("error", err),
		)
		return err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	s.certs.Cert = caPEM
	s.certs.CertKey = caPrivKeyPEM

	// Générer un nouveau certificat serveur
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1659),
		Subject: pkix.Name{
			Organization: []string{certOrg},
			CommonName:   "localhost",
		},
		DNSNames:    []string{"localhost", "etcd"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"GenerateKey",
			slog.Any("error", err),
		)
		return err
	}

	serverBytes, err := x509.CreateCertificate(cryptoRand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate",
			slog.Any("error", err),
		)
		return err
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	s.certs.ServerCert = serverPEM
	s.certs.ServerKey = serverPrivKeyPEM

	// Générer un nouveau certificat client
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(1660),
		Subject: pkix.Name{
			Organization: []string{certOrg},
			CommonName:   "client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	clientPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"GenerateKey clientPrivKey",
			slog.Any("error", err),
		)
		return err
	}

	clientBytes, err := x509.CreateCertificate(cryptoRand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate clientBytes",
			slog.Any("error", err),
		)
		return err
	}

	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	s.certs.ClientCert = clientPEM
	s.certs.ClientKey = clientPrivKeyPEM

	_ = s.saveCerts()

	return nil
}

func (s *Service) generateCertificate() error {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1654), // @TODO heu ? nombre au pif ?
		Subject: pkix.Name{
			Organization: []string{certOrg},
			CommonName:   certCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // @TODO cert expiration
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		return err
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		s.logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate",
			slog.Any("error", err),
		)
		return err
	}

	_ = caBytes

	return nil
}
