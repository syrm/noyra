package etcd

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// @TODO le nom de fichier ne dit pas que c'est un client etcd
// etsidy on dit

type Client struct {
	client         *clientv3.Client
	caCertFile     string
	serverCertFile string
	serverKeyFile  string
}

func BuildEtcdClient(
	ctx context.Context,
	caCertFile string,
	caKeyFile string,
	serverCertFile string,
	serverKeyFile string,
	clientCertFile string,
	clientKeyFile string,
) (*Client, error) {
	generateCertificat(caCertFile, caKeyFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile)

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error loading CA certificate", slog.Any("error", err))
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error loading client certificate", slog.Any("error", err))
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"https://localhost:2379"}, // @TODO utiliser l'endpoint de la config
		DialTimeout: 5 * time.Second,
		TLS:         tlsConfig,
	})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error connecting to etcd", slog.Any("error", err))
		return nil, err
	}

	return &Client{
		client: client,
	}, nil
}

func (e *Client) Write(ctx context.Context, key, value string) error {
	_, err := e.client.Put(ctx, key, value)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error writing to etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) Put(ctx context.Context, key, value string) error {
	_, err := e.client.Put(ctx, key, value)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error putting value in etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) Get(ctx context.Context, key string) (string, error) {
	resp, err := e.client.Get(ctx, key)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error getting value from etcd", slog.Any("error", err))
		return "", err
	}

	if len(resp.Kvs) == 0 {
		return "", nil
	}

	return string(resp.Kvs[0].Value), nil
}

func (e *Client) GetWithPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error getting values with prefix from etcd", slog.Any("error", err))
		return nil, err
	}

	result := make(map[string]string)
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = string(kv.Value)
	}

	return result, nil
}

func (e *Client) GetCaCertFile() string {
	return e.caCertFile
}

func (e *Client) GetServerCertFile() string {
	return e.serverCertFile
}

func (e *Client) GetServerKeyFile() string {
	return e.serverKeyFile
}

func generateCertificat(
	caCertFile string,
	caKeyFile string,
	serverCertFile string,
	serverKeyFile string,
	clientCertFile string,
	clientKeyFile string,
) {
	_, errCrt := os.Stat(caCertFile)
	_, errKey := os.Stat(caKeyFile)

	if errCrt == nil && errKey == nil {
		slog.LogAttrs(context.Background(), slog.LevelInfo, "certificat not found")
		return
	}

	// Générer une nouvelle autorité de certification (CA) ou réutiliser l'existante
	// Pour cet exemple, nous générons une nouvelle CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1654),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
			CommonName:   "Noyra etcd",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		//log.Fatalf("Erreur: %v", err)
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	if errCa := os.WriteFile(caCertFile, caPEM, 0644); err != nil {
		log.Fatal(errCa)
	}
	if errCaPriv := os.WriteFile(caKeyFile, caPrivKeyPEM, 0600); err != nil {
		log.Fatal(errCaPriv)
	}

	// Générer un nouveau certificat serveur
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1659),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
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
		// log.Fatalf("Erreur: %v", err)
	}

	serverBytes, err := x509.CreateCertificate(cryptoRand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		// log.Fatalf("Erreur: %v", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	if errCrt := os.WriteFile(serverCertFile, serverPEM, 0644); err != nil {
		log.Fatal(errCrt)
	}

	if errPriv := os.WriteFile(serverKeyFile, serverPrivKeyPEM, 0600); err != nil {
		log.Fatal(errPriv)
	}

	// Générer un nouveau certificat client
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(1660),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
			CommonName:   "client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	clientPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		// log.Fatalf("Erreur: %v", err)
	}

	clientBytes, err := x509.CreateCertificate(cryptoRand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		// log.Fatalf("Erreur: %v", err)
	}

	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	if err := os.WriteFile(clientCertFile, clientPEM, 0644); err != nil {
		// log.Fatal(err)
	}
	if err := os.WriteFile(clientKeyFile, clientPrivKeyPEM, 0600); err != nil {
		// log.Fatal(err)
	}

	// log.Println("Nouveaux certificats générés avec succès")
}
