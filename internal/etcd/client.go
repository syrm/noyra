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
	logger         *slog.Logger
}

func BuildEtcdClient(
	ctx context.Context,
	caCertFile string,
	caKeyFile string,
	serverCertFile string,
	serverKeyFile string,
	clientCertFile string,
	clientKeyFile string,
	logger *slog.Logger,
) (*Client, error) {
	errGen := generateCertificat(caCertFile, caKeyFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile, logger)

	if errGen != nil {
		return nil, errGen
	}

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error loading CA certificate", slog.Any("error", err))
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error loading client certificate", slog.Any("error", err))
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
		logger.LogAttrs(ctx, slog.LevelError, "error connecting to etcd", slog.Any("error", err))
		return nil, err
	}

	return &Client{
		client:         client,
		caCertFile:     caCertFile,
		serverCertFile: serverCertFile,
		serverKeyFile:  serverKeyFile,
		logger:         logger,
	}, nil
}

func (e *Client) Write(ctx context.Context, key, value string) error {
	_, err := e.client.Put(ctx, key, value)
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error writing to etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) Put(ctx context.Context, key, value string) error {
	_, err := e.client.Put(ctx, key, value)
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error putting value in etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) GetKeys(ctx context.Context) ([]string, error) {
	resp, err := e.client.Get(ctx, "/", clientv3.WithPrefix())
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error getting value from etcd", slog.Any("error", err))
		return []string{}, err
	}

	keys := make([]string, 0, len(resp.Kvs))

	for _, kv := range resp.Kvs {
		keys = append(keys, string(kv.Key))
	}

	return keys, nil
}

func (e *Client) Get(ctx context.Context, key string) (string, error) {
	resp, err := e.client.Get(ctx, key)
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error getting value from etcd", slog.Any("error", err))
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
		e.logger.LogAttrs(ctx, slog.LevelError, "error getting values with prefix from etcd", slog.Any("error", err))
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
	logger *slog.Logger,
) error {
	_, errCrt := os.Stat(caCertFile)
	_, errKey := os.Stat(caKeyFile)

	if errCrt == nil && errKey == nil {
		logger.LogAttrs(context.Background(), slog.LevelInfo, "certificat found")
		return nil
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
		return err
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	if errCa := os.WriteFile(caCertFile, caPEM, 0644); errCa != nil {
		return errCa
	}
	if errCaPriv := os.WriteFile(caKeyFile, caPrivKeyPEM, 0600); errCaPriv != nil {
		return errCaPriv
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
		return err
	}

	serverBytes, err := x509.CreateCertificate(cryptoRand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	if errCrt := os.WriteFile(serverCertFile, serverPEM, 0644); errCrt != nil {
		log.Fatal(errCrt)
	}

	if errPriv := os.WriteFile(serverKeyFile, serverPrivKeyPEM, 0600); errPriv != nil {
		return errPriv
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
		return err
	}

	clientBytes, err := x509.CreateCertificate(cryptoRand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	if err := os.WriteFile(clientCertFile, clientPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(clientKeyFile, clientPrivKeyPEM, 0600); err != nil {
		return err
	}

	return nil
}
