package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"blackprism.org/noyra/internal/certificate/component"
)

// @TODO le nom de fichier ne dit pas que c'est un client etcd
// etsidy on dit

type Client struct {
	client     *clientv3.Client
	tlsConfig  *tls.Config
	clientCert component.Certificate
	logger     *slog.Logger
}

func BuildEtcdClient(
	clientCert component.Certificate,
	logger *slog.Logger,
) *Client {
	return &Client{
		clientCert: clientCert,
		logger:     logger,
	}
}

func (e *Client) getClient(ctx context.Context) (*clientv3.Client, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(e.clientCert.Ca)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{e.clientCert.Cert.Raw},
		PrivateKey:  e.clientCert.Key,
		Leaf:        e.clientCert.Cert,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caCertPool,
	}

	e.tlsConfig = tlsConfig

	if e.client != nil {
		return e.client, nil
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"https://localhost:2379"}, // @TODO utiliser l'endpoint de la config
		DialTimeout: 5 * time.Second,
		TLS:         e.tlsConfig,
	})

	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error connecting to etcd", slog.Any("error", err))
		return nil, err
	}

	e.client = client

	return client, nil
}

func (e *Client) Write(ctx context.Context, key, value string) error {
	client, errClient := e.getClient(ctx)

	if errClient != nil {
		return errClient
	}

	_, err := client.Put(ctx, key, value)
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error writing to etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) Put(ctx context.Context, key, value string) error {
	client, errClient := e.getClient(ctx)

	if errClient != nil {
		return errClient
	}

	_, err := client.Put(ctx, key, value)
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "error putting value in etcd", slog.Any("error", err))
		return err
	}
	return nil
}

func (e *Client) GetKeys(ctx context.Context) ([]string, error) {
	client, errClient := e.getClient(ctx)

	if errClient != nil {
		return []string{}, errClient
	}

	resp, err := client.Get(ctx, "/", clientv3.WithPrefix())
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
	client, errClient := e.getClient(ctx)

	if errClient != nil {
		return "", errClient
	}

	resp, err := client.Get(ctx, key)
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
	client, errClient := e.getClient(ctx)

	if errClient != nil {
		return nil, errClient
	}

	resp, err := client.Get(ctx, prefix, clientv3.WithPrefix())
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
