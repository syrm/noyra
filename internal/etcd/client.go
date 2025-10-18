package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// @TODO le nom de fichier ne dit pas que c'est un client etcd
// etsidy on dit

type Client struct {
	client *clientv3.Client
}

func BuildEtcdClient(ctx context.Context) (*Client, error) {
	caCert, err := os.ReadFile("./certs/etcd-ca.crt")
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error loading CA certificate", slog.Any("error", err))
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("./certs/etcd-client.crt", "./certs/etcd-client.key")
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
