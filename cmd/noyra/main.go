package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	gopsAgent "github.com/google/gops/agent"
	"golang.org/x/sync/errgroup"

	"blackprism.org/noyra/config"
	"blackprism.org/noyra/internal/agent"
	"blackprism.org/noyra/internal/certificate"
	"blackprism.org/noyra/internal/discovery"
	"blackprism.org/noyra/internal/etcd"
	"blackprism.org/noyra/internal/podman"
	"blackprism.org/noyra/internal/supervisor"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	go func() {
		err := gopsAgent.Listen(gopsAgent.Options{Addr: "0.0.0.0:50000"})
		if err != nil {
			logger.LogAttrs(context.Background(), slog.LevelError, "unable to start gops agent", slog.Any("error", err))
		}
	}()

	if os.Getenv("PODMAN_HOST") == "" {
		logger.LogAttrs(context.Background(), slog.LevelError, "PODMAN_HOST env var is not set")
		os.Exit(1)
	}

	//errLI := client.ListImages(ctx)
	//
	//if errLI != nil {
	//	logger.LogAttrs(ctx, slog.LevelError, "error list images", slog.Any("error", errLI))
	//}
	//client.PullImage(ctx, "memcached")

	if os.Getenv("NOYRA_CONFIG") == "" {
		logger.LogAttrs(context.Background(), slog.LevelError, "NOYRA_CONFIG env var is not set")
		os.Exit(1)
	}

	podmanClient := podman.BuildClient("/run/user/1000/podman/podman.sock", logger)

	agentService := agent.BuildAgent(podmanClient, logger)
	ds := discovery.BuildDiscoveryService(ctx, "noyra-id", agentService, logger)

	agentServer := agent.BuildServer(agentService, logger)
	go agentServer.Run(ctx, 4646)

	errgrp, errgrpCtx := errgroup.WithContext(ctx)
	errgrp.Go(func() error {
		return ds.Run(errgrpCtx)
	})

	certGenerator := certificate.Generator{}
	caCert, errCa := certGenerator.GenerateCACertificate()
	if errCa != nil {
		logger.LogAttrs(ctx, slog.LevelError, "unable to generate CA cert", slog.Any("error", errCa))
	}

	etcdCert, errEtcdCert := certGenerator.GenerateCertificateServer(*caCert, false, "etcd")
	if errEtcdCert != nil {
		logger.LogAttrs(ctx, slog.LevelError, "unable to generate etcd cert", slog.Any("error", errEtcdCert))
	}
	_ = etcdCert

	etcdClientCert, errEtcdClientCert := certGenerator.GenerateCertificateClient(*caCert, "etcd")
	if errEtcdClientCert != nil {
		logger.LogAttrs(ctx, slog.LevelError, "unable to generate etcd cert", slog.Any("error", errEtcdClientCert))
	}

	etcdClient := etcd.BuildEtcdClient(
		*etcdClientCert,
		logger,
	)

	supervisorServer := supervisor.BuildSupervisor(agentService, etcdClient, config.Schema, logger)
	_ = supervisorServer
	//apiServer := api.BuildAPIServer(etcdClient, logger)

	caPubDER, _ := x509.MarshalPKIXPublicKey(caCert.Cert.PublicKey)
	keyPubDER, _ := x509.MarshalPKIXPublicKey(caCert.Key.(crypto.Signer).Public())

	caFP := sha256.Sum256(caPubDER)
	keyFP := sha256.Sum256(keyPubDER)

	log.Printf("CA  pubkey fp: %x", caFP)
	log.Printf("KEY pubkey fp: %x", keyFP)
	log.Printf("match: %v", caFP == keyFP)

	signerCerts, errGen := certGenerator.GenerateCertificateServer(*caCert, true, "signer")

	if errGen != nil {
		logger.LogAttrs(context.Background(), slog.LevelError, "unable to generate certificate", slog.Any("error", errGen))
		os.Exit(1)
	}

	caCertBytes := certGenerator.CertToBytes(*caCert.Cert)
	os.WriteFile("/mnt/data/src/noyra/ca.pem", caCertBytes, 0600)

	caBytes := certGenerator.CertToBytes(*signerCerts.Ca)
	os.WriteFile("/mnt/data/src/noyra/ca-signer.pem", caBytes, 0600)
	os.WriteFile("/mnt/data/src/noyra-sidecar/ca-sidecar.pem", caBytes, 0600)
	certBytes := certGenerator.CertToBytes(*signerCerts.Cert)
	os.WriteFile("/mnt/data/src/noyra/cert-signer.pem", certBytes, 0600)

	sidecarCerts, errGen := certGenerator.GenerateCertificateServer(*caCert, true, "sidecar")

	if errGen != nil {
		logger.LogAttrs(context.Background(), slog.LevelError, "unable to generate sidecar certificate", slog.Any("error", errGen))
		os.Exit(1)
	}

	certBytes = certGenerator.CertToBytes(*sidecarCerts.Cert)
	os.WriteFile("/mnt/data/src/noyra-sidecar/cert-sidecar.pem", certBytes, 0600)
	keyBytes, _ := certGenerator.KeyToBytes(sidecarCerts.Key)
	os.WriteFile("/mnt/data/src/noyra-sidecar/cert-sidecar-key.pem", keyBytes, 0600)

	signer := certificate.BuildSigner(*caCert, *signerCerts)
	signerServer := certificate.BuildServer(*signerCerts, signer, logger)
	go func() {
		err := signerServer.Run(ctx, 4647)
		println(err.Error())
		if err != nil {
			logger.LogAttrs(context.Background(), slog.LevelError, "signer server crash", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	for {
	}

	/* @TODO enable again errgrp.Go(func() error {
		return supervisorServer.Run(errgrpCtx, certs2)
	})*/

	//errgrp.Go(func() error {
	//	return apiServer.Run(errgrpCtx)
	//})

	if errWait := errgrp.Wait(); errWait != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error starting supervisor", slog.Any("error", errWait))
	}
}
