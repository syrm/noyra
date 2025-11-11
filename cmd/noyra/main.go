package main

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/containers/podman/v5/pkg/bindings"
	gopsAgent "github.com/google/gops/agent"
	"golang.org/x/sync/errgroup"

	"blackprism.org/noyra/config"
	"blackprism.org/noyra/internal/agent"
	"blackprism.org/noyra/internal/api"
	"blackprism.org/noyra/internal/discovery"
	"blackprism.org/noyra/internal/etcd"
	"blackprism.org/noyra/internal/supervisor"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}))

	go func() {
		err := gopsAgent.Listen(gopsAgent.Options{Addr: "0.0.0.0:50000"})
		if err != nil {
			logger.LogAttrs(context.Background(), slog.LevelError, "unable to start gops agent", slog.Any("error", err))

			os.Exit(1)
		}
	}()

	if os.Getenv("PODMAN_HOST") == "" {
		logger.LogAttrs(context.Background(), slog.LevelError, "PODMAN_HOST env var is not set")
		os.Exit(1)
	}

	if os.Getenv("NOYRA_CONFIG") == "" {
		logger.LogAttrs(context.Background(), slog.LevelError, "NOYRA_CONFIG env var is not set")
		os.Exit(1)
	}

	podmanConnection, err := bindings.NewConnection(ctx, os.Getenv("PODMAN_HOST"))
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error connecting to Podman",
			slog.Any("error", err))
		os.Exit(1)
	}

	agentService := agent.BuildAgent(podmanConnection, logger)
	ds := discovery.BuildDiscoveryService(ctx, "noyra-id", agentService, logger)

	errgrp, errgrpCtx := errgroup.WithContext(ctx)
	errgrp.Go(func() error {
		return ds.Run(errgrpCtx)
	})

	// for {
	// 	time.Sleep(1 * time.Second)
	// }

	etcdClient, errEtcd := etcd.BuildEtcdClient(
		ctx,
		os.Getenv("ETCD_CA_CERT"),
		os.Getenv("ETCD_CA_KEY"),
		os.Getenv("ETCD_SERVER_CERT"),
		os.Getenv("ETCD_SERVER_KEY"),
		os.Getenv("ETCD_CLIENT_CERT"),
		os.Getenv("ETCD_CLIENT_KEY"),
		logger,
	)

	if errEtcd != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error connecting to etcd", slog.Any("error", errEtcd))
		os.Exit(1)
	}

	supervisorServer := supervisor.BuildSupervisor(agentService, etcdClient, config.Schema, logger)
	apiServer := api.BuildAPIServer(etcdClient, logger)

	errgrp.Go(func() error {
		return supervisorServer.Run(errgrpCtx)
	})

	errgrp.Go(func() error {
		return apiServer.Run(errgrpCtx)
	})

	if errWait := errgrp.Wait(); errWait != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error starting supervisor", slog.Any("error", errWait))
	}
}
