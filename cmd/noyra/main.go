package main

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/signal"

	"github.com/containers/podman/v5/pkg/bindings"
	gopsAgent "github.com/google/gops/agent"

	"blackprism.org/noyra/config"
	"blackprism.org/noyra/internal/agent"
	"blackprism.org/noyra/internal/api"
	"blackprism.org/noyra/internal/discovery"
	"blackprism.org/noyra/internal/etcd"
	"blackprism.org/noyra/internal/supervisor"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	go func() {
		err := gopsAgent.Listen(gopsAgent.Options{Addr: "0.0.0.0:50000"})
		if err != nil {
			return
		}
	}()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}))

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
	go ds.Run(ctx)

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

	go supervisorServer.Run(ctx)

	// Initialize and start the Client server
	apiServer := api.BuildAPIServer(etcdClient, logger)
	go apiServer.Run(ctx)

	<-ctx.Done()
}
