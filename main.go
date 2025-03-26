//go:generate protoc --go_out=./grpc-proto --go_opt=paths=source_relative --go-grpc_out=./grpc-proto --go-grpc_opt=paths=source_relative -I=./grpc-proto ./grpc-proto/agent/agent.proto

package main

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"time"

	"github.com/containers/podman/v5/pkg/bindings"
)

//go:embed schema.cue
var embeddedSchema string

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}))
	slog.SetDefault(logger)

	ctx := context.Background()

	podmanConnection, err := bindings.NewConnection(ctx, "unix:///run/user/1000/podman/podman.sock")

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error connecting to Podman",
			slog.Any("error", err))
		os.Exit(1)
	}

	agentService := BuildAgent(podmanConnection)
	go agentService.Run(ctx)

	ds := BuildDiscoveryService(ctx, "noyra-id", agentService)
	go ds.Run(ctx)

	// for {
	// 	time.Sleep(1 * time.Second)
	// }

	supervisor := BuildSupervisor(agentService)

	go supervisor.Run(ctx)

	for {
		time.Sleep(1 * time.Second)
	}
}
