//go:generate protoc --go_out=./grpc-proto --go_opt=paths=source_relative --go-grpc_out=./grpc-proto --go-grpc_opt=paths=source_relative -I=./grpc-proto ./grpc-proto/agent/agent.proto

package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	protoContainer "blackprism.org/noyra/grpc-proto/agent"
	"github.com/containers/podman/v5/pkg/bindings"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
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
	go agentService.Run()

	initNoyra()

	ds := BuildDiscoveryService(context.Background(), "noyra-id", agentService)
	go ds.Run(context.Background())

	// for {
	// 	time.Sleep(1 * time.Second)
	// }

	go supervisor()

	for {
		time.Sleep(1 * time.Second)
	}
}

func initNoyra() {

	conn, err := grpc.NewClient("localhost:4646", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := protoContainer.NewAgentClient(conn)

	startRequest := &protoContainer.ContainerStartRequest{
		Image: "envoyproxy/envoy:v1.33.0",
		Name:  "noyra-envoy",
		ExposedPorts: map[uint32]string{
			10000: "tcp",
		},
		Network: "noyra",
	}

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := c.ContainerStart(ctx, startRequest)
	if err != nil {
		log.Fatalf("could not start: %v", err)
	}
	log.Printf("Greeting: %s", r.Status)

}
