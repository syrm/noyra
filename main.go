//go:generate protoc --go_out=./grpc-proto --go_opt=paths=source_relative --go-grpc_out=./grpc-proto --go-grpc_opt=paths=source_relative -I=./grpc-proto ./grpc-proto/container/container.proto

package main

import (
	"context"
	"log"
	"time"

	protoContainer "blackprism.org/noyra/grpc-proto/container"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	go agent()

	initNoyra()

	for {
	}

	go supervisor()

	for {
	}
}

func initNoyra() {

	conn, err := grpc.NewClient("localhost:4646", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := protoContainer.NewContainerClient(conn)

	startRequest := &protoContainer.StartRequest{
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
	r, err := c.Start(ctx, startRequest)
	if err != nil {
		log.Fatalf("could not start: %v", err)
	}
	log.Printf("Greeting: %s", r.Status)

}
