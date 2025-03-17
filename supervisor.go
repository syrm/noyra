package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	protoContainer "blackprism.org/noyra/grpc-proto/agent"
)

func supervisor() {
	fmt.Println("supervisor")
	// Set up a connection to the server.
	conn, err := grpc.NewClient("localhost:4646", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := protoContainer.NewAgentClient(conn)

	stream, err := c.ContainerListener(context.Background(), &protoContainer.ContainerListenerRequest{})

	if err != nil {
		log.Fatalf("Error while calling ContainerListener: %v", err)
	}

	for {
		feature, _ := stream.Recv()
		log.Println("bouh supervisoooooooooooooooor", feature)
	}

	// newUUID := uuid.New()
	// shortUUID := newUUID.String()[:8]

	// startRequest := &protoContainer.ContainerStartRequest{
	// 	Image: "192.168.1.39:50000/smallapp:0.3",
	// 	Name:  "noyra-smallapp-" + shortUUID,
	// 	Labels: map[string]string{
	// 		"traefik.http.routers.smallapp.rule":                      "Host(`smallapp.local`)",
	// 		"traefik.http.services.smallapp.loadbalancer.server.port": "80",
	// 	},
	// 	ExposedPorts: map[uint32]string{
	// 		80: "tcp",
	// 	},
	// }

	// // Contact the server and print out its response.
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// defer cancel()
	// r, err := c.ContainerStart(ctx, startRequest)
	// if err != nil {
	// 	log.Fatalf("could not greet: %v", err)
	// }
	// log.Printf("Greeting: %s", r.Status)

	// listResponse, _ := c.ContainerList(ctx, &protoContainer.ContainerListRequest{})

	// log.Println("Containers list")
	// for _, containerInfo := range listResponse.GetContainers() {
	// 	log.Printf("ID: %s\tNAME: %s\n", containerInfo.GetId(), containerInfo.GetName())
	// 	//c.Stop(ctx, &protoContainer.StopRequest{ContainerId: containerInfo.GetId()})
	// 	//c.Remove(ctx, &protoContainer.RemoveRequest{ContainerId: containerInfo.GetId()})
	// }
}
