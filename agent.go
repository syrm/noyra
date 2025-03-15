package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	protoContainer "blackprism.org/noyra/grpc-proto/container"

	nettypes "github.com/containers/common/libnetwork/types"
	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/images"
	"github.com/containers/podman/v5/pkg/bindings/network"
	"github.com/containers/podman/v5/pkg/specgen"
	"google.golang.org/grpc"
)

type containerServer struct {
	protoContainer.UnimplementedContainerServer

	podmanContext context.Context
}

func (cs *containerServer) Start(ctx context.Context, startRequest *protoContainer.StartRequest) (*protoContainer.Response, error) {

	cs.pullImage(ctx, startRequest)

	network.Create(cs.podmanContext, &nettypes.Network{
		Name:   "noyra",
		Driver: "bridge",
	})

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range startRequest.GetExposedPorts() {
		println(i, exposedPort)
		exposedPorts[uint16(i)] = exposedPort
	}

	containerSpec := specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:   startRequest.GetName(),
			Labels: startRequest.GetLabels(),
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image: startRequest.GetImage(),
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			Expose: exposedPorts,
			Networks: map[string]nettypes.PerNetworkOptions{
				"noyra": {},
			},
		},
	}

	response, err := containers.CreateWithSpec(cs.podmanContext, &containerSpec, nil)

	if err != nil {
		return &protoContainer.Response{Status: "KO"}, err
	}

	containerID := response.ID
	fmt.Printf("Le conteneur a été créé avec ID: %s\n", containerID)

	containers.Start(cs.podmanContext, containerID, &containers.StartOptions{})

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) Stop(ctx context.Context, stopRequest *protoContainer.StopRequest) (*protoContainer.Response, error) {

	// err := cs.podmanConnection.ContainerStop(ctx, stopRequest.GetContainerId(), container.StopOptions{})

	// if err != nil {
	// 	println(err.Error())
	// 	return &protoContainer.Response{Status: "KO"}, err
	// }

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) Remove(ctx context.Context, removeRequest *protoContainer.RemoveRequest) (*protoContainer.Response, error) {
	// err := cs.podmanConnection.ContainerRemove(ctx, removeRequest.GetContainerId(), container.RemoveOptions{})

	// if err != nil {
	// 	println(err.Error())
	// 	return &protoContainer.Response{Status: "KO"}, err
	// }

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) pullImage(ctx context.Context, startRequest *protoContainer.StartRequest) {
	// filterArgs := filters.NewArgs()
	// filterArgs.Add("reference", startRequest.GetImage())

	// images, _ := cs.podmanConnection.ImageList(ctx, image.ListOptions{Filters: filterArgs})

	// if len(images) > 0 {
	// 	log.Println("image " + startRequest.GetImage() + " already present")
	// 	return
	// }

	imagesList, _ := images.List(cs.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {startRequest.GetImage()},
	}})

	if len(imagesList) > 0 {
		log.Println("image " + startRequest.GetImage() + " already present")
		return
	}

	quiet := true
	_, err := images.Pull(cs.podmanContext, startRequest.GetImage(), &images.PullOptions{Quiet: &quiet})

	if err != nil {
		panic(err.Error())
	}
}

// func (cs *containerServer) List(ctx context.Context, listRequest *protoContainer.ListRequest) (*protoContainer.ListResponse, error) {

// containers, errContainerList := cs.podmanConnection.ContainerList(ctx, container.ListOptions{})
// if errContainerList != nil {
// 	println(errContainerList.Error())
// }

// var containersInfo []*protoContainer.ContainerInfo

// for _, c := range containers {
// 	containersInfo = append(containersInfo, &protoContainer.ContainerInfo{
// 		Id:   c.ID,
// 		Name: c.Names[0],
// 	})
// }

// return &protoContainer.ListResponse{Containers: containersInfo}, nil
// }

func agent() {
	flag.Parse()
	lis, err := net.Listen("tcp", ":4646")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	_ = lis

	ctx := context.Background()

	podmanConnection, err := bindings.NewConnection(ctx, "unix:///run/user/1000/podman/podman.sock")

	if err != nil {
		log.Fatalf("bahhhhhhhhhhhh ?", err)
	}
	/*
		inspectData, err := containers.Inspect(conn, "smallapp-1", new(containers.InspectOptions).WithSize(true))

		if err != nil {
			log.Fatalf("a", err)
		}

		fmt.Printf("%+v\n", inspectData)
	*/

	//cli, _ := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	cs := containerServer{
		podmanContext: podmanConnection,
	}

	s := grpc.NewServer()
	protoContainer.RegisterContainerServer(s, &cs)
	log.Printf("containerServer listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
