package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	protoAgent "blackprism.org/noyra/grpc-proto/agent"

	nettypes "github.com/containers/common/libnetwork/types"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/images"
	"github.com/containers/podman/v5/pkg/bindings/network"
	"github.com/containers/podman/v5/pkg/bindings/system"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/containers/podman/v5/pkg/specgen"
	"github.com/fullstorydev/grpchan/inprocgrpc"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

// @TODO le nom agent MEH
type agent struct {
	protoAgent.UnimplementedAgentServer

	podmanContext context.Context
	GrpcServer    *grpc.Server
	Direct        protoAgent.AgentClient
}

func BuildAgent(podmanContext context.Context) *agent {
	a := &agent{podmanContext: podmanContext}

	channel := &inprocgrpc.Channel{}
	a.GrpcServer = grpc.NewServer()

	protoAgent.RegisterAgentServer(a.GrpcServer, a)
	channel.RegisterService(&protoAgent.Agent_ServiceDesc, a)

	a.Direct = protoAgent.NewAgentClient(channel)

	return a
}

func (agentService *agent) Run() {
	ctx := context.Background()
	flag.Parse()
	listenContainer, err := net.Listen("tcp", ":4646")

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to listen for container service",
			slog.Any("error", err))
		os.Exit(1)
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Container service listening",
		slog.Any("address", listenContainer.Addr()))

	if err := agentService.GrpcServer.Serve(listenContainer); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Container service failed",
			slog.Any("error", err))
		os.Exit(1)
	}
}

func (cs *agent) ContainerStart(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) (*protoAgent.Response, error) {
	cs.pullImage(ctx, startRequest)

	networkExists := false
	networks, errList := network.List(cs.podmanContext, &network.ListOptions{})
	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error checking networks",
			slog.Any("error", errList))
		return &protoAgent.Response{Status: "KO"}, fmt.Errorf("error checking networks: %v", errList)
	}

	for _, net := range networks {
		if net.Name == "noyra" {
			networkExists = true
			if net.Driver != "bridge" {
				slog.LogAttrs(ctx, slog.LevelWarn, "Network noyra exists but is not configured in bridge mode",
					slog.String("currentDriver", net.Driver))
				_, errRemove := network.Remove(cs.podmanContext, "noyra", &network.RemoveOptions{})
				if errRemove != nil {
					return &protoAgent.Response{Status: "KO"}, fmt.Errorf("unable to remove non-bridge noyra network: %v", errRemove)
				}
				networkExists = false
			}
			break
		}
	}

	if !networkExists {
		networkCreate, err := network.Create(cs.podmanContext, &nettypes.Network{
			Name:   "noyra",
			Driver: "bridge",
		})
		if err != nil {
			slog.LogAttrs(ctx, slog.LevelError, "Error creating noyra network",
				slog.Any("error", err))
			return &protoAgent.Response{Status: "KO"}, fmt.Errorf("error creating noyra network: %v", err)
		}
		slog.LogAttrs(ctx, slog.LevelInfo, "Noyra network created successfully",
			slog.Any("network", networkCreate))
	}

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range startRequest.GetExposedPorts() {
		println(i, exposedPort)
		exposedPorts[uint16(i)] = exposedPort
	}

	configPath := "/mnt/data/src/go/noyra/config/envoy.yaml"

	args := []string{}
	if strings.Contains(startRequest.GetImage(), "envoyproxy/envoy") {
		args = []string{"-c", "/config.yaml", "--drain-time-s", "5", "-l", "debug"}
	}

	containerSpec := specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:    startRequest.GetName(),
			Labels:  startRequest.GetLabels(),
			Command: args,
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image:   startRequest.GetImage(),
			Volumes: []*specgen.NamedVolume{},
			Mounts: []spec.Mount{
				{
					Destination: "/config.yaml",
					Type:        "bind",
					Source:      configPath,
					Options:     []string{"rbind", "ro"},
				},
			},
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			Expose: exposedPorts,
			NetNS: specgen.Namespace{
				NSMode: specgen.Bridge,
			},
			Networks: map[string]nettypes.PerNetworkOptions{
				"noyra": {},
			},
		},
	}

	if strings.Contains(startRequest.GetImage(), "envoyproxy/envoy") {
		containerSpec.ContainerNetworkConfig.PortMappings = []nettypes.PortMapping{
			{
				ContainerPort: 10000,
				HostPort:      10000,
			},
			{
				ContainerPort: 9001,
				HostPort:      9001,
			},
		}
	}

	response, errList := containers.CreateWithSpec(cs.podmanContext, &containerSpec, nil)

	if errList != nil {
		return &protoAgent.Response{Status: "KO"}, errList
	}

	containerID := response.ID
	slog.LogAttrs(ctx, slog.LevelInfo, "Container created",
		slog.String("id", containerID))

	containers.Start(cs.podmanContext, containerID, &containers.StartOptions{})

	return &protoAgent.Response{Status: "OK"}, nil
}

func (cs *agent) ContainerStop(ctx context.Context, stopRequest *protoAgent.ContainerStopRequest) (*protoAgent.Response, error) {
	containerID := stopRequest.GetContainerId()

	stopOptions := &containers.StopOptions{}

	err := containers.Stop(cs.podmanContext, containerID, stopOptions)

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error stopping container",
			slog.String("containerId", containerID),
			slog.Any("error", err))
		return &protoAgent.Response{Status: "KO"}, err
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Container stopped successfully",
		slog.String("containerId", containerID))
	return &protoAgent.Response{Status: "OK"}, nil
}

func (cs *agent) ContainerRemove(ctx context.Context, removeRequest *protoAgent.ContainerRemoveRequest) (*protoAgent.Response, error) {
	containerID := removeRequest.GetContainerId()

	force := true
	volumes := true
	removeOptions := &containers.RemoveOptions{
		Force:   &force,
		Volumes: &volumes,
	}

	response, err := containers.Remove(cs.podmanContext, containerID, removeOptions)

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error removing container",
			slog.String("containerId", containerID),
			slog.Any("error", err))
		return &protoAgent.Response{Status: "KO"}, err
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Container removed successfully",
		slog.String("containerId", containerID),
		slog.Any("response", response))
	return &protoAgent.Response{Status: "OK"}, nil
}

func (cs *agent) ContainerList(ctx context.Context, listRequest *protoAgent.ContainerListRequest) (*protoAgent.ContainerListResponse, error) {
	podmanContainers, err := containers.List(cs.podmanContext, &containers.ListOptions{})
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error listing containers",
			slog.Any("error", err))
		return nil, err
	}

	var containersInfo []*protoAgent.ContainerInfo

	for _, c := range podmanContainers {
		var exposedPort int32
		for key := range c.ExposedPorts {
			exposedPort = int32(key)
			break
		}

		var ipAddress string
		inspectData, err := containers.Inspect(cs.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, network := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = network.IPAddress
					break
				}
			}
		}

		containersInfo = append(containersInfo, &protoAgent.ContainerInfo{
			Id:          c.ID,
			Name:        c.Names[0],
			Labels:      c.Labels,
			ExposedPort: exposedPort,
			IPAddress:   ipAddress,
		})
	}

	return &protoAgent.ContainerListResponse{Containers: containersInfo}, nil
}

func (cs *agent) ContainerListener(in *protoAgent.ContainerListenerRequest, stream protoAgent.Agent_ContainerListenerServer) error {

	options := new(system.EventsOptions).WithStream(true)
	options.WithFilters(map[string][]string{
		"type":  {"container"},
		"event": {"create", "start", "stop", "die"},
	})

	eventChannel := make(chan entities.Event)

	go func() {
		err := system.Events(cs.podmanContext, eventChannel, nil, options)
		if err != nil {
			fmt.Printf("Error setting up events listener: %v\n", err)
		}
	}()

	for {
		select {
		case event := <-eventChannel:
			if event.Type == "container" {
				containerEvent := &protoAgent.ContainerEvent{
					Id:     event.Actor.ID,
					Action: event.Status,
				}

				if err := stream.Send(containerEvent); err != nil {
					fmt.Printf("Error sending event: %v\n", err)
					return err
				}

				switch event.Status {
				case "create":
					fmt.Printf("Container created: %s\n", event.Actor.ID)
				case "start":
					fmt.Printf("Container started: %s\n", event.Actor.ID)
				case "stop":
					fmt.Printf("Container stopped: %s\n", event.Actor.ID)
				case "die":
					fmt.Printf("Container died: %s\n", event.Actor.ID)
				}
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (cs *agent) pullImage(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) {
	imagesList, _ := images.List(cs.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {startRequest.GetImage()},
	}})

	if len(imagesList) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "Image already present",
			slog.String("image", startRequest.GetImage()))
		return
	}

	quiet := true
	_, err := images.Pull(cs.podmanContext, startRequest.GetImage(), &images.PullOptions{Quiet: &quiet})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error pulling image",
			slog.String("image", startRequest.GetImage()),
			slog.Any("error", err))
		panic(err.Error())
	}
}
