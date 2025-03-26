package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
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

func (a *agent) Run(ctx context.Context) {
	a.initNoyra(ctx)

	flag.Parse()
	listenContainer, err := net.Listen("tcp", ":4646")

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to listen for container service",
			slog.Any("error", err))
		os.Exit(1)
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Container service listening",
		slog.Any("address", listenContainer.Addr()))

	if err := a.GrpcServer.Serve(listenContainer); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Container service failed",
			slog.Any("error", err))
		os.Exit(1)
	}
}

func (a *agent) ContainerStart(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) (*protoAgent.Response, error) {
	a.pullImage(ctx, startRequest)

	if err := a.createNetwork(ctx); err != nil {
		return &protoAgent.Response{Status: "KO"}, err
	}

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range startRequest.GetExposedPorts() {
		exposedPorts[uint16(i)] = exposedPort
	}

	mounts := make([]spec.Mount, 0, len(startRequest.GetMounts()))
	slog.LogAttrs(ctx, slog.LevelDebug, "Initializing mounts", slog.Any("mounts", mounts))
	for _, m := range startRequest.GetMounts() {
		mounts = append(mounts, spec.Mount{
			Destination: m.GetDestination(),
			Source:      m.GetSource(),
			Type:        m.GetType(),
			Options:     m.GetOptions(),
		})
	}

	portMappings := make([]nettypes.PortMapping, 0, len(startRequest.GetPortMappings()))
	for _, p := range startRequest.GetPortMappings() {
		portMappings = append(portMappings, nettypes.PortMapping{
			ContainerPort: uint16(p.GetContainerPort()),
			HostPort:      uint16(p.GetHostPort()),
		})
	}

	var memoryLimit int64 = 100_000_000 // 100mb
	var cpuQuota int64 = 10_000         // 10ms cpu
	var cpuPeriod uint64 = 1_000_000

	containerSpec := specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:    startRequest.GetName(),
			Labels:  startRequest.GetLabels(),
			Command: startRequest.GetCommand(),
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image:   startRequest.GetImage(),
			Volumes: []*specgen.NamedVolume{},
			Mounts:  mounts,
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			Expose: exposedPorts,
			NetNS: specgen.Namespace{
				NSMode: specgen.Bridge,
			},
			Networks: map[string]nettypes.PerNetworkOptions{
				"noyra": {},
			},
			PortMappings: portMappings,
		},
		ContainerResourceConfig: specgen.ContainerResourceConfig{
			ResourceLimits: &spec.LinuxResources{
				Memory: &spec.LinuxMemory{
					Limit: &memoryLimit,
				},
				CPU: &spec.LinuxCPU{
					Quota:  &cpuQuota,
					Period: &cpuPeriod,
				},
			},
		},
	}

	response, errList := containers.CreateWithSpec(a.podmanContext, &containerSpec, nil)

	if errList != nil {
		return &protoAgent.Response{Status: "KO"}, errList
	}

	containerID := response.ID
	slog.LogAttrs(ctx, slog.LevelInfo, "Container created",
		slog.String("id", containerID))

	containers.Start(a.podmanContext, containerID, &containers.StartOptions{})

	return &protoAgent.Response{Status: "OK"}, nil
}

func (a *agent) createNetwork(ctx context.Context) error {
	networkExists := false
	networks, errList := network.List(a.podmanContext, &network.ListOptions{Filters: map[string][]string{"name": {"noyra"}}})
	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error checking networks",
			slog.Any("error", errList))
		return fmt.Errorf("error checking networks: %v", errList)
	}

	if len(networks) == 1 {
		noyraNetwork := networks[0]
		networkExists = true
		if noyraNetwork.Driver != "bridge" {
			slog.LogAttrs(ctx, slog.LevelWarn, "Network noyra exists but is not configured in bridge mode",
				slog.String("currentDriver", noyraNetwork.Driver))
			_, errRemove := network.Remove(a.podmanContext, "noyra", &network.RemoveOptions{})
			if errRemove != nil {
				return fmt.Errorf("unable to remove non-bridge noyra network: %v", errRemove)
			}
			networkExists = false
		}
	}

	if !networkExists {
		networkCreate, err := network.Create(a.podmanContext, &nettypes.Network{
			Name:   "noyra",
			Driver: "bridge",
			Subnets: []nettypes.Subnet{
				{
					Subnet: nettypes.IPNet{
						IPNet: net.IPNet{
							IP:   net.ParseIP("10.66.0.0"),
							Mask: net.CIDRMask(16, 32),
						},
					},
				},
			},
		})

		if err != nil {
			slog.LogAttrs(ctx, slog.LevelError, "Error creating noyra network",
				slog.Any("error", err))
			return fmt.Errorf("error creating noyra network: %v", err)
		}

		slog.LogAttrs(ctx, slog.LevelInfo, "Noyra network created successfully",
			slog.Any("network", networkCreate))
	}

	return nil
}

func (a *agent) ContainerStop(ctx context.Context, stopRequest *protoAgent.ContainerStopRequest) (*protoAgent.Response, error) {
	containerID := stopRequest.GetContainerId()

	stopOptions := &containers.StopOptions{}

	err := containers.Stop(a.podmanContext, containerID, stopOptions)

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

func (a *agent) ContainerRemove(ctx context.Context, removeRequest *protoAgent.ContainerRemoveRequest) (*protoAgent.Response, error) {
	containerID := removeRequest.GetContainerId()

	force := true
	volumes := true
	removeOptions := &containers.RemoveOptions{
		Force:   &force,
		Volumes: &volumes,
	}

	response, err := containers.Remove(a.podmanContext, containerID, removeOptions)

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

func (a *agent) ContainerList(ctx context.Context, listRequest *protoAgent.ContainerListRequest) (*protoAgent.ContainerListResponse, error) {
	filters := make(map[string][]string)

	if listRequest.GetContainersId() != nil {
		filters["id"] = listRequest.GetContainersId()
	}

	if listRequest.GetLabels() != nil {
		var labels []string
		for key, value := range listRequest.GetLabels() {
			labels = append(labels, key+"="+value)
		}

		filters["label"] = labels
	}

	podmanContainers, err := containers.List(a.podmanContext, &containers.ListOptions{Filters: filters})
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error listing containers",
			slog.Any("error", err))
		return nil, err
	}

	containersList := make(map[string]*protoAgent.ContainerInfo)

	for _, c := range podmanContainers {
		var exposedPort int32
		for key := range c.ExposedPorts {
			exposedPort = int32(key)
			break
		}

		var ipAddress string
		inspectData, err := containers.Inspect(a.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, network := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = network.IPAddress
					break
				}
			}
		}

		containersList[c.ID] = &protoAgent.ContainerInfo{
			Id:          c.ID,
			Name:        c.Names[0],
			Labels:      c.Labels,
			ExposedPort: exposedPort,
			IPAddress:   ipAddress,
		}
	}

	return &protoAgent.ContainerListResponse{Containers: containersList}, nil
}

func (a *agent) ContainerListener(in *protoAgent.ContainerListenerRequest, stream protoAgent.Agent_ContainerListenerServer) error {

	options := new(system.EventsOptions).WithStream(true)
	options.WithFilters(map[string][]string{
		"type":  {"container"},
		"event": {"create", "start", "stop", "die"},
	})

	eventChannel := make(chan entities.Event)

	go func() {
		err := system.Events(a.podmanContext, eventChannel, nil, options)
		if err != nil {
			slog.LogAttrs(stream.Context(), slog.LevelError, "Error setting up events listener", slog.Any("error", err))
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
					slog.LogAttrs(stream.Context(), slog.LevelError, "Error sending container event",
						slog.Any("error", err),
						slog.String("containerId", event.Actor.ID),
						slog.String("action", event.Status))
					return err
				}

				switch event.Status {
				case "create":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "Container created", slog.String("containerId", event.Actor.ID))
				case "start":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "Container started", slog.String("containerId", event.Actor.ID))
				case "stop":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "Container stopped", slog.String("containerId", event.Actor.ID))
				case "die":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "Container died", slog.String("containerId", event.Actor.ID))
				}
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (a *agent) pullImage(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) {
	imagesList, _ := images.List(a.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {startRequest.GetImage()},
	}})

	if len(imagesList) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "Image already present",
			slog.String("image", startRequest.GetImage()))
		return
	}

	quiet := true
	_, err := images.Pull(a.podmanContext, startRequest.GetImage(), &images.PullOptions{Quiet: &quiet})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error pulling image",
			slog.String("image", startRequest.GetImage()),
			slog.Any("error", err))
		panic(err.Error())
	}
}

func (a *agent) initNoyra(ctx context.Context) {
	containersList, err := a.ContainerList(ctx, &protoAgent.ContainerListRequest{
		Labels: map[string]string{
			"noyra.name": "noyra-envoy",
		},
	})

	if len(containersList.GetContainers()) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "Noyra already running")
		return
	}

	configPath := "/mnt/data/src/go/noyra/config/envoy.yaml"

	startRequest := &protoAgent.ContainerStartRequest{
		Image:   "envoyproxy/envoy:v1.33.0",
		Name:    "noyra-envoy",
		Command: []string{"-c", "/config.yaml", "--drain-time-s", "5"},
		ExposedPorts: map[uint32]string{
			10000: "tcp",
			19001: "tcp",
		},
		Network: "noyra",
		Labels: map[string]string{
			"noyra.name": "noyra-envoy",
		},
		Mounts: []*protoAgent.ContainerMount{
			{
				Destination: "/config.yaml",
				Type:        "bind",
				Source:      configPath,
				Options:     []string{"rbind", "ro"},
			},
		},
		PortMappings: []*protoAgent.ContainerPortMapping{
			{
				ContainerPort: 10000,
				HostPort:      10000,
			},
			{
				ContainerPort: 19001,
				HostPort:      19001,
			},
		},
	}

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r, err := a.Direct.ContainerStart(timeoutCtx, startRequest)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Could not start container", slog.Any("error", err))
		os.Exit(1)
	}
	slog.LogAttrs(ctx, slog.LevelInfo, "Container start response", slog.String("status", r.Status))

}
