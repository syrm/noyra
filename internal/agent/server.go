package agent

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"time"

	protoAgent "blackprism.org/noyra/api/agent/v1"
	"blackprism.org/noyra/internal/agent/component"

	nettypes "github.com/containers/common/libnetwork/types"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/images"
	"github.com/containers/podman/v5/pkg/bindings/network"
	"github.com/containers/podman/v5/pkg/bindings/system"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/containers/podman/v5/pkg/specgen"
	"github.com/fullstorydev/grpchan/inprocgrpc"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/samber/oops"
	"google.golang.org/grpc"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

// @TODO le nom Server MEH
type Server struct {
	protoAgent.UnimplementedAgentServiceServer

	podmanContext context.Context
	serverMux     *http.ServeMux
	GrpcServer    *grpc.Server
	Direct        protoAgent.AgentServiceClient
}

func BuildServer(podmanContext context.Context) *Server {
	a := &Server{
		podmanContext: podmanContext,
		serverMux:     http.NewServeMux(),
	}

	channel := &inprocgrpc.Channel{}
	a.GrpcServer = grpc.NewServer()

	//protoAgent.RegisterAgentServiceServer(a.GrpcServer, a)
	channel.RegisterService(&protoAgent.AgentService_ServiceDesc, a)

	a.Direct = protoAgent.NewAgentServiceClient(channel)

	return a
}

func (s *Server) Run(ctx context.Context) int {
	exitCode := s.initNoyra(ctx)

	if exitCode > 0 {
		return exitCode
	}

	flag.Parse()

	//s.serverMux.HandleFunc("/containers", s.ListContainer())
	//
	//server := &http.Server{
	//	Addr:    ":8686",
	//	Handler: s.serverMux,
	//}
	//
	//go server.ListenAndServe()

	listenAgent, err := net.Listen("tcp", ":4646")

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "failed to listen for agent service", slog.Any("error", err))
		return 1
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "server service listening", slog.Any("address", listenAgent.Addr()))

	if err := s.GrpcServer.Serve(listenAgent); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "server service failed", slog.Any("error", err))
		return 1
	}

	return 0
}

func (s *Server) ListContainer(ctx context.Context, filters map[string]map[string]string) []component.Container {
	podmanFilters := make(map[string][]string)

	for filterKey, filterValue := range filters {
		podmanFilters[filterKey] = make([]string, 0, len(filterValue))
		for k, v := range filterValue {
			podmanFilters[filterKey] = append(podmanFilters[filterKey], fmt.Sprintf("%s=%s", k, v))
		}
	}

	podmanContainers, err := containers.List(s.podmanContext, &containers.ListOptions{Filters: podmanFilters})
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error listing containers", slog.Any("error", err))
		return nil
	}

	containersList := make([]component.Container, 0)

	for _, c := range podmanContainers {
		var exposedPort uint16
		for key := range c.ExposedPorts {
			exposedPort = key
			break
		}

		var ipAddress string
		inspectData, err := containers.Inspect(s.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, network := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = network.IPAddress
					break
				}
			}
		}

		containerInfo := component.Container{
			ID:          c.ID,
			Name:        c.Names[0],
			Labels:      c.Labels,
			IPAddress:   ipAddress,
			ExposedPort: exposedPort,
			State:       c.State,
		}

		containersList = append(containersList, containerInfo)
	}

	return containersList
}

func (s *Server) ContainerStart(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) (*protoAgent.ContainerStartResponse, error) {
	errPull := s.pullImage(ctx, startRequest)

	if errPull != nil {
		response := &protoAgent.ContainerStartResponse{}
		response.SetStatus("KO")
		return response, errPull
	}

	if err := s.createNetwork(ctx); err != nil {
		response := &protoAgent.ContainerStartResponse{}
		response.SetStatus("KO")
		return response, err
	}

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range startRequest.GetExposedPorts() {
		if i > math.MaxUint16 {
			continue
		}

		exposedPorts[uint16(i)] = exposedPort
	}

	mounts := make([]spec.Mount, 0, len(startRequest.GetMounts()))
	slog.LogAttrs(ctx, slog.LevelDebug, "initializing mounts", slog.Any("mounts", mounts))
	for _, m := range startRequest.GetMounts() {
		mounts = append(mounts, spec.Mount{
			Destination: m.GetDestination(),
			Source:      m.GetSource(),
			Type:        m.GetType(),
			Options:     m.GetOptions(),
		})
	}

	volumes := make([]*specgen.NamedVolume, 0, len(startRequest.GetVolumes()))
	for _, v := range startRequest.GetVolumes() {
		volumes = append(volumes, &specgen.NamedVolume{
			Name:    v.GetSource(),
			Dest:    v.GetDestination(),
			Options: v.GetOptions(),
		})
	}

	portMappings := make([]nettypes.PortMapping, 0, len(startRequest.GetPortMappings()))
	for _, p := range startRequest.GetPortMappings() {
		containerPort := p.GetContainerPort()
		hostPort := p.GetHostPort()
		if containerPort > math.MaxUint16 || hostPort > math.MaxUint16 {
			continue
		}

		portMappings = append(portMappings, nettypes.PortMapping{
			ContainerPort: uint16(containerPort),
			HostPort:      uint16(hostPort),
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
			Env:     startRequest.GetEnv(),
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image:   startRequest.GetImage(),
			Volumes: volumes,
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

	response, errList := containers.CreateWithSpec(s.podmanContext, &containerSpec, nil)

	protoAgentResponse := &protoAgent.ContainerStartResponse{}

	if errList != nil {
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, errList
	}

	containerID := response.ID
	slog.LogAttrs(ctx, slog.LevelInfo, "container created", slog.String("id", containerID))

	errStart := containers.Start(s.podmanContext, containerID, &containers.StartOptions{})
	if errStart != nil {
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, errStart
	}

	protoAgentResponse.SetStatus("OK")

	return protoAgentResponse, nil
}

func (s *Server) createNetwork(ctx context.Context) error {
	networkExists := false
	networks, errList := network.List(s.podmanContext, &network.ListOptions{Filters: map[string][]string{"name": {"noyra"}}})
	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error checking networks", slog.Any("error", errList))
		return fmt.Errorf("error checking networks: %w", errList)
	}

	if len(networks) == 1 {
		noyraNetwork := networks[0]
		networkExists = true
		if noyraNetwork.Driver != "bridge" {
			slog.LogAttrs(
				ctx,
				slog.LevelWarn,
				"network noyra exists but is not configured in bridge mode",
				slog.String("currentDriver", noyraNetwork.Driver),
			)
			_, errRemove := network.Remove(s.podmanContext, "noyra", &network.RemoveOptions{})
			if errRemove != nil {
				return fmt.Errorf("unable to remove non-bridge noyra network: %w", errRemove)
			}
			networkExists = false
		}
	}

	if !networkExists {
		networkCreate, err := network.Create(s.podmanContext, &nettypes.Network{
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
			slog.LogAttrs(ctx, slog.LevelError, "error creating noyra network", slog.Any("error", err))
			return fmt.Errorf("error creating noyra network: %w", err)
		}

		slog.LogAttrs(ctx, slog.LevelInfo, "noyra network created successfully", slog.Any("network", networkCreate))
	}

	return nil
}

func (s *Server) ContainerStop(ctx context.Context, stopRequest *protoAgent.ContainerStopRequest) (*protoAgent.ContainerStopResponse, error) {
	containerID := stopRequest.GetContainerId()

	stopOptions := &containers.StopOptions{}

	err := containers.Stop(s.podmanContext, containerID, stopOptions)

	protoAgentResponse := &protoAgent.ContainerStopResponse{}

	if err != nil {
		slog.LogAttrs(
			ctx,
			slog.LevelError, "error stopping container",
			slog.String("containerId", containerID),
			slog.Any("error", err),
		)
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, err
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "container stopped successfully", slog.String("containerId", containerID))
	protoAgentResponse.SetStatus("OK")
	return protoAgentResponse, nil
}

func (s *Server) ContainerRemove(ctx context.Context, removeRequest *protoAgent.ContainerRemoveRequest) (*protoAgent.ContainerRemoveResponse, error) {
	containerID := removeRequest.GetContainerId()

	force := true
	volumes := true
	removeOptions := &containers.RemoveOptions{
		Force:   &force,
		Volumes: &volumes,
	}

	response, err := containers.Remove(s.podmanContext, containerID, removeOptions)
	protoAgentResponse := &protoAgent.ContainerRemoveResponse{}

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error removing container",
			slog.String("containerId", containerID),
			slog.Any("error", err))
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, err
	}

	slog.LogAttrs(
		ctx,
		slog.LevelInfo,
		"container removed successfully",
		slog.String("containerId", containerID),
		slog.Any("response", response),
	)
	protoAgentResponse.SetStatus("OK")
	return protoAgentResponse, nil
}

func (s *Server) ContainerList(ctx context.Context, listRequest *protoAgent.ContainerListRequest) (*protoAgent.ContainerListResponse, error) {
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

	podmanContainers, err := containers.List(s.podmanContext, &containers.ListOptions{Filters: filters})
	if err != nil {
		slog.LogAttrs(
			ctx,
			slog.LevelError,
			"error listing containers",
			slog.Any("error", err),
		)
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
		inspectData, err := containers.Inspect(s.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, network := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = network.IPAddress
					break
				}
			}
		}

		containerInfo := &protoAgent.ContainerInfo{}
		containerInfo.SetId(c.ID)
		containerInfo.SetName(c.Names[0])
		containerInfo.SetLabels(c.Labels)
		containerInfo.SetExposedPort(exposedPort)
		containerInfo.SetIpAddress(ipAddress)
		containerInfo.SetState(c.State)

		containersList[c.ID] = containerInfo
	}

	containerListResponse := &protoAgent.ContainerListResponse{}
	containerListResponse.SetContainers(containersList)

	return containerListResponse, nil
}

func (s *Server) ContainerListener(in *protoAgent.ContainerListenerRequest, stream grpc.ServerStreamingServer[protoAgent.ContainerListenerResponse]) error {

	options := new(system.EventsOptions).WithStream(true)
	options.WithFilters(map[string][]string{
		"type":  {"container"},
		"event": {"create", "start", "stop", "die"},
	})

	eventChannel := make(chan entities.Event, 1000)

	go func() {
		err := system.Events(s.podmanContext, eventChannel, nil, options)
		if err != nil {
			slog.LogAttrs(stream.Context(), slog.LevelError, "error setting up events listener", slog.Any("error", err))
		}
	}()

	for {
		select {
		case event := <-eventChannel:
			if event.Type == "container" {
				containerEvent := &protoAgent.ContainerListenerResponse{}
				containerEvent.SetId(event.Actor.ID)
				containerEvent.SetAction(event.Status)

				if err := stream.Send(containerEvent); err != nil {
					slog.LogAttrs(stream.Context(), slog.LevelError, "error sending container event",
						slog.Any("error", err),
						slog.String("containerId", event.Actor.ID),
						slog.String("action", event.Status),
					)
					return err
				}

				switch event.Status {
				case "create":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "container created", slog.String("containerId", event.Actor.ID))
				case "start":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "container started", slog.String("containerId", event.Actor.ID))
				case "stop":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "container stopped", slog.String("containerId", event.Actor.ID))
				case "die":
					slog.LogAttrs(stream.Context(), slog.LevelInfo, "container died", slog.String("containerId", event.Actor.ID))
				}
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *Server) pullImage(ctx context.Context, startRequest *protoAgent.ContainerStartRequest) error {
	imagesList, errList := images.List(s.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {startRequest.GetImage()},
	}})

	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error listing image", slog.Any("error", errList))
		return oops.Wrapf(errList, "error listing image")
	}

	if len(imagesList) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "image already present", slog.String("image", startRequest.GetImage()))
		return nil
	}

	quiet := true
	_, err := images.Pull(s.podmanContext, startRequest.GetImage(), &images.PullOptions{Quiet: &quiet})

	if err != nil {
		slog.LogAttrs(
			ctx,
			slog.LevelError,
			"error pulling image",
			slog.String("image", startRequest.GetImage()),
			slog.Any("error", err),
		)
		return oops.With("image", startRequest.GetImage()).Wrapf(err, "error pulling image")
	}

	return nil
}

func (s *Server) initNoyra(ctx context.Context) int {
	containerListRequest := &protoAgent.ContainerListRequest{}
	containerListRequest.SetLabels(
		map[string]string{
			"noyra.name": "noyra-envoy",
		},
	)

	filters := make(map[string]map[string]string)
	filters["label"] = map[string]string{
		"noyra.name": "noyra-envoy",
	}

	containersList := s.ListContainer(ctx, filters)

	// if err != nil {
	// 	slog.LogAttrs(ctx, slog.LevelError, "Error listing containers",
	// 		slog.Any("error", err))
	// }

	if len(containersList) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "noyra Envoy already running")
		return 0
	}

	configPath := "/mnt/data/src/go/noyra/config/envoy.yaml"

	containerMount := &protoAgent.ContainerMount{}
	containerMount.SetDestination("/config.yaml")
	containerMount.SetType("bind")
	containerMount.SetSource(configPath)
	containerMount.SetOptions([]string{"rbind", "ro"})

	containerPortMapping := &protoAgent.ContainerPortMapping{}
	containerPortMapping.SetContainerPort(10000)
	containerPortMapping.SetHostPort(10000)

	containerPortMapping2 := &protoAgent.ContainerPortMapping{}
	containerPortMapping2.SetContainerPort(19001)
	containerPortMapping2.SetHostPort(19001)

	startRequest := &protoAgent.ContainerStartRequest{}
	startRequest.SetImage("envoyproxy/envoy:distroless-v1.33-latest")
	startRequest.SetName("noyra-envoy")
	startRequest.SetCommand([]string{"-c", "/config.yaml", "--drain-time-s", "5"})
	startRequest.SetExposedPorts(map[uint32]string{
		10000: "tcp",
		19001: "tcp",
	})
	startRequest.SetNetwork("noyra")
	startRequest.SetLabels(
		map[string]string{
			"noyra.name": "noyra-envoy",
		},
	)
	startRequest.SetMounts([]*protoAgent.ContainerMount{containerMount})
	startRequest.SetPortMappings([]*protoAgent.ContainerPortMapping{containerPortMapping, containerPortMapping2})

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r, err := s.Direct.ContainerStart(timeoutCtx, startRequest)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "could not start container", slog.Any("error", err))
		return 1
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "container start response", slog.String("status", r.GetStatus()))

	return 0
}
