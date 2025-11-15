package agent

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"time"

	protoAgent "blackprism.org/noyra/api/agent/v1"
	"blackprism.org/noyra/internal/agent/component"

	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/system"
	"github.com/fullstorydev/grpchan/inprocgrpc"
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

	agent      Agent
	serverMux  *http.ServeMux
	GrpcServer *grpc.Server
	logger     *slog.Logger
}

func BuildServer(agent Agent, logger *slog.Logger) *Server {
	a := &Server{
		agent:     agent,
		serverMux: http.NewServeMux(),
		logger:    logger,
	}

	channel := &inprocgrpc.Channel{}
	a.GrpcServer = grpc.NewServer()

	//protoAgent.RegisterAgentServiceServer(a.GrpcServer, a)
	channel.RegisterService(&protoAgent.AgentService_ServiceDesc, a)

	return a
}

func (s *Server) Run(ctx context.Context) int {
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
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to listen for agent service", slog.Any("error", err))
		return 1
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "server service listening", slog.Any("address", listenAgent.Addr()))

	if err := s.GrpcServer.Serve(listenAgent); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "server service failed", slog.Any("error", err))
		return 1
	}

	return 0
}

func (s *Server) ContainerStart(
	ctx context.Context,
	startRequest *protoAgent.ContainerStartRequest,
) (*protoAgent.ContainerStartResponse, error) {
	mounts := make([]component.ContainerMount, len(startRequest.GetMounts()))

	for i, m := range startRequest.GetMounts() {
		mounts[i] = component.ContainerMount{
			Destination: m.GetDestination(),
			Source:      m.GetSource(),
			Type:        m.GetType(),
			Options:     m.GetOptions(),
		}
	}

	volumes := make([]component.ContainerVolume, len(startRequest.GetVolumes()))
	for i, v := range startRequest.GetVolumes() {
		volumes[i] = component.ContainerVolume{
			Destination: v.GetDestination(),
			Source:      v.GetSource(),
			Options:     v.GetOptions(),
		}
	}

	portMappings := make([]component.ContainerPortMapping, len(startRequest.GetPortMappings()))
	for i, p := range startRequest.GetPortMappings() {
		portMappings[i] = component.ContainerPortMapping{
			ContainerPort: p.GetContainerPort(),
			HostPort:      p.GetHostPort(),
		}
	}

	errContainerStart := s.agent.ContainerStart(ctx, component.ContainerRequest{
		Name:         startRequest.GetName(),
		Image:        startRequest.GetImage(),
		Commands:     startRequest.GetCommand(),
		Labels:       startRequest.GetLabels(),
		Env:          startRequest.GetEnv(),
		ExposedPorts: startRequest.GetExposedPorts(),
		Network:      startRequest.GetNetwork(),
		Mounts:       mounts,
		Volumes:      volumes,
		PortMappings: portMappings,
	})

	protoAgentResponse := &protoAgent.ContainerStartResponse{}

	if errContainerStart != nil {
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, errContainerStart
	}

	protoAgentResponse.SetStatus("OK")

	return protoAgentResponse, nil
}

func (s *Server) ContainerStop(
	ctx context.Context,
	stopRequest *protoAgent.ContainerStopRequest,
) (*protoAgent.ContainerStopResponse, error) {
	containerID := stopRequest.GetContainerId()
	err := s.agent.ContainerStop(ctx, containerID)

	protoAgentResponse := &protoAgent.ContainerStopResponse{}

	if err != nil {
		s.logger.LogAttrs(
			ctx,
			slog.LevelError, "error stopping container",
			slog.String("containerId", containerID),
			slog.Any("error", err),
		)
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, err
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "container stopped successfully", slog.String("containerId", containerID))
	protoAgentResponse.SetStatus("OK")
	return protoAgentResponse, nil
}

func (s *Server) ContainerRemove(
	ctx context.Context,
	removeRequest *protoAgent.ContainerRemoveRequest,
) (*protoAgent.ContainerRemoveResponse, error) {
	containerID := removeRequest.GetContainerId()
	err := s.agent.ContainerRemove(ctx, containerID)

	protoAgentResponse := &protoAgent.ContainerRemoveResponse{}

	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error removing container",
			slog.String("containerId", containerID),
			slog.Any("error", err))
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, err
	}

	s.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"container removed successfully",
		slog.String("containerId", containerID),
	)
	protoAgentResponse.SetStatus("OK")
	return protoAgentResponse, nil
}

func (s *Server) ContainerList(
	ctx context.Context,
	listRequest *protoAgent.ContainerListRequest,
) (*protoAgent.ContainerListResponse, error) {
	containersList, err := s.agent.ContainerList(ctx, false, listRequest.GetContainersId(), listRequest.GetLabels())

	protoAgentResponse := &protoAgent.ContainerListResponse{}

	if err != nil {
		s.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"error listing containers",
			slog.Any("containersID", listRequest.GetContainersId()),
			slog.Any("labels", listRequest.GetLabels()),
			slog.Any("error", err),
		)
		protoAgentResponse.SetStatus("KO")
		return protoAgentResponse, err
	}

	containerInfoList := make(map[string]*protoAgent.ContainerInfo)

	for _, c := range containersList {
		var exposedPort int32
		for key := range c.ExposedPort {
			exposedPort = int32(key)
			break
		}

		var ipAddress string
		// @TODO interdit d'appeler podman ici
		inspectData, err := containers.Inspect(ctx, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, networkInspected := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = networkInspected.IPAddress
					break
				}
			}
		}

		containerInfo := &protoAgent.ContainerInfo{}
		containerInfo.SetId(c.ID)
		containerInfo.SetName(c.Name)
		containerInfo.SetLabels(c.Labels)
		containerInfo.SetExposedPort(exposedPort)
		containerInfo.SetIpAddress(ipAddress)
		containerInfo.SetState(c.State)

		containerInfoList[c.ID] = containerInfo
	}

	containerListResponse := &protoAgent.ContainerListResponse{}
	containerListResponse.SetContainers(containerInfoList)

	return containerListResponse, nil
}

func (s *Server) ContainerListener(
	in *protoAgent.ContainerListenerRequest,
	stream grpc.ServerStreamingServer[protoAgent.ContainerListenerResponse],
) error {

	options := new(system.EventsOptions).WithStream(true)
	options.WithFilters(map[string][]string{
		"type":  {"container"},
		"event": {"create", "start", "stop", "die"},
	})

	containerListenerResponseChan := make(chan component.ContainerListenerResponse, 1000)

	go func() {
		err := s.agent.ContainerListener(stream.Context(), containerListenerResponseChan)
		if err != nil {
			s.logger.LogAttrs(stream.Context(), slog.LevelError, "error setting up events listener", slog.Any("error", err))
		}
	}()

	for {
		select {
		case event := <-containerListenerResponseChan:
			containerEvent := &protoAgent.ContainerListenerResponse{}
			containerEvent.SetId(event.ID)
			containerEvent.SetAction(event.Action)

			if err := stream.Send(containerEvent); err != nil {
				slog.LogAttrs(stream.Context(), slog.LevelError, "error sending container event",
					slog.Any("error", err),
					slog.String("containerID", event.ID),
					slog.String("action", event.Action),
				)
				return err
			}

			switch event.Action {
			case "create":
				slog.LogAttrs(stream.Context(), slog.LevelInfo, "container created", slog.String("containerId", event.ID))
			case "start":
				slog.LogAttrs(stream.Context(), slog.LevelInfo, "container started", slog.String("containerId", event.ID))
			case "stop":
				slog.LogAttrs(stream.Context(), slog.LevelInfo, "container stopped", slog.String("containerId", event.ID))
			case "die":
				slog.LogAttrs(stream.Context(), slog.LevelInfo, "container died", slog.String("containerId", event.ID))
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}
