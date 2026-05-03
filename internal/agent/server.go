package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	protoAgent "blackprism.org/noyra/api/agent/v1"
	noyraGrpc "blackprism.org/noyra/internal/grpc"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1_000_000
)

type Option func(s *Server)

type Server struct {
	protoAgent.UnimplementedAgentServiceServer

	agent             *Agent
	grpcServer        *grpc.Server
	loggerInterceptor noyraGrpc.LoggerInterceptor
	logger            *slog.Logger
}

func BuildServer(agent *Agent, logger *slog.Logger, opts ...Option) *Server {
	s := &Server{
		agent:             agent,
		loggerInterceptor: noyraGrpc.BuildLogger(logger),
		logger:            logger,
	}

	s.grpcServer = grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: grpcKeepaliveMinTime,
		}),
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		// Logging centralisé ici — les handlers ne loguent rien eux-mêmes (single handling rule)
		grpc.ChainUnaryInterceptor(
			s.loggerInterceptor.LoggingUnaryInterceptor,
			s.loggerInterceptor.RecoveryUnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			s.loggerInterceptor.LoggingStreamInterceptor,
			s.loggerInterceptor.RecoveryStreamInterceptor,
		),
	)

	protoAgent.RegisterAgentServiceServer(s.grpcServer, s)
	// Health check obligatoire — Kubernetes readiness/liveness probes
	healthpb.RegisterHealthServer(s.grpcServer, health.NewServer())

	return s
}

func WithLoggerInterceptor(loggerInterceptor noyraGrpc.LoggerInterceptor) Option {
	return func(s *Server) {
		s.logger = loggerInterceptor.GetLogger()
		s.loggerInterceptor = loggerInterceptor
	}
}

func (s *Server) Run(ctx context.Context, port uint) error {
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("listen on :"+strconv.Itoa(int(port))+" : %w", err)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "grpc server listening", slog.String("address", lis.Addr().String()))

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("grpc server: %w", err)
	case <-ctx.Done():
		return nil
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	stopped := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		s.logger.LogAttrs(ctx, slog.LevelInfo, "grpc server stopped gracefully")
	case <-ctx.Done():
		s.logger.LogAttrs(ctx, slog.LevelWarn, "grpc graceful stop timed out, forcing stop")
		s.grpcServer.Stop()
	}
}

func (s *Server) ContainerStart(
	ctx context.Context,
	startRequest *protoAgent.ContainerStartRequest,
) (*protoAgent.ContainerStartResponse, error) {
	/*
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
	*/
	protoAgentResponse := &protoAgent.ContainerStartResponse{}

	//if errContainerStart != nil {
	//	protoAgentResponse.SetStatus("KO")
	//	return protoAgentResponse, errContainerStart
	//}

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
	//err := s.agent.ContainerRemove(ctx, containerID)
	err := errors.New("not implemented")

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
	containersList := s.agent.ListContainers(ctx, false, nil)
	containerInfoList := make(map[string]*protoAgent.ContainerInfo)

	for _, c := range containersList {
		containerInfo := &protoAgent.ContainerInfo{}
		containerInfo.SetId(c.ID)
		containerInfo.SetName(c.Name)
		containerInfo.SetLabels(c.Labels)
		containerInfo.SetState(c.State)

		containerInfoList[c.ID] = containerInfo
	}

	//protoAgentResponse.SetContainers(containerInfoList)

	//for _, c := range containersList {
	//	var exposedPort int32
	//	for key := range c.ExposedPort {
	//		exposedPort = int32(key)
	//		break
	//	}
	//
	//	var ipAddress string
	//	// @TODO interdit d'appeler podman ici
	//	inspectData, err := containers.Inspect(ctx, c.ID, &containers.InspectOptions{})
	//	if err == nil && inspectData.NetworkSettings != nil {
	//		for name, networkInspected := range inspectData.NetworkSettings.Networks {
	//			if name == "noyra" {
	//				ipAddress = networkInspected.IPAddress
	//				break
	//			}
	//		}
	//	}
	//
	//	containerInfo := &protoAgent.ContainerInfo{}
	//	containerInfo.SetId(c.ID)
	//	containerInfo.SetName(c.Name)
	//	containerInfo.SetLabels(c.Labels)
	//	containerInfo.SetExposedPort(exposedPort)
	//	containerInfo.SetIpAddress(ipAddress)
	//	containerInfo.SetState(c.State)
	//
	//	containerInfoList[c.ID] = containerInfo
	//}

	protoAgentResponse := &protoAgent.ContainerListResponse{}
	protoAgentResponse.SetContainers(containerInfoList)

	return protoAgentResponse, nil
}

func (s *Server) ContainerListener(
	in *protoAgent.ContainerListenerRequest,
	stream grpc.ServerStreamingServer[protoAgent.ContainerListenerResponse],
) error {

	//options := new(system.EventsOptions).WithStream(true)
	//options.WithFilters(map[string][]string{
	//	"type":  {"container"},
	//	"event": {"create", "start", "stop", "die"},
	//})
	//
	//containerListenerResponseChan := make(chan component.ContainerListenerResponse, 1000)
	//
	//go func() {
	//	err := s.agent.ContainerListener(stream.Context(), containerListenerResponseChan)
	//	if err != nil {
	//		s.logger.LogAttrs(stream.Context(), slog.LevelError, "error setting up events listener", slog.Any("error", err))
	//	}
	//}()

	//for {
	//	select {
	//	case event := <-containerListenerResponseChan:
	//		containerEvent := &protoAgent.ContainerListenerResponse{}
	//		containerEvent.SetId(event.ID)
	//		containerEvent.SetAction(event.Action)
	//
	//		if err := stream.Send(containerEvent); err != nil {
	//			slog.LogAttrs(stream.Context(), slog.LevelError, "error sending container event",
	//				slog.Any("error", err),
	//				slog.String("containerID", event.ID),
	//				slog.String("action", event.Action),
	//			)
	//			return err
	//		}
	//
	//		switch event.Action {
	//		case "create":
	//			slog.LogAttrs(stream.Context(), slog.LevelInfo, "container created", slog.String("containerId", event.ID))
	//		case "start":
	//			slog.LogAttrs(stream.Context(), slog.LevelInfo, "container started", slog.String("containerId", event.ID))
	//		case "stop":
	//			slog.LogAttrs(stream.Context(), slog.LevelInfo, "container stopped", slog.String("containerId", event.ID))
	//		case "die":
	//			slog.LogAttrs(stream.Context(), slog.LevelInfo, "container died", slog.String("containerId", event.ID))
	//		}
	//	case <-stream.Context().Done():
	//		return stream.Context().Err()
	//	}
	//}

	return nil
}
