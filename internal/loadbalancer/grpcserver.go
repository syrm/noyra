package loadbalancer

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/url"

	"google.golang.org/grpc/reflection"

	protoLoadbalancer "blackprism.org/noyra/api/loadbalancer/v1"
	"blackprism.org/noyra/internal/loadbalancer/component"

	"google.golang.org/grpc"
)

// @TODO le nom GrpcServer MEH
type GrpcServer struct {
	protoLoadbalancer.UnimplementedLoadbalancerServiceServer

	chanConfiguration chan<- component.Configuration
	logger            *slog.Logger
}

func BuildGrpcServer(chanConfiguration chan<- component.Configuration, logger *slog.Logger) *GrpcServer {
	g := &GrpcServer{
		chanConfiguration: chanConfiguration,
		logger:            logger,
	}

	return g
}

func (g *GrpcServer) Run(ctx context.Context) error {
	flag.Parse()

	server := grpc.NewServer()
	protoLoadbalancer.RegisterLoadbalancerServiceServer(server, g)
	reflection.Register(server)

	listener, err := net.Listen("tcp", ":7778")

	if err != nil {
		g.logger.LogAttrs(ctx, slog.LevelError, "failed to listen for agent service", slog.Any("error", err))
		return err
	}

	g.logger.LogAttrs(ctx, slog.LevelInfo, "server service listening", slog.Any("address", listener.Addr()))

	errChan := make(chan error)

	go func() {
		if err := server.Serve(listener); err != nil {
			g.logger.LogAttrs(ctx, slog.LevelError, "server service failed", slog.Any("error", err))
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err = <-errChan:
		return err
	}
}

func (g *GrpcServer) UpdateConfig(
	ctx context.Context,
	updateConfigRequest *protoLoadbalancer.UpdateConfigRequest,
) (*protoLoadbalancer.UpdateConfigResponse, error) {

	config := component.Configuration{}

	for _, h := range updateConfigRequest.GetHosts() {
		hostURL, errHost := url.Parse(h.GetHost())

		if errHost != nil {
			response := &protoLoadbalancer.UpdateConfigResponse{}
			response.SetStatus("KO")
			response.SetMessage("Unable to parse host " + h.GetHost())
			return response, nil
		}

		targets := make([]url.URL, 0, len(h.GetTargets()))

		for _, t := range h.GetTargets() {
			targetURL, errTarget := url.Parse(t)
			if errTarget != nil {
				response := &protoLoadbalancer.UpdateConfigResponse{}
				response.SetStatus("KO")
				response.SetMessage("Unable to parse target " + t)
				return response, nil
			}

			targets = append(targets, *targetURL)
		}

		config.Hosts = append(config.Hosts, component.Host{
			Host:    *hostURL,
			Targets: targets,
		})
	}

	g.chanConfiguration <- config

	response := &protoLoadbalancer.UpdateConfigResponse{}
	response.SetStatus("OK")

	return response, nil
}
