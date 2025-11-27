package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/samber/oops"

	"google.golang.org/grpc"

	"blackprism.org/noyra/internal/agent"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

type Service struct {
	nodeID         string
	agent          *agent.Agent
	containers     map[string]string
	versionCounter int64
	logger         *slog.Logger
}

func BuildDiscoveryService(ctx context.Context, nodeID string, agent *agent.Agent, logger *slog.Logger) *Service {
	ds := &Service{
		nodeID:     nodeID,
		agent:      agent,
		containers: make(map[string]string),
		logger:     logger,
	}

	// @TODO est ce que le ctx a une utilité ici ?
	ds.init(ctx)

	return ds
}

func (ds *Service) Run(ctx context.Context) error {
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	lis, errListen := net.Listen("tcp", ":18000")
	if errListen != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to listen",
			slog.Any("error", errListen))
		return errListen
	}

	go ds.eventListener(ctx)

	ds.logger.LogAttrs(ctx, slog.LevelInfo, "EDS server started",
		slog.Int("port", 18000))

	errChan := make(chan error)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			ds.logger.LogAttrs(
				ctx, slog.LevelError, "error starting server",
				slog.Any("error", err),
			)

			errChan <- err
		}
	}()

	var errFromChan error

	select {
	case <-ctx.Done():
		return closeDiscoveryService(lis, errFromChan)
	case errFromChan = <-errChan:
		return closeDiscoveryService(lis, errFromChan)
	}
}

func closeDiscoveryService(lis net.Listener, parentErr error) error {
	errListenClose := lis.Close()
	if errListenClose != nil {
		return oops.Wrapf(oops.Join(parentErr, errListenClose), "error shutdown discovery server")
	}
	return parentErr
}

func (ds *Service) init(ctx context.Context) {
	//containers, err := ds.agent.ContainerList(ctx, false, nil, nil)
	//
	//if err != nil {
	//	ds.logger.LogAttrs(ctx, slog.LevelError, "failed to list containers", slog.Any("error", err))
	//	return
	//}
	//
	//for _, container := range containers {
	//	if container.Labels["noyra.type"] == "http" {
	//	}
	//}

	// @TODO est ce que le ctx a une utilité ici ?
}

func (ds *Service) eventListener(ctx context.Context) error {
	//containerListenerResponseChan := make(chan component.ContainerListenerResponse, 1000)
	//err := ds.agent.ContainerListener(ctx, containerListenerResponseChan)
	err := errors.New("not implemented")

	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to listen for container events", slog.Any("error", err))
		return oops.Wrapf(err, "failed to listen for container events")
	}

	//for {
	//	select {
	//	case event := <-containerListenerResponseChan:
	//		if event.Action == "start" || event.Action == "create" {
	//			//containersID := []string{event.ID}
	//			//containersList, errList := ds.agent.ContainerList(ctx, false, containersID, nil)
	//			//
	//			//if errList != nil {
	//			//	ds.logger.LogAttrs(ctx, slog.LevelWarn, "failed to get container labels", slog.Any("error", errList))
	//			//	continue
	//			}
	//
	//			//container, ok := containersList[event.ID]
	//			//if !ok {
	//			//	continue
	//			//}
	//
	//			//ds.addCluster(container)
	//			//ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
	//			continue
	//		}
	//
	//		//if event.Action == "died" || event.Action == "stop" {
	//		//	ds.logger.LogAttrs(ctx, slog.LevelInfo, "DS Service Event received", slog.String("event", event.Action))
	//		//
	//		//	ds.removeCluster(event.ID)
	//		//	ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
	//		//}
	//
	//	case <-ctx.Done():
	//		return ctx.Err()
	//	}
	//}

	return nil
}

func (ds *Service) newVersion() string {
	if ds.versionCounter > math.MaxInt64-1 {
		ds.versionCounter = 0
	}

	v := atomic.AddInt64(&ds.versionCounter, 1)

	return time.Now().Format(time.RFC3339Nano) + "-" + fmt.Sprintf("%d", v)
}
