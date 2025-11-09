package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/samber/oops"
	"google.golang.org/protobuf/types/known/structpb"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"blackprism.org/noyra/internal/agent"
	"blackprism.org/noyra/internal/agent/component"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

type Service struct {
	clusterCache   cache.SnapshotCache
	nodeID         string
	agent          *agent.Agent
	resources      map[string]map[resource.Type][]types.Resource
	containers     map[string]string
	versionCounter int64
	logger         *slog.Logger
}

func BuildDiscoveryService(ctx context.Context, nodeID string, agent *agent.Agent, logger *slog.Logger) *Service {
	ds := &Service{
		clusterCache: cache.NewSnapshotCache(false, cache.IDHash{}, nil),
		nodeID:       nodeID,
		agent:        agent,
		resources:    make(map[string]map[resource.Type][]types.Resource),
		containers:   make(map[string]string),
		logger:       logger,
	}

	// @TODO est ce que le ctx a une utilité ici ?
	ds.init(ctx)

	return ds
}

func (ds *Service) Run(ctx context.Context) {
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	lis, err := net.Listen("tcp", ":18000")
	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to listen",
			slog.Any("error", err))
		os.Exit(1)
	}

	xdsServer := server.NewServer(ctx, ds.clusterCache, server.CallbackFuncs{})
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, xdsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, xdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, xdsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, xdsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, xdsServer)

	go ds.eventListener(ctx)

	ds.logger.LogAttrs(ctx, slog.LevelInfo, "EDS server started",
		slog.Int("port", 18000))

	if err := grpcServer.Serve(lis); err != nil {
		ds.logger.LogAttrs(
			ctx, slog.LevelError, "error starting server",
			slog.Any("error", err),
		)
		os.Exit(1)
	}
}

func (ds *Service) SetSnapshot(ctx context.Context, resources map[resource.Type][]types.Resource) bool {
	snapshot, err := cache.NewSnapshot(ds.newVersion(), resources)

	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to create snapshot", slog.Any("error", err))
		return false
	}

	err = ds.clusterCache.SetSnapshot(ctx, ds.nodeID, snapshot)

	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to set snapshot", slog.Any("error", err))
		return false
	}

	return true
}

func (ds *Service) init(ctx context.Context) {
	containers, err := ds.agent.ContainerList(ctx, nil, nil)

	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to list containers", slog.Any("error", err))
		return
	}

	for _, container := range containers {
		if container.Labels["noyra.type"] == "http" {
			ds.addCluster(container)
		}
	}

	// @TODO est ce que le ctx a une utilité ici ?
	ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
}

func (ds *Service) getResourcesForSnapshot() map[resource.Type][]types.Resource {
	resources := make(map[resource.Type][]types.Resource)

	for _, resource := range ds.resources {
		for resourceType, resourceList := range resource {
			resources[resourceType] = append(resources[resourceType], resourceList...)
		}
	}

	return resources
}

func (ds *Service) findIndexLbEndpointForContainer(clusterName string, containerID string) int {
	if ds.resources[clusterName] == nil {
		return -1
	}

	for index, lbEndPoint := range ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints {
		metadata := lbEndPoint.GetMetadata()

		metadataNoyra, ok := metadata.GetFilterMetadata()["org.blackprism.noyra.container"]

		if !ok {
			continue
		}

		if metadataNoyra.GetFields()["id"].GetStringValue() == containerID {
			return index
		}
	}

	return -1
}

func (ds *Service) addCluster(container component.Container) {
	clusterName, ok := container.Labels["noyra.cluster"]

	if !ok {
		clusterName = container.Name
	}

	containerIndex := ds.findIndexLbEndpointForContainer(clusterName, container.ID)

	if containerIndex > -1 {
		return
	}

	ds.logger.LogAttrs(context.Background(), slog.LevelInfo, "add Cluster", slog.String("container_id", container.ID))

	ds.containers[container.ID] = clusterName

	if ds.resources[clusterName] != nil {
		ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints = append(ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints, ds.addEndpoint(container))
		return
	}

	clusterDomain, ok := container.Labels["noyra.domain"]

	if !ok {
		clusterDomain = container.Name
	}

	resources := make(map[resource.Type][]types.Resource)
	loadAssignment := ds.makeEndpointConfig(clusterName, []*endpoint.LbEndpoint{ds.addEndpoint(container)})
	resources[resource.ListenerType] = append(resources[resource.ListenerType], ds.makeListenerConfig(container.Name))
	resources[resource.RouteType] = append(resources[resource.RouteType], ds.makeRouteConfig(clusterName, clusterDomain, container.Name))
	resources[resource.ClusterType] = append(resources[resource.ClusterType], ds.makeClusterConfig(clusterName, loadAssignment))

	ds.resources[clusterName] = resources
}

func (ds *Service) removeCluster(containerID string) {
	clusterName, ok := ds.containers[containerID]

	if !ok {
		return
	}

	delete(ds.containers, containerID)

	containerIndex := ds.findIndexLbEndpointForContainer(clusterName, containerID)

	if containerIndex == -1 {
		return
	}

	lbEndpoints := ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints

	ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints = append(lbEndpoints[:containerIndex], lbEndpoints[containerIndex+1:]...)
}

func (ds *Service) makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

func (ds *Service) makeListenerConfig(name string) *listener.Listener {
	routerConfig, _ := anypb.New(&router.Router{})

	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    ds.makeConfigSource(),
				RouteConfigName: name,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: "http-router",
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: routerConfig,
			},
		}},
	}

	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: name,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 10000, // @TODO voir si on peut le changer, ou mettre 80 sans être root
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: "http-connection-manager",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}

func (ds *Service) makeRouteConfig(clusterName string, clusterDomain string, name string) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name: name,
		VirtualHosts: []*route.VirtualHost{{
			Name:    name,
			Domains: []string{clusterDomain + ":10000"}, // @TODO voir pour un port configurable
			Routes: []*route.Route{{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/", // @TODO voir pour un path configurable via les labels
					},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: clusterName,
						},
						// HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
						// 	HostRewriteLiteral: "yoloooooo",
						// },
					},
				},
			}},
		}},
	}
}

func (ds *Service) makeClusterConfig(name string, loadAssignment *endpoint.ClusterLoadAssignment) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(250 * time.Millisecond), // @TODO voir pour un timeout configurable
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       loadAssignment,
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func (ds *Service) makeEndpointConfig(clusterName string, endpoints []*endpoint.LbEndpoint) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{
			{ // @TODO on va utiliser ca a un moment
				LbEndpoints: endpoints,
			},
		},
	}
}

func (ds *Service) addEndpoint(container component.Container) *endpoint.LbEndpoint {
	return &endpoint.LbEndpoint{
		Metadata: &core.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				"org.blackprism.noyra.container": {
					Fields: map[string]*structpb.Value{
						"id": structpb.NewStringValue(container.ID),
					},
				},
			},
		},
		HostIdentifier: &endpoint.LbEndpoint_Endpoint{
			Endpoint: &endpoint.Endpoint{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Address: container.IPAddress,
							PortSpecifier: &core.SocketAddress_PortValue{
								PortValue: uint32(container.ExposedPort),
							},
						},
					},
				},
			},
		},
	}
}

func (ds *Service) eventListener(ctx context.Context) error {
	containerListenerResponseChan := make(chan component.ContainerListenerResponse, 1000)
	err := ds.agent.ContainerListener(ctx, containerListenerResponseChan)

	if err != nil {
		ds.logger.LogAttrs(ctx, slog.LevelError, "failed to listen for container events", slog.Any("error", err))
		return oops.Wrapf(err, "failed to listen for container events")
	}

	for {
		select {
		case event := <-containerListenerResponseChan:
			if event.Action == "start" || event.Action == "create" {
				containersID := []string{event.ID}
				containersList, errList := ds.agent.ContainerList(ctx, containersID, nil)

				if errList != nil {
					ds.logger.LogAttrs(ctx, slog.LevelWarn, "failed to get container labels", slog.Any("error", errList))
					continue
				}

				container, ok := containersList[event.ID]
				if !ok {
					continue
				}

				ds.addCluster(container)
				ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
				continue
			}

			if event.Action == "died" || event.Action == "stop" {
				ds.logger.LogAttrs(ctx, slog.LevelInfo, "DS Service Event received", slog.String("event", event.Action))

				ds.removeCluster(event.ID)
				ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (ds *Service) newVersion() string {
	if ds.versionCounter > math.MaxInt64-1 {
		ds.versionCounter = 0
	}

	v := atomic.AddInt64(&ds.versionCounter, 1)

	return time.Now().Format(time.RFC3339Nano) + "-" + fmt.Sprintf("%d", v)
}
