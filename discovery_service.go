package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"time"

	protoAgent "blackprism.org/noyra/grpc-proto/agent"

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
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type discoveryService struct {
	clusterCache cache.SnapshotCache
	nodeID       string
	agent        *agent
	resources    map[string]map[resource.Type][]types.Resource
}

func BuildDiscoveryService(ctx context.Context, nodeID string, agent *agent) *discoveryService {
	ds := &discoveryService{
		clusterCache: cache.NewSnapshotCache(false, cache.IDHash{}, nil),
		nodeID:       nodeID,
		agent:        agent,
		resources:    make(map[string]map[resource.Type][]types.Resource),
	}

	// @TODO est ce que le ctx a une utilité ici ?
	ds.init(ctx)

	return ds
}

func (ds *discoveryService) Run(ctx context.Context) {
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	lis, err := net.Listen("tcp", ":18000")
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to listen",
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

	slog.LogAttrs(ctx, slog.LevelInfo, "EDS server started",
		slog.Int("port", 18000))

	if err := grpcServer.Serve(lis); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error starting server",
			slog.Any("error", err))
		os.Exit(1)
	}
}

func (ds *discoveryService) SetSnapshot(ctx context.Context, resources map[resource.Type][]types.Resource) bool {
	snapshot, err := cache.NewSnapshot(ds.newVersion(), resources)

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to create snapshot", slog.Any("error", err))
		return false
	}

	err = ds.clusterCache.SetSnapshot(ctx, ds.nodeID, snapshot)

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to set snapshot", slog.Any("error", err))
		return false
	}

	return true
}

func (ds *discoveryService) init(ctx context.Context) {
	containers, err := ds.agent.ContainerList(ctx, &protoAgent.ContainerListRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to list containers", slog.Any("error", err))
		return
	}

	for _, container := range containers.Containers {
		if container.Labels["noyra.type"] == "http" {
			ds.addCluster(container)
		}
	}

	// @TODO est ce que le ctx a une utilité ici ?
	ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
}

func (ds *discoveryService) getResourcesForSnapshot() map[resource.Type][]types.Resource {
	resources := make(map[resource.Type][]types.Resource)

	for _, resource := range ds.resources {
		for resourceType, resourceList := range resource {
			resources[resourceType] = append(resources[resourceType], resourceList...)
		}
	}

	return resources
}

func (ds *discoveryService) addCluster(container *protoAgent.ContainerInfo) {
	clusterName, ok := container.Labels["noyra.cluster"]

	if !ok {
		clusterName = container.Name
	}

	if ds.resources[clusterName] != nil {
		ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints = append(ds.resources[clusterName][resource.ClusterType][0].(*cluster.Cluster).LoadAssignment.Endpoints[0].LbEndpoints, ds.addEndpoint(container.IPAddress, container.ExposedPort))
		return
	}

	clusterDomain, ok := container.Labels["noyra.domain"]

	if !ok {
		clusterDomain = container.Name
	}

	resources := make(map[resource.Type][]types.Resource)
	loadAssignment := ds.makeEndpointConfig(clusterName, []*endpoint.LbEndpoint{ds.addEndpoint(container.IPAddress, container.ExposedPort)})
	resources[resource.ListenerType] = append(resources[resource.ListenerType], ds.makeListenerConfig(container.Name))
	resources[resource.RouteType] = append(resources[resource.RouteType], ds.makeRouteConfig(clusterName, clusterDomain, container.Name))
	resources[resource.ClusterType] = append(resources[resource.ClusterType], ds.makeClusterConfig(clusterName, loadAssignment))

	ds.resources[clusterName] = resources
}

func (ds *discoveryService) makeConfigSource() *core.ConfigSource {
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

func (ds *discoveryService) makeListenerConfig(name string) *listener.Listener {
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

func (ds *discoveryService) makeRouteConfig(clusterName string, clusterDomain string, name string) *route.RouteConfiguration {
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

func (ds *discoveryService) makeClusterConfig(name string, loadAssignment *endpoint.ClusterLoadAssignment) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(250 * time.Millisecond), // @TODO voir pour un timeout configurable
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       loadAssignment,
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func (ds *discoveryService) makeEndpointConfig(clusterName string, endpoints []*endpoint.LbEndpoint) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{
			{ // @TODO on va utiliser ca a un moment
				LbEndpoints: endpoints,
			},
		},
	}
}

func (ds *discoveryService) addEndpoint(ipAddress string, port int32) *endpoint.LbEndpoint {
	return &endpoint.LbEndpoint{
		HostIdentifier: &endpoint.LbEndpoint_Endpoint{
			Endpoint: &endpoint.Endpoint{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Address: ipAddress,
							PortSpecifier: &core.SocketAddress_PortValue{
								PortValue: uint32(port),
							},
						},
					},
				},
			},
		},
	}
}

func (ds *discoveryService) eventListener(ctx context.Context) {
	stream, err := ds.agent.Direct.ContainerListener(ctx, &protoAgent.ContainerListenerRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Failed to listen for container events", slog.String("error", "stream is nil"))
		return
	}

	for {
		event, err := stream.Recv()

		if err != nil {
			slog.LogAttrs(ctx, slog.LevelWarn, "Failed to listen for container events", slog.Any("error", err))
			continue
		}

		if event.Action == "start" || event.Action == "create" {
			containersList, err := ds.agent.Direct.ContainerList(ctx, &protoAgent.ContainerListRequest{ContainersId: []string{event.Id}})

			if err != nil {
				slog.LogAttrs(ctx, slog.LevelWarn, "Failed to get container labels", slog.Any("error", err))
				continue
			}

			container, ok := containersList.GetContainers()[event.Id]
			if !ok {
				continue
			}

			ds.addCluster(container)
			ds.SetSnapshot(ctx, ds.getResourcesForSnapshot())
			continue
		}

		if event.Action == "die" || event.Action == "stop" {
			// @TODO a faire
			continue
		}
	}
}

func (ds *discoveryService) newVersion() string {
	uuidv7, err := uuid.NewV7()

	if err != nil {
		// @TODO a l'init pas grave, pas de collision possible, au runtime collision possible si c'est fréquent
		uuidv7 = uuid.UUID{}
	}

	return time.Now().Format(time.RFC3339Nano) + " " + uuidv7.String()
}
