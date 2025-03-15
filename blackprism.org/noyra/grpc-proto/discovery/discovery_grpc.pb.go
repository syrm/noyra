// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: grpc-proto/discovery/discovery.proto

package discovery

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	DiscoveryService_StreamClusters_FullMethodName            = "/discovery.DiscoveryService/StreamClusters"
	DiscoveryService_StreamListeners_FullMethodName           = "/discovery.DiscoveryService/StreamListeners"
	DiscoveryService_StreamRoutes_FullMethodName              = "/discovery.DiscoveryService/StreamRoutes"
	DiscoveryService_StreamEndpoints_FullMethodName           = "/discovery.DiscoveryService/StreamEndpoints"
	DiscoveryService_StreamAggregatedResources_FullMethodName = "/discovery.DiscoveryService/StreamAggregatedResources"
)

// DiscoveryServiceClient is the client API for DiscoveryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Service de découverte compatible avec Envoy xDS v3
type DiscoveryServiceClient interface {
	// Streaming pour les Clusters (CDS)
	StreamClusters(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error)
	// Streaming pour les Listeners (LDS)
	StreamListeners(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error)
	// Streaming pour les Routes (RDS)
	StreamRoutes(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error)
	// Streaming pour les Endpoints (EDS)
	StreamEndpoints(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error)
	// API agrégée pour tous les types de ressources
	StreamAggregatedResources(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error)
}

type discoveryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDiscoveryServiceClient(cc grpc.ClientConnInterface) DiscoveryServiceClient {
	return &discoveryServiceClient{cc}
}

func (c *discoveryServiceClient) StreamClusters(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &DiscoveryService_ServiceDesc.Streams[0], DiscoveryService_StreamClusters_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[DiscoveryRequest, DiscoveryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamClustersClient = grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse]

func (c *discoveryServiceClient) StreamListeners(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &DiscoveryService_ServiceDesc.Streams[1], DiscoveryService_StreamListeners_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[DiscoveryRequest, DiscoveryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamListenersClient = grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse]

func (c *discoveryServiceClient) StreamRoutes(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &DiscoveryService_ServiceDesc.Streams[2], DiscoveryService_StreamRoutes_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[DiscoveryRequest, DiscoveryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamRoutesClient = grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse]

func (c *discoveryServiceClient) StreamEndpoints(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &DiscoveryService_ServiceDesc.Streams[3], DiscoveryService_StreamEndpoints_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[DiscoveryRequest, DiscoveryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamEndpointsClient = grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse]

func (c *discoveryServiceClient) StreamAggregatedResources(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &DiscoveryService_ServiceDesc.Streams[4], DiscoveryService_StreamAggregatedResources_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[DiscoveryRequest, DiscoveryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamAggregatedResourcesClient = grpc.BidiStreamingClient[DiscoveryRequest, DiscoveryResponse]

// DiscoveryServiceServer is the server API for DiscoveryService service.
// All implementations must embed UnimplementedDiscoveryServiceServer
// for forward compatibility.
//
// Service de découverte compatible avec Envoy xDS v3
type DiscoveryServiceServer interface {
	// Streaming pour les Clusters (CDS)
	StreamClusters(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error
	// Streaming pour les Listeners (LDS)
	StreamListeners(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error
	// Streaming pour les Routes (RDS)
	StreamRoutes(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error
	// Streaming pour les Endpoints (EDS)
	StreamEndpoints(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error
	// API agrégée pour tous les types de ressources
	StreamAggregatedResources(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error
	mustEmbedUnimplementedDiscoveryServiceServer()
}

// UnimplementedDiscoveryServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedDiscoveryServiceServer struct{}

func (UnimplementedDiscoveryServiceServer) StreamClusters(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamClusters not implemented")
}
func (UnimplementedDiscoveryServiceServer) StreamListeners(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamListeners not implemented")
}
func (UnimplementedDiscoveryServiceServer) StreamRoutes(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamRoutes not implemented")
}
func (UnimplementedDiscoveryServiceServer) StreamEndpoints(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamEndpoints not implemented")
}
func (UnimplementedDiscoveryServiceServer) StreamAggregatedResources(grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamAggregatedResources not implemented")
}
func (UnimplementedDiscoveryServiceServer) mustEmbedUnimplementedDiscoveryServiceServer() {}
func (UnimplementedDiscoveryServiceServer) testEmbeddedByValue()                          {}

// UnsafeDiscoveryServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DiscoveryServiceServer will
// result in compilation errors.
type UnsafeDiscoveryServiceServer interface {
	mustEmbedUnimplementedDiscoveryServiceServer()
}

func RegisterDiscoveryServiceServer(s grpc.ServiceRegistrar, srv DiscoveryServiceServer) {
	// If the following call pancis, it indicates UnimplementedDiscoveryServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&DiscoveryService_ServiceDesc, srv)
}

func _DiscoveryService_StreamClusters_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DiscoveryServiceServer).StreamClusters(&grpc.GenericServerStream[DiscoveryRequest, DiscoveryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamClustersServer = grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]

func _DiscoveryService_StreamListeners_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DiscoveryServiceServer).StreamListeners(&grpc.GenericServerStream[DiscoveryRequest, DiscoveryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamListenersServer = grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]

func _DiscoveryService_StreamRoutes_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DiscoveryServiceServer).StreamRoutes(&grpc.GenericServerStream[DiscoveryRequest, DiscoveryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamRoutesServer = grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]

func _DiscoveryService_StreamEndpoints_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DiscoveryServiceServer).StreamEndpoints(&grpc.GenericServerStream[DiscoveryRequest, DiscoveryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamEndpointsServer = grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]

func _DiscoveryService_StreamAggregatedResources_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DiscoveryServiceServer).StreamAggregatedResources(&grpc.GenericServerStream[DiscoveryRequest, DiscoveryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type DiscoveryService_StreamAggregatedResourcesServer = grpc.BidiStreamingServer[DiscoveryRequest, DiscoveryResponse]

// DiscoveryService_ServiceDesc is the grpc.ServiceDesc for DiscoveryService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var DiscoveryService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "discovery.DiscoveryService",
	HandlerType: (*DiscoveryServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamClusters",
			Handler:       _DiscoveryService_StreamClusters_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamListeners",
			Handler:       _DiscoveryService_StreamListeners_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamRoutes",
			Handler:       _DiscoveryService_StreamRoutes_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamEndpoints",
			Handler:       _DiscoveryService_StreamEndpoints_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamAggregatedResources",
			Handler:       _DiscoveryService_StreamAggregatedResources_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "grpc-proto/discovery/discovery.proto",
}
