// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v6.30.0
// source: agent/agent.proto

package agent

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ContainerStartRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Image         string                 `protobuf:"bytes,1,opt,name=image,proto3" json:"image,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Labels        map[string]string      `protobuf:"bytes,3,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	ExposedPorts  map[uint32]string      `protobuf:"bytes,4,rep,name=exposed_ports,json=exposedPorts,proto3" json:"exposed_ports,omitempty" protobuf_key:"varint,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Network       string                 `protobuf:"bytes,5,opt,name=network,proto3" json:"network,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerStartRequest) Reset() {
	*x = ContainerStartRequest{}
	mi := &file_agent_agent_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerStartRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerStartRequest) ProtoMessage() {}

func (x *ContainerStartRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerStartRequest.ProtoReflect.Descriptor instead.
func (*ContainerStartRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{0}
}

func (x *ContainerStartRequest) GetImage() string {
	if x != nil {
		return x.Image
	}
	return ""
}

func (x *ContainerStartRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ContainerStartRequest) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *ContainerStartRequest) GetExposedPorts() map[uint32]string {
	if x != nil {
		return x.ExposedPorts
	}
	return nil
}

func (x *ContainerStartRequest) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

type ContainerStopRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ContainerId   string                 `protobuf:"bytes,1,opt,name=containerId,proto3" json:"containerId,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerStopRequest) Reset() {
	*x = ContainerStopRequest{}
	mi := &file_agent_agent_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerStopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerStopRequest) ProtoMessage() {}

func (x *ContainerStopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerStopRequest.ProtoReflect.Descriptor instead.
func (*ContainerStopRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{1}
}

func (x *ContainerStopRequest) GetContainerId() string {
	if x != nil {
		return x.ContainerId
	}
	return ""
}

type ContainerRemoveRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ContainerId   string                 `protobuf:"bytes,1,opt,name=containerId,proto3" json:"containerId,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerRemoveRequest) Reset() {
	*x = ContainerRemoveRequest{}
	mi := &file_agent_agent_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerRemoveRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerRemoveRequest) ProtoMessage() {}

func (x *ContainerRemoveRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerRemoveRequest.ProtoReflect.Descriptor instead.
func (*ContainerRemoveRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{2}
}

func (x *ContainerRemoveRequest) GetContainerId() string {
	if x != nil {
		return x.ContainerId
	}
	return ""
}

type ContainerInfoRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ContainerId   string                 `protobuf:"bytes,1,opt,name=containerId,proto3" json:"containerId,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerInfoRequest) Reset() {
	*x = ContainerInfoRequest{}
	mi := &file_agent_agent_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerInfoRequest) ProtoMessage() {}

func (x *ContainerInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerInfoRequest.ProtoReflect.Descriptor instead.
func (*ContainerInfoRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{3}
}

func (x *ContainerInfoRequest) GetContainerId() string {
	if x != nil {
		return x.ContainerId
	}
	return ""
}

type ContainerListRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ContainersId  []string               `protobuf:"bytes,1,rep,name=containersId,proto3" json:"containersId,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerListRequest) Reset() {
	*x = ContainerListRequest{}
	mi := &file_agent_agent_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerListRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerListRequest) ProtoMessage() {}

func (x *ContainerListRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerListRequest.ProtoReflect.Descriptor instead.
func (*ContainerListRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{4}
}

func (x *ContainerListRequest) GetContainersId() []string {
	if x != nil {
		return x.ContainersId
	}
	return nil
}

type ContainerListResponse struct {
	state         protoimpl.MessageState    `protogen:"open.v1"`
	Containers    map[string]*ContainerInfo `protobuf:"bytes,1,rep,name=containers,proto3" json:"containers,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerListResponse) Reset() {
	*x = ContainerListResponse{}
	mi := &file_agent_agent_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerListResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerListResponse) ProtoMessage() {}

func (x *ContainerListResponse) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerListResponse.ProtoReflect.Descriptor instead.
func (*ContainerListResponse) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{5}
}

func (x *ContainerListResponse) GetContainers() map[string]*ContainerInfo {
	if x != nil {
		return x.Containers
	}
	return nil
}

type ContainerInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Labels        map[string]string      `protobuf:"bytes,3,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	IPAddress     string                 `protobuf:"bytes,4,opt,name=IPAddress,proto3" json:"IPAddress,omitempty"`
	ExposedPort   int32                  `protobuf:"varint,5,opt,name=exposedPort,proto3" json:"exposedPort,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerInfo) Reset() {
	*x = ContainerInfo{}
	mi := &file_agent_agent_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerInfo) ProtoMessage() {}

func (x *ContainerInfo) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerInfo.ProtoReflect.Descriptor instead.
func (*ContainerInfo) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{6}
}

func (x *ContainerInfo) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ContainerInfo) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ContainerInfo) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *ContainerInfo) GetIPAddress() string {
	if x != nil {
		return x.IPAddress
	}
	return ""
}

func (x *ContainerInfo) GetExposedPort() int32 {
	if x != nil {
		return x.ExposedPort
	}
	return 0
}

type ContainerListenerRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerListenerRequest) Reset() {
	*x = ContainerListenerRequest{}
	mi := &file_agent_agent_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerListenerRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerListenerRequest) ProtoMessage() {}

func (x *ContainerListenerRequest) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerListenerRequest.ProtoReflect.Descriptor instead.
func (*ContainerListenerRequest) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{7}
}

type ContainerEvent struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Action        string                 `protobuf:"bytes,2,opt,name=action,proto3" json:"action,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContainerEvent) Reset() {
	*x = ContainerEvent{}
	mi := &file_agent_agent_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContainerEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerEvent) ProtoMessage() {}

func (x *ContainerEvent) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerEvent.ProtoReflect.Descriptor instead.
func (*ContainerEvent) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{8}
}

func (x *ContainerEvent) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ContainerEvent) GetAction() string {
	if x != nil {
		return x.Action
	}
	return ""
}

type Response struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        string                 `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	Message       string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Response) Reset() {
	*x = Response{}
	mi := &file_agent_agent_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_agent_agent_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_agent_agent_proto_rawDescGZIP(), []int{9}
}

func (x *Response) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *Response) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_agent_agent_proto protoreflect.FileDescriptor

var file_agent_agent_proto_rawDesc = string([]byte{
	0x0a, 0x11, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x22, 0xee, 0x02, 0x0a, 0x15, 0x43,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x40,
	0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x53, 0x74, 0x61, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4c, 0x61, 0x62,
	0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x12, 0x53, 0x0a, 0x0d, 0x65, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x5f, 0x70, 0x6f, 0x72, 0x74,
	0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x45, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x50, 0x6f, 0x72,
	0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0c, 0x65, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64,
	0x50, 0x6f, 0x72, 0x74, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x1a,
	0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3f, 0x0a, 0x11, 0x45, 0x78,
	0x70, 0x6f, 0x73, 0x65, 0x64, 0x50, 0x6f, 0x72, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x38, 0x0a, 0x14, 0x43,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x49, 0x64, 0x22, 0x3a, 0x0a, 0x16, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49,
	0x64, 0x22, 0x38, 0x0a, 0x14, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x64, 0x22, 0x3a, 0x0a, 0x14, 0x43,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x73, 0x49, 0x64, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x73, 0x49, 0x64, 0x22, 0xba, 0x01, 0x0a, 0x15, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x4c, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f,
	0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x1a,
	0x53, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x22, 0xe8, 0x01, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x06, 0x6c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f,
	0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61,
	0x62, 0x65, 0x6c, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x65, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x50, 0x6f, 0x72,
	0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x65, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64,
	0x50, 0x6f, 0x72, 0x74, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22,
	0x1a, 0x0a, 0x18, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x38, 0x0a, 0x0e, 0x43,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16, 0x0a,
	0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x3c, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x32, 0xef, 0x02, 0x0a, 0x05, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x41, 0x0a,
	0x0e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12,
	0x1c, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
	0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0f, 0x2e,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x12, 0x3f, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x53, 0x74, 0x6f,
	0x70, 0x12, 0x1b, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0f,
	0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x12, 0x43, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65,
	0x6d, 0x6f, 0x76, 0x65, 0x12, 0x1d, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x0f, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4c, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1b, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x4f, 0x0a, 0x11, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
	0x72, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x12, 0x1f, 0x2e, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x65,
	0x6e, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x15, 0x2e, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x22, 0x00, 0x30, 0x01, 0x42, 0x27, 0x5a, 0x25, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0x70, 0x72,
	0x69, 0x73, 0x6d, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x6e, 0x6f, 0x79, 0x72, 0x61, 0x2f, 0x67, 0x72,
	0x70, 0x63, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_agent_agent_proto_rawDescOnce sync.Once
	file_agent_agent_proto_rawDescData []byte
)

func file_agent_agent_proto_rawDescGZIP() []byte {
	file_agent_agent_proto_rawDescOnce.Do(func() {
		file_agent_agent_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_agent_agent_proto_rawDesc), len(file_agent_agent_proto_rawDesc)))
	})
	return file_agent_agent_proto_rawDescData
}

var file_agent_agent_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_agent_agent_proto_goTypes = []any{
	(*ContainerStartRequest)(nil),    // 0: agent.ContainerStartRequest
	(*ContainerStopRequest)(nil),     // 1: agent.ContainerStopRequest
	(*ContainerRemoveRequest)(nil),   // 2: agent.ContainerRemoveRequest
	(*ContainerInfoRequest)(nil),     // 3: agent.ContainerInfoRequest
	(*ContainerListRequest)(nil),     // 4: agent.ContainerListRequest
	(*ContainerListResponse)(nil),    // 5: agent.ContainerListResponse
	(*ContainerInfo)(nil),            // 6: agent.ContainerInfo
	(*ContainerListenerRequest)(nil), // 7: agent.ContainerListenerRequest
	(*ContainerEvent)(nil),           // 8: agent.ContainerEvent
	(*Response)(nil),                 // 9: agent.Response
	nil,                              // 10: agent.ContainerStartRequest.LabelsEntry
	nil,                              // 11: agent.ContainerStartRequest.ExposedPortsEntry
	nil,                              // 12: agent.ContainerListResponse.ContainersEntry
	nil,                              // 13: agent.ContainerInfo.LabelsEntry
}
var file_agent_agent_proto_depIdxs = []int32{
	10, // 0: agent.ContainerStartRequest.labels:type_name -> agent.ContainerStartRequest.LabelsEntry
	11, // 1: agent.ContainerStartRequest.exposed_ports:type_name -> agent.ContainerStartRequest.ExposedPortsEntry
	12, // 2: agent.ContainerListResponse.containers:type_name -> agent.ContainerListResponse.ContainersEntry
	13, // 3: agent.ContainerInfo.labels:type_name -> agent.ContainerInfo.LabelsEntry
	6,  // 4: agent.ContainerListResponse.ContainersEntry.value:type_name -> agent.ContainerInfo
	0,  // 5: agent.Agent.ContainerStart:input_type -> agent.ContainerStartRequest
	1,  // 6: agent.Agent.ContainerStop:input_type -> agent.ContainerStopRequest
	2,  // 7: agent.Agent.ContainerRemove:input_type -> agent.ContainerRemoveRequest
	4,  // 8: agent.Agent.ContainerList:input_type -> agent.ContainerListRequest
	7,  // 9: agent.Agent.ContainerListener:input_type -> agent.ContainerListenerRequest
	9,  // 10: agent.Agent.ContainerStart:output_type -> agent.Response
	9,  // 11: agent.Agent.ContainerStop:output_type -> agent.Response
	9,  // 12: agent.Agent.ContainerRemove:output_type -> agent.Response
	5,  // 13: agent.Agent.ContainerList:output_type -> agent.ContainerListResponse
	8,  // 14: agent.Agent.ContainerListener:output_type -> agent.ContainerEvent
	10, // [10:15] is the sub-list for method output_type
	5,  // [5:10] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_agent_agent_proto_init() }
func file_agent_agent_proto_init() {
	if File_agent_agent_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_agent_agent_proto_rawDesc), len(file_agent_agent_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_agent_agent_proto_goTypes,
		DependencyIndexes: file_agent_agent_proto_depIdxs,
		MessageInfos:      file_agent_agent_proto_msgTypes,
	}.Build()
	File_agent_agent_proto = out.File
	file_agent_agent_proto_goTypes = nil
	file_agent_agent_proto_depIdxs = nil
}
