package component

type ContainerRequest struct {
	Name         string
	Image        string
	Commands     []string
	Labels       map[string]string
	Env          map[string]string
	ExposedPorts map[uint32]string
	Network      string
	Mounts       []ContainerMount
	Volumes      []ContainerVolume
	PortMappings []ContainerPortMapping
	UserNS       bool
}

type ContainerMount struct {
	Destination string
	Source      string
	Type        string
	Options     []string
}

type ContainerVolume struct {
	Destination string
	Source      string
	Options     []string
}

type ContainerPortMapping struct {
	ContainerPort uint32
	HostPort      uint32
}
