package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
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
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/samber/oops"
)

// @TODO le nom Agent on garde ?
type Agent struct {
	podmanContext context.Context
	logger        *slog.Logger
}

func BuildAgent(podmanContext context.Context, logger *slog.Logger) *Agent {
	a := &Agent{
		podmanContext: podmanContext,
		logger:        logger,
	}

	return a
}

func (a *Agent) ListContainer(ctx context.Context, filters map[string]map[string]string) []component.Container {
	podmanFilters := make(map[string][]string)

	for filterKey, filterValue := range filters {
		podmanFilters[filterKey] = make([]string, 0, len(filterValue))
		for k, v := range filterValue {
			podmanFilters[filterKey] = append(podmanFilters[filterKey], fmt.Sprintf("%s=%s", k, v))
		}
	}

	podmanContainers, err := containers.List(a.podmanContext, &containers.ListOptions{Filters: podmanFilters})
	if err != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "error listing containers", slog.Any("error", err))
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
		inspectData, err := containers.Inspect(a.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, networkInspected := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = networkInspected.IPAddress
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

func (a *Agent) ContainerResume(ctx context.Context, containerIDorName string) error {

	errStart := containers.Start(a.podmanContext, containerIDorName, &containers.StartOptions{})
	if errStart != nil {
		return errStart
	}

	a.logger.LogAttrs(ctx, slog.LevelInfo, "container resumed", slog.String("id", containerIDorName))

	return nil
}

func (a *Agent) ContainerStart(ctx context.Context, containerRequest component.ContainerRequest) error {
	errPull := a.pullImage(ctx, containerRequest.Image)

	if errPull != nil {
		return errPull
	}

	if err := a.createNetwork(ctx); err != nil {
		return err
	}

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range containerRequest.ExposedPorts {
		if i > math.MaxUint16 {
			continue
		}

		exposedPorts[uint16(i)] = exposedPort
	}

	mounts := make([]spec.Mount, 0, len(containerRequest.Mounts))
	a.logger.LogAttrs(ctx, slog.LevelDebug, "initializing mounts", slog.Any("mounts", mounts))
	for _, m := range containerRequest.Mounts {
		mounts = append(mounts, spec.Mount{
			Destination: m.Destination,
			Source:      m.Source,
			Type:        m.Type,
			Options:     m.Options,
		})
	}

	volumes := make([]*specgen.NamedVolume, 0, len(containerRequest.Volumes))
	for _, v := range containerRequest.Volumes {
		volumes = append(volumes, &specgen.NamedVolume{
			Name:    v.Source,
			Dest:    v.Destination,
			Options: v.Options,
		})
	}

	portMappings := make([]nettypes.PortMapping, 0, len(containerRequest.PortMappings))
	for _, p := range containerRequest.PortMappings {
		containerPort := p.ContainerPort
		hostPort := p.HostPort
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
			Name:    containerRequest.Name,
			Labels:  containerRequest.Labels,
			Command: containerRequest.Commands,
			Env:     containerRequest.Env,
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image:   containerRequest.Image,
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

	response, errList := containers.CreateWithSpec(a.podmanContext, &containerSpec, nil)

	if errList != nil {
		return errList
	}

	containerID := response.ID
	a.logger.LogAttrs(ctx, slog.LevelInfo, "container created", slog.String("id", containerID))

	errStart := containers.Start(a.podmanContext, containerID, &containers.StartOptions{})
	if errStart != nil {
		return errStart
	}

	return nil
}

func (a *Agent) createNetwork(ctx context.Context) error {
	networkExists := false
	networks, errList := network.List(a.podmanContext, &network.ListOptions{Filters: map[string][]string{"name": {"noyra"}}})
	if errList != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "error checking networks", slog.Any("error", errList))
		return fmt.Errorf("error checking networks: %w", errList)
	}

	if len(networks) == 1 {
		noyraNetwork := networks[0]
		networkExists = true
		if noyraNetwork.Driver != "bridge" {
			a.logger.LogAttrs(
				ctx,
				slog.LevelWarn,
				"network noyra exists but is not configured in bridge mode",
				slog.String("currentDriver", noyraNetwork.Driver),
			)
			_, errRemove := network.Remove(a.podmanContext, "noyra", &network.RemoveOptions{})
			if errRemove != nil {
				return fmt.Errorf("unable to remove non-bridge noyra network: %w", errRemove)
			}
			networkExists = false
		}
	}

	if !networkExists {
		networkCreate, err := network.Create(a.podmanContext, &nettypes.Network{
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
			a.logger.LogAttrs(ctx, slog.LevelError, "error creating noyra network", slog.Any("error", err))
			return fmt.Errorf("error creating noyra network: %w", err)
		}

		a.logger.LogAttrs(ctx, slog.LevelInfo, "noyra network created successfully", slog.Any("network", networkCreate))
	}

	return nil
}

func (a *Agent) ContainerStop(ctx context.Context, containerIDorName string) error {
	err := containers.Stop(a.podmanContext, containerIDorName, &containers.StopOptions{})

	if err != nil {
		a.logger.LogAttrs(
			ctx,
			slog.LevelError, "error stopping container",
			slog.String("containerIDorName", containerIDorName),
			slog.Any("error", err),
		)
		return oops.With("containerIDorName", containerIDorName).Wrapf(err, "error stopping container")
	}

	slog.LogAttrs(
		ctx,
		slog.LevelInfo,
		"container stopped successfully",
		slog.String("containerIDorName", containerIDorName),
	)

	return nil
}

func (a *Agent) ContainerRemove(ctx context.Context, containerIDorName string) error {
	// @TODO volume shouldn't be removed
	force := true
	volumes := true
	removeOptions := &containers.RemoveOptions{
		Force:   &force,
		Volumes: &volumes,
	}

	response, err := containers.Remove(ctx, containerIDorName, removeOptions)

	if err != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "error removing container",
			slog.String("containerIDorName", containerIDorName),
			slog.Any("error", err))

		return oops.With("containerIDorName", containerIDorName).Wrapf(err, "error removing container")
	}

	a.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"container removed successfully",
		slog.String("containerIDorName", containerIDorName),
		slog.Any("response", response),
	)

	return nil
}

func (a *Agent) ContainerList(
	ctx context.Context,
	all bool,
	containersID []string,
	labels map[string]string,
) (map[string]component.Container, error) {
	filters := make(map[string][]string)

	if len(containersID) != 0 {
		filters["id"] = containersID
	}

	if len(labels) != 0 {
		var filtersLabels []string
		for key, value := range labels {
			filtersLabels = append(filtersLabels, key+"="+value)
		}

		filters["label"] = filtersLabels
	}

	podmanContainers, err := containers.List(a.podmanContext, &containers.ListOptions{All: &all, Filters: filters})
	if err != nil {
		a.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"error listing containers",
			slog.Any("error", err),
		)
		return nil, err
	}

	containersList := make(map[string]component.Container)

	for _, c := range podmanContainers {
		var exposedPort int32
		for key := range c.ExposedPorts {
			exposedPort = int32(key)
			break
		}

		var ipAddress string
		inspectData, err := containers.Inspect(a.podmanContext, c.ID, &containers.InspectOptions{})
		if err == nil && inspectData.NetworkSettings != nil {
			for name, networkInspected := range inspectData.NetworkSettings.Networks {
				if name == "noyra" {
					ipAddress = networkInspected.IPAddress
					break
				}
			}
		}

		containerInfo := component.Container{
			ID:          c.ID,
			Name:        c.Names[0],
			Labels:      c.Labels,
			ExposedPort: uint16(exposedPort),
			IPAddress:   ipAddress,
			State:       c.State,
		}

		containersList[c.ID] = containerInfo
	}

	return containersList, nil
}

func (a *Agent) ContainerListener(
	ctx context.Context,
	containerListenerResponseChan chan component.ContainerListenerResponse,
) error {

	options := new(system.EventsOptions).WithStream(true)
	options.WithFilters(map[string][]string{
		"type":  {"container"},
		"event": {"create", "start", "stop", "die"},
	})

	eventChannel := make(chan entities.Event, 1000)

	go func() {
		err := system.Events(a.podmanContext, eventChannel, nil, options)
		if err != nil {
			a.logger.LogAttrs(ctx, slog.LevelError, "error setting up events listener", slog.Any("error", err))
		}
	}()

	for {
		select {
		case event := <-eventChannel:
			if event.Type == "container" {
				containerEvent := component.ContainerListenerResponse{
					ID:     event.Actor.ID,
					Action: string(event.Action),
				}

				containerListenerResponseChan <- containerEvent

				switch event.Action {
				case "create":
					a.logger.LogAttrs(ctx, slog.LevelInfo, "container created", slog.String("containerId", event.Actor.ID))
				case "start":
					a.logger.LogAttrs(ctx, slog.LevelInfo, "container started", slog.String("containerId", event.Actor.ID))
				case "stop":
					a.logger.LogAttrs(ctx, slog.LevelInfo, "container stopped", slog.String("containerId", event.Actor.ID))
				case "die":
					a.logger.LogAttrs(ctx, slog.LevelInfo, "container died", slog.String("containerId", event.Actor.ID))
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (a *Agent) pullImage(ctx context.Context, imageName string) error {
	imagesList, errList := images.List(a.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {imageName},
	}})

	if errList != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "error listing image", slog.Any("error", errList))
		return oops.Wrapf(errList, "error listing image")
	}

	if len(imagesList) > 0 {
		a.logger.LogAttrs(ctx, slog.LevelInfo, "image already present", slog.String("image", imageName))
		return nil
	}

	quiet := true
	_, err := images.Pull(a.podmanContext, imageName, &images.PullOptions{Quiet: &quiet})

	if err != nil {
		a.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"error pulling image",
			slog.String("image", imageName),
			slog.Any("error", err),
		)
		return oops.With("image", imageName).Wrapf(err, "error pulling image")
	}

	return nil
}

func (a *Agent) StartNoyra(ctx context.Context) int {
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

	containersList := a.ListContainer(ctx, filters)

	// if err != nil {
	// 	a.logger.LogAttrs(ctx, slog.LevelError, "Error listing containers",
	// 		slog.Any("error", err))
	// }

	if len(containersList) > 0 {
		a.logger.LogAttrs(ctx, slog.LevelInfo, "noyra Envoy already running")
		return 0
	}

	configPath := "/mnt/data/src/go/noyra/config/envoy.yaml"

	containerMount := component.ContainerMount{}
	containerMount.Destination = "/config.yaml"
	containerMount.Type = "bind"
	containerMount.Source = configPath
	containerMount.Options = []string{"rbind", "ro"}

	containerPortMapping := component.ContainerPortMapping{}
	containerPortMapping.ContainerPort = 10000
	containerPortMapping.HostPort = 10000

	containerPortMapping2 := component.ContainerPortMapping{}
	containerPortMapping2.ContainerPort = 19001
	containerPortMapping2.HostPort = 19001

	containerRequest := component.ContainerRequest{}
	containerRequest.Image = "envoyproxy/envoy:distroless-v1.36-latest"
	containerRequest.Name = "noyra-envoy"
	containerRequest.Commands = []string{"-c", "/config.yaml", "--drain-time-a", "5"}
	containerRequest.ExposedPorts = map[uint32]string{
		10000: "tcp",
		19001: "tcp",
	}
	containerRequest.Network = "noyra"
	containerRequest.Labels = map[string]string{"noyra.name": "noyra-envoy"}
	containerRequest.Mounts = []component.ContainerMount{containerMount}
	containerRequest.PortMappings = []component.ContainerPortMapping{containerPortMapping, containerPortMapping2}

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err := a.ContainerStart(timeoutCtx, containerRequest)
	if err != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "could not start container", slog.Any("error", err))
		return 1
	}

	return 0
}
