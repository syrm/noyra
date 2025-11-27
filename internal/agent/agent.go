package agent

import (
	"context"
	"fmt"
	"log/slog"

	"blackprism.org/noyra/internal/podman"
	podmanComponent "blackprism.org/noyra/internal/podman/component"

	"github.com/samber/oops"
)

// @TODO le nom Agent on garde ?
type Agent struct {
	podmanClient *podman.Client
	logger       *slog.Logger
}

func BuildAgent(podmanClient *podman.Client, logger *slog.Logger) *Agent {
	a := &Agent{
		podmanClient: podmanClient,
		logger:       logger,
	}

	return a
}

func (a *Agent) InspectContainer(ctx context.Context, name string) (podmanComponent.ContainerInspected, error) {
	//errPull := a.podmanClient.PullImage(ctx, containerRequest.Image)
	//
	//if errPull != nil {
	//	return errPull
	//}
	//
	//if err := a.createNetwork(ctx); err != nil {
	//	return err
	//}
	//
	//containerID, errCreate := a.podmanClient.CreateContainer(ctx, containerRequest)
	//
	//if errCreate != nil {
	//	return errCreate
	//}

	a.logger.LogAttrs(ctx, slog.LevelInfo, "container started", slog.String("name", name))

	container, err := a.podmanClient.InspectContainer(ctx, name)
	if err != nil {
		return podmanComponent.ContainerInspected{}, err
	}

	return container, nil
}

func (a *Agent) ListContainers(ctx context.Context, all bool, filters map[string][]string) []podmanComponent.Container {
	podmanContainers, err := a.podmanClient.ListContainers(ctx, all, filters)
	if err != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "error listing containers", slog.Any("error", err))
		return nil
	}

	return podmanContainers

	//containersList := make([]component.ContainerRequest, 0)
	//
	//
	//for _, c := range podmanContainers {
	//	var exposedPort uint16
	//	for key := range c.ExposedPorts {
	//		exposedPort = key
	//		break
	//	}
	//
	//	var ipAddress string
	//	inspectData, err := containers.Inspect(a.podmanContext, c.ID, &containers.InspectOptions{})
	//	if err == nil && inspectData.NetworkSettings != nil {
	//		for name, networkInspected := range inspectData.NetworkSettings.Networks {
	//			if name == "noyra" {
	//				ipAddress = networkInspected.IPAddress
	//				break
	//			}
	//		}
	//	}
	//
	//	containerInfo := component.ContainerRequest{
	//		ID:          c.ID,
	//		Name:        c.Names[0],
	//		Labels:      c.Labels,
	//		IPAddress:   ipAddress,
	//		ExposedPort: exposedPort,
	//		State:       c.State,
	//	}
	//
	//	containersList = append(containersList, containerInfo)
	//}
	//
	//return containersList
}

//func (a *Agent) ContainerResume(ctx context.Context, containerIDorName string) error {
//
//	errStart := containers.Start(a.podmanContext, containerIDorName, &containers.StartOptions{})
//	if errStart != nil {
//		return errStart
//	}
//
//	a.logger.LogAttrs(ctx, slog.LevelInfo, "container resumed", slog.String("id", containerIDorName))
//
//	return nil
//}

func (a *Agent) ContainerCreate(ctx context.Context, containerRequest podmanComponent.ContainerRequest) (string, error) {
	//errPull := a.podmanClient.PullImage(ctx, containerRequest.Image)
	//
	//if errPull != nil {
	//	return errPull
	//}
	//
	//if err := a.createNetwork(ctx); err != nil {
	//	return err
	//}
	//
	//containerID, errCreate := a.podmanClient.CreateContainer(ctx, containerRequest)
	//
	//if errCreate != nil {
	//	return errCreate
	//}

	a.logger.LogAttrs(ctx, slog.LevelInfo, "container started", slog.String("name", containerRequest.Name))

	id, errStart := a.podmanClient.CreateContainer(ctx, containerRequest)
	if errStart != nil {
		return "", errStart
	}

	return id, nil
}

func (a *Agent) ContainerStart(ctx context.Context, name string) error {
	//errPull := a.podmanClient.PullImage(ctx, containerRequest.Image)
	//
	//if errPull != nil {
	//	return errPull
	//}
	//
	//if err := a.createNetwork(ctx); err != nil {
	//	return err
	//}
	//
	//containerID, errCreate := a.podmanClient.CreateContainer(ctx, containerRequest)
	//
	//if errCreate != nil {
	//	return errCreate
	//}

	a.logger.LogAttrs(ctx, slog.LevelInfo, "container started", slog.String("name", name))

	errStart := a.podmanClient.StartContainer(ctx, name)
	if errStart != nil {
		return errStart
	}

	return nil
}

func (a *Agent) createNetwork(ctx context.Context) error {
	networkExists := false
	networks, errList := a.podmanClient.ListNetworks(ctx, map[string][]string{"name": {"noyra"}})
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
			_, errRemove := a.podmanClient.RemoveNetwork(ctx, "noyra")
			if errRemove != nil {
				return fmt.Errorf("unable to remove non-bridge noyra network: %w", errRemove)
			}
			networkExists = false
		}
	}

	if !networkExists {
		err := a.podmanClient.CreateNetwork(ctx, podmanComponent.Network{
			Name:   "noyra",
			Driver: "bridge",
			Subnets: []podmanComponent.NetworkSubnet{
				{
					Subnet: "10.66.0.0/16",
				},
			},
		})

		if err != nil {
			a.logger.LogAttrs(ctx, slog.LevelError, "error creating noyra network", slog.Any("error", err))
			return fmt.Errorf("error creating noyra network: %w", err)
		}

		a.logger.LogAttrs(ctx, slog.LevelInfo, "noyra network created successfully", slog.Any("network", "noyra"))
	}

	return nil
}

func (a *Agent) ContainerStop(ctx context.Context, containerIDorName string) error {
	err := a.podmanClient.StopContainer(ctx, containerIDorName)
	//err := containers.Stop(a.podmanContext, containerIDorName, &containers.StopOptions{})

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
	// @TODO volume shouldn't be removed, or maybe
	//force := true
	//volumes := true
	//removeOptions := &containers.RemoveOptions{
	//	Force:   &force,
	//	Volumes: &volumes,
	//}

	err := a.podmanClient.RemoveContainer(ctx, containerIDorName)

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
	)

	return nil
}

//func (a *Agent) ContainerList(
//	ctx context.Context,
//	all bool,
//	containersID []string,
//	labels map[string]string,
//) (map[string]component.ContainerRequest, error) {
//	filters := make(map[string][]string)
//
//	if len(containersID) != 0 {
//		filters["id"] = containersID
//	}
//
//	if len(labels) != 0 {
//		var filtersLabels []string
//		for key, value := range labels {
//			filtersLabels = append(filtersLabels, key+"="+value)
//		}
//
//		filters["label"] = filtersLabels
//	}
//
//	podmanContainers, err := containers.List(a.podmanContext, &containers.ListOptions{All: &all, Filters: filters})
//	if err != nil {
//		a.logger.LogAttrs(
//			ctx,
//			slog.LevelError,
//			"error listing containers",
//			slog.Any("error", err),
//		)
//		return nil, err
//	}
//
//	containersList := make(map[string]component.ContainerRequest)
//
//	for _, c := range podmanContainers {
//		var exposedPort int32
//		for key := range c.ExposedPorts {
//			exposedPort = int32(key)
//			break
//		}
//
//		var ipAddress string
//		inspectData, err := containers.Inspect(a.podmanContext, c.ID, &containers.InspectOptions{})
//		if err == nil && inspectData.NetworkSettings != nil {
//			for name, networkInspected := range inspectData.NetworkSettings.Networks {
//				if name == "noyra" {
//					ipAddress = networkInspected.IPAddress
//					break
//				}
//			}
//		}
//
//		containerInfo := component.ContainerRequest{
//			ID:          c.ID,
//			Name:        c.Names[0],
//			Labels:      c.Labels,
//			ExposedPort: uint16(exposedPort),
//			IPAddress:   ipAddress,
//			State:       c.State,
//		}
//
//		containersList[c.ID] = containerInfo
//	}
//
//	return containersList, nil
//}

//func (a *Agent) ContainerListener(
//	ctx context.Context,
//	containerListenerResponseChan chan component.ContainerListenerResponse,
//) error {
//
//	options := new(system.EventsOptions).WithStream(true)
//	options.WithFilters(map[string][]string{
//		"type":  {"container"},
//		"event": {"create", "start", "stop", "die"},
//	})
//
//	eventChannel := make(chan entities.Event, 1000)
//
//	go func() {
//		err := system.Events(a.podmanContext, eventChannel, nil, options)
//		if err != nil {
//			a.logger.LogAttrs(ctx, slog.LevelError, "error setting up events listener", slog.Any("error", err))
//		}
//	}()
//
//	for {
//		select {
//		case event := <-eventChannel:
//			if event.Type == "container" {
//				containerEvent := component.ContainerListenerResponse{
//					ID:     event.Actor.ID,
//					Action: string(event.Action),
//				}
//
//				containerListenerResponseChan <- containerEvent
//
//				switch event.Action {
//				case "create":
//					a.logger.LogAttrs(ctx, slog.LevelInfo, "container created", slog.String("containerId", event.Actor.ID))
//				case "start":
//					a.logger.LogAttrs(ctx, slog.LevelInfo, "container started", slog.String("containerId", event.Actor.ID))
//				case "stop":
//					a.logger.LogAttrs(ctx, slog.LevelInfo, "container stopped", slog.String("containerId", event.Actor.ID))
//				case "die":
//					a.logger.LogAttrs(ctx, slog.LevelInfo, "container died", slog.String("containerId", event.Actor.ID))
//				}
//			}
//		case <-ctx.Done():
//			return ctx.Err()
//		}
//	}
//}

//func (a *Agent) pullImage(ctx context.Context, imageName string) error {
//	imagesList, errList := images.List(a.podmanContext, &images.ListOptions{Filters: map[string][]string{
//		"reference": {imageName},
//	}})
//
//	if errList != nil {
//		a.logger.LogAttrs(ctx, slog.LevelError, "error listing image", slog.Any("error", errList))
//		return oops.Wrapf(errList, "error listing image")
//	}
//
//	if len(imagesList) > 0 {
//		a.logger.LogAttrs(ctx, slog.LevelInfo, "image already present", slog.String("image", imageName))
//		return nil
//	}
//
//	quiet := true
//	_, err := images.Pull(a.podmanContext, imageName, &images.PullOptions{Quiet: &quiet})
//
//	if err != nil {
//		a.logger.LogAttrs(
//			ctx,
//			slog.LevelError,
//			"error pulling image",
//			slog.String("image", imageName),
//			slog.Any("error", err),
//		)
//		return oops.With("image", imageName).Wrapf(err, "error pulling image")
//	}
//
//	return nil
//}
