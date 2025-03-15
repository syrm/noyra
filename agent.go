package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	protoContainer "blackprism.org/noyra/grpc-proto/container"

	nettypes "github.com/containers/common/libnetwork/types"
	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/images"
	"github.com/containers/podman/v5/pkg/bindings/network"
	"github.com/containers/podman/v5/pkg/specgen"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

type containerServer struct {
	protoContainer.UnimplementedContainerServer

	podmanContext context.Context
}

func (cs *containerServer) Start(ctx context.Context, startRequest *protoContainer.StartRequest) (*protoContainer.Response, error) {

	cs.pullImage(ctx, startRequest)

	// Vérifier si le réseau noyra existe déjà
	networkExists := false
	networks, err := network.List(cs.podmanContext, &network.ListOptions{})
	if err != nil {
		log.Printf("Erreur lors de la vérification des réseaux: %v", err)
		return &protoContainer.Response{Status: "KO"}, fmt.Errorf("erreur lors de la vérification des réseaux: %v", err)
	}

	for _, net := range networks {
		if net.Name == "noyra" {
			networkExists = true
			// Vérifier que le réseau est bien en mode bridge
			if net.Driver != "bridge" {
				log.Printf("Le réseau noyra existe mais n'est pas configuré en mode bridge (mode actuel: %s)", net.Driver)
				// Supprimer le réseau existant pour le recréer en bridge
				_, err := network.Remove(cs.podmanContext, "noyra", &network.RemoveOptions{})
				if err != nil {
					return &protoContainer.Response{Status: "KO"}, fmt.Errorf("impossible de supprimer le réseau noyra non-bridge: %v", err)
				}
				networkExists = false
			}
			break
		}
	}

	// Créer le réseau s'il n'existe pas ou s'il a été supprimé
	if !networkExists {
		networkCreate, err := network.Create(cs.podmanContext, &nettypes.Network{
			Name:   "noyra",
			Driver: "bridge",
		})
		if err != nil {
			log.Printf("Erreur lors de la création du réseau noyra: %v", err)
			return &protoContainer.Response{Status: "KO"}, fmt.Errorf("erreur lors de la création du réseau noyra: %v", err)
		}
		log.Printf("Réseau noyra créé avec succès: %s", networkCreate)
	}

	exposedPorts := make(map[uint16]string)

	for i, exposedPort := range startRequest.GetExposedPorts() {
		println(i, exposedPort)
		exposedPorts[uint16(i)] = exposedPort
	}

	// Préparer les volumes pour le conteneur
	// Utiliser un chemin absolu pour le fichier de configuration
	configPath := "/mnt/data/src/go/noyra/config/envoy.yaml"

	// Vérifier si nous avons des arguments spéciaux pour l'image envoy
	args := []string{}
	if strings.Contains(startRequest.GetImage(), "envoyproxy/envoy") {
		// Si c'est l'image Envoy, ajouter les arguments spécifiques
		args = []string{"-c", "/config.yaml", "--drain-time-s", "5", "-l", "debug"}
	}

	containerSpec := specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:    startRequest.GetName(),
			Labels:  startRequest.GetLabels(),
			Command: args,
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image: startRequest.GetImage(),
			// Ajouter les volumes
			Volumes: []*specgen.NamedVolume{},
			Mounts: []spec.Mount{
				{
					Destination: "/config.yaml",
					Type:        "bind",
					Source:      configPath,
					Options:     []string{"rbind", "ro"},
				},
			},
		},
		ContainerNetworkConfig: specgen.ContainerNetworkConfig{
			Expose: exposedPorts,
			// Spécifier explicitement le mode réseau bridge
			NetNS: specgen.Namespace{
				NSMode: specgen.Bridge,
			},
			Networks: map[string]nettypes.PerNetworkOptions{
				"noyra": {},
			},
			PortMappings: []nettypes.PortMapping{
				{
					ContainerPort: 10000,
					HostPort:      10000,
				},
				{
					ContainerPort: 9001,
					HostPort:      9001,
				},
			},
		},
	}

	response, err := containers.CreateWithSpec(cs.podmanContext, &containerSpec, nil)

	if err != nil {
		return &protoContainer.Response{Status: "KO"}, err
	}

	containerID := response.ID
	fmt.Printf("Le conteneur a été créé avec ID: %s\n", containerID)

	containers.Start(cs.podmanContext, containerID, &containers.StartOptions{})

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) Stop(ctx context.Context, stopRequest *protoContainer.StopRequest) (*protoContainer.Response, error) {

	// err := cs.podmanConnection.ContainerStop(ctx, stopRequest.GetContainerId(), container.StopOptions{})

	// if err != nil {
	// 	println(err.Error())
	// 	return &protoContainer.Response{Status: "KO"}, err
	// }

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) Remove(ctx context.Context, removeRequest *protoContainer.RemoveRequest) (*protoContainer.Response, error) {
	// err := cs.podmanConnection.ContainerRemove(ctx, removeRequest.GetContainerId(), container.RemoveOptions{})

	// if err != nil {
	// 	println(err.Error())
	// 	return &protoContainer.Response{Status: "KO"}, err
	// }

	return &protoContainer.Response{Status: "OK"}, nil
}

func (cs *containerServer) pullImage(ctx context.Context, startRequest *protoContainer.StartRequest) {
	// filterArgs := filters.NewArgs()
	// filterArgs.Add("reference", startRequest.GetImage())

	// images, _ := cs.podmanConnection.ImageList(ctx, image.ListOptions{Filters: filterArgs})

	// if len(images) > 0 {
	// 	log.Println("image " + startRequest.GetImage() + " already present")
	// 	return
	// }

	imagesList, _ := images.List(cs.podmanContext, &images.ListOptions{Filters: map[string][]string{
		"reference": {startRequest.GetImage()},
	}})

	if len(imagesList) > 0 {
		log.Println("image " + startRequest.GetImage() + " already present")
		return
	}

	quiet := true
	_, err := images.Pull(cs.podmanContext, startRequest.GetImage(), &images.PullOptions{Quiet: &quiet})

	if err != nil {
		panic(err.Error())
	}
}

// func (cs *containerServer) List(ctx context.Context, listRequest *protoContainer.ListRequest) (*protoContainer.ListResponse, error) {

// containers, errContainerList := cs.podmanConnection.ContainerList(ctx, container.ListOptions{})
// if errContainerList != nil {
// 	println(errContainerList.Error())
// }

// var containersInfo []*protoContainer.ContainerInfo

// for _, c := range containers {
// 	containersInfo = append(containersInfo, &protoContainer.ContainerInfo{
// 		Id:   c.ID,
// 		Name: c.Names[0],
// 	})
// }

// return &protoContainer.ListResponse{Containers: containersInfo}, nil
// }

func agent() {
	flag.Parse()
	// Connexion pour le service conteneur
	listenContainer, err := net.Listen("tcp", ":4646")
	if err != nil {
		log.Fatalf("failed to listen for container service: %v", err)
	}

	ctx := context.Background()

	podmanConnection, err := bindings.NewConnection(ctx, "unix:///run/user/1000/podman/podman.sock")

	if err != nil {
		log.Fatalf("Error connecting to Podman: %v", err)
	}
	/*
		inspectData, err := containers.Inspect(conn, "smallapp-1", new(containers.InspectOptions).WithSize(true))

		if err != nil {
			log.Fatalf("a", err)
		}

		fmt.Printf("%+v\n", inspectData)
	*/

	//cli, _ := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	cs := containerServer{
		podmanContext: podmanConnection,
	}

	// Démarrer le service container
	containerServer := grpc.NewServer()
	protoContainer.RegisterContainerServer(containerServer, &cs)

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)

	go discoveryService()

	// Lancer les deux serveurs en parallèle
	log.Printf("containerServer listening at %v", listenContainer.Addr())

	if err := containerServer.Serve(listenContainer); err != nil {
		log.Fatalf("failed to serve container service: %v", err)
	}

}

func discoveryService() {
	// Créer la configuration du cache xDS
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)

	// Créer le serveur avec les callbacks
	xdsServer := server.NewServer(context.Background(), snapshotCache, Callbacks{})

	// Créer un nouveau snapshot en ajoutant les ressources
	resources := map[resource.Type][]types.Resource{
		resource.ClusterType:  {makeCluster()},
		resource.RouteType:    {makeRouteConfig()},
		resource.ListenerType: {makeListener()},
	}

	// Créer le snapshot
	snapshot, err := cache.NewSnapshot("1", resources)
	if err != nil {
		log.Fatalf("Impossible de créer le snapshot: %v", err)
	}

	// Mettre à jour le cache avec le nouveau snapshot
	err = snapshotCache.SetSnapshot(context.Background(), nodeID, snapshot)
	if err != nil {
		log.Fatalf("Erreur mise à jour snapshot: %v", err)
	}

	// Démarrer le serveur gRPC
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	lis, err := net.Listen("tcp", ":18000")
	if err != nil {
		log.Fatalf("Impossible d'écouter: %v", err)
	}

	// Enregistrer les services EDS
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, xdsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, xdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, xdsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, xdsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, xdsServer)

	log.Printf("Serveur EDS démarré sur port 18000...")

	// Mettre à jour périodiquement les endpoints (simulation)
	//go func() {
	//	version := 2
	//	for {
	//		time.Sleep(30 * time.Second)
	//		resources := map[resource.Type][]types.Resource{
	//			resource.EndpointType: {makeCluster()},
	//			resource.ListenerType: {makeListener()},
	//		}
	//		snapshot, err := cache.NewSnapshot(fmt.Sprintf("%d", version), resources)
	//		if err != nil {
	//			log.Printf("Erreur création snapshot: %v", err)
	//			continue
	//		}
	//
	//		err = snapshotCache.SetSnapshot(context.Background(), nodeID, snapshot)
	//		if err != nil {
	//			log.Printf("Erreur mise à jour snapshot: %v", err)
	//		}
	//		version++
	//	}
	//}()

	// Démarrer le serveur
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Erreur démarrage serveur: %v", err)
	}
}
