package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	protoContainer "blackprism.org/noyra/grpc-proto/agent"
)

type Config struct {
	Service map[string]Service `json:"service"`
}

type Service struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Image   string   `json:"image"`
	Expose  []string `json:"expose"`
	Deploy  Deploy   `json:"deploy"`
}

type Deploy struct {
	Type     string `json:"type"`
	Replicas int    `json:"replicas"`
}

// LoadConfig charge et valide les fichiers CUE, puis les convertit en structure Go
func LoadConfig(configDir string) (*Config, error) {
	// Créer un contexte CUE
	cuectx := cuecontext.New()

	// Compiler le schéma embarqué
	schemaVal := cuectx.CompileString(embeddedSchema)
	if schemaVal.Err() != nil {
		return nil, fmt.Errorf("erreur dans le schéma intégré: %v", schemaVal.Err())
	}

	// Charger les fichiers CUE
	bis := load.Instances([]string{configDir}, nil)
	if len(bis) == 0 {
		return nil, fmt.Errorf("aucun fichier CUE trouvé dans %s", configDir)
	}

	// Construire la valeur CUE
	var value cue.Value
	for _, bi := range bis {
		if bi.Err != nil {
			return nil, fmt.Errorf("erreur lors du chargement du fichier CUE: %v", bi.Err)
		}
		if value.Exists() {
			value = value.FillPath(cue.Path{}, cuectx.BuildInstance(bi))
		} else {
			value = cuectx.BuildInstance(bi)
		}
	}

	// Vérifier les erreurs
	if value.Err() != nil {
		return nil, fmt.Errorf("erreur dans la configuration CUE: %v", value.Err())
	}

	// Unifier le schéma et la configuration
	value = schemaVal.Unify(value)
	if value.Err() != nil {
		return nil, fmt.Errorf("la configuration n'est pas valide selon le schéma: %v", value.Err())
	}

	// Convertir en structure Go
	var config Config
	if err := value.Decode(&config); err != nil {
		return nil, fmt.Errorf("erreur lors de la conversion en Go: %v", err)
	}

	return &config, nil
}

func supervisor(agentService *agent) {
	config, err := LoadConfig(".")

	if err != nil {
		log.Fatalf("erreur dans la configuration: %v", err)
	}

	fmt.Println("supervisor")
	// Set up a connection to the server.
	conn, err := grpc.NewClient("localhost:4646", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := protoContainer.NewAgentClient(conn)

	stream, err := c.ContainerListener(context.Background(), &protoContainer.ContainerListenerRequest{})

	if err != nil {
		log.Fatalf("Error while calling ContainerListener: %v", err)
	}

	for _, service := range config.Service {
		exposedPorts := make(map[uint32]string)

		for _, portWithProtocol := range service.Expose {
			port := strings.Split(portWithProtocol, "/")

			if len(port) == 1 {
				port[1] = "tcp"
			}

			portUint32, _ := strconv.Atoi(port[0])

			exposedPorts[uint32(portUint32)] = "tcp"
		}

		for range service.Deploy.Replicas {
			agentService.Direct.ContainerStart(context.Background(), &protoContainer.ContainerStartRequest{
				Image:        service.Image,
				Name:         service.Name + "-" + ContainerNameHash(),
				ExposedPorts: exposedPorts,
				Labels: map[string]string{
					"noyra.type":    service.Deploy.Type,
					"noyra.cluster": service.Name,
					"noyra.domain":  service.Domains[0],
				},
			})
		}
	}

	for {
		feature, _ := stream.Recv()
		log.Println("bouh supervisoooooooooooooooor", feature)
	}

	// newUUID := uuid.New()
	// shortUUID := newUUID.String()[:8]

	// startRequest := &protoContainer.ContainerStartRequest{
	// 	Image: "192.168.1.39:50000/smallapp:0.3",
	// 	Name:  "noyra-smallapp-" + shortUUID,
	// 	Labels: map[string]string{
	// 		"traefik.http.routers.smallapp.rule":                      "Host(`smallapp.local`)",
	// 		"traefik.http.services.smallapp.loadbalancer.server.port": "80",
	// 	},
	// 	ExposedPorts: map[uint32]string{
	// 		80: "tcp",
	// 	},
	// }

	// // Contact the server and print out its response.
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// defer cancel()
	// r, err := c.ContainerStart(ctx, startRequest)
	// if err != nil {
	// 	log.Fatalf("could not greet: %v", err)
	// }
	// log.Printf("Greeting: %s", r.Status)

	// listResponse, _ := c.ContainerList(ctx, &protoContainer.ContainerListRequest{})

	// log.Println("Containers list")
	// for _, containerInfo := range listResponse.GetContainers() {
	// 	log.Printf("ID: %s\tNAME: %s\n", containerInfo.GetId(), containerInfo.GetName())
	// 	//c.Stop(ctx, &protoContainer.StopRequest{ContainerId: containerInfo.GetId()})
	// 	//c.Remove(ctx, &protoContainer.RemoveRequest{ContainerId: containerInfo.GetId()})
	// }
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

const (
	// We omit vowels from the set of available characters to reduce the chances
	// of "bad words" being formed.
	alphanums = "bcdfghjklmnpqrstvwxz2456789"
	// No. of bits required to index into alphanums string.
	alphanumsIdxBits = 5
	// Mask used to extract last alphanumsIdxBits of an int.
	alphanumsIdxMask = 1<<alphanumsIdxBits - 1
	// No. of random letters we can extract from a single int63.
	maxAlphanumsPerInt = 63 / alphanumsIdxBits
)

// @TODO attention si appelé dans goroutine soucis de concurrence
func ContainerNameHash() string {
	b := make([]byte, 5)

	randomInt63 := rng.Int63()
	remaining := maxAlphanumsPerInt
	for i := 0; i < 5; {
		if remaining == 0 {
			randomInt63, remaining = rng.Int63(), maxAlphanumsPerInt
		}
		if idx := int(randomInt63 & alphanumsIdxMask); idx < len(alphanums) {
			b[i] = alphanums[idx]
			i++
		}
		randomInt63 >>= alphanumsIdxBits
		remaining--
	}
	return string(b)
}
