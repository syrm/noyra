package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"

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

type Supervisor struct {
	agentService *agent
}

func BuildSupervisor(agentService *agent) *Supervisor {
	return &Supervisor{
		agentService: agentService,
	}
}

// LoadConfig charge et valide les fichiers CUE, puis les convertit en structure Go
func (s *Supervisor) loadConfig(ctx context.Context, configDir string) (*Config, error) {
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

func (s *Supervisor) Run(ctx context.Context) {
	config, err := s.loadConfig(ctx, ".")

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error in configuration", slog.Any("error", err))
		os.Exit(1)
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Supervisor starting")
	// Set up a connection to the server.

	stream, err := s.agentService.Direct.ContainerListener(ctx, &protoContainer.ContainerListenerRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error while calling ContainerListener", slog.Any("error", err))
		os.Exit(1)
	}

	for _, service := range config.Service {
		s.deployService(ctx, service)
	}

	for {
		feature, _ := stream.Recv()
		slog.LogAttrs(ctx, slog.LevelInfo, "Container event received", slog.Any("feature", feature))
	}
}

func (s *Supervisor) deployService(ctx context.Context, service Service) {
	// @TODO containersList or containerLists or other ?
	containersList, err := s.agentService.Direct.ContainerList(ctx, &protoContainer.ContainerListRequest{
		Labels: map[string]string{
			"noyra.name": service.Name,
		},
	})

	containerToDeploy := max(service.Deploy.Replicas-len(containersList.Containers), 0)

	if containerToDeploy == 0 {
		return
	}

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelWarn, "Failed to get container labels", slog.Any("error", err))
	}

	exposedPorts := make(map[uint32]string)

	for _, portWithProtocol := range service.Expose {
		port := strings.Split(portWithProtocol, "/")

		if len(port) == 1 {
			port = append(port, "tcp")
		}

		portUint32, _ := strconv.Atoi(port[0])

		exposedPorts[uint32(portUint32)] = "tcp"
	}

	for range containerToDeploy {
		s.agentService.Direct.ContainerStart(ctx, &protoContainer.ContainerStartRequest{
			Image:        service.Image,
			Name:         service.Name + "-" + ContainerNameHash(),
			ExposedPorts: exposedPorts,
			Labels: map[string]string{
				"noyra.name":    service.Name,
				"noyra.type":    service.Deploy.Type,
				"noyra.cluster": service.Name,
				"noyra.domain":  service.Domains[0],
			},
		})
	}
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))
var mutex sync.Mutex

const (
	// We omit vowels from the set of available characters to reduce the chances
	// of "bad words" being formed.
	alphanums = "bcdfghjklmnpqrstvwxz2456789"
)

func ContainerNameHash() string {
	b := make([]byte, 5)

	mutex.Lock()
	randomInt63 := rng.Int63()
	mutex.Unlock()

	for i := range 5 {
		idx := randomInt63 & 0b111111
		b[i] = alphanums[idx%int64(len(alphanums))]
		randomInt63 >>= 6
	}

	return string(b)
}
