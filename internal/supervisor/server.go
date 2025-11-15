package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/samber/oops"

	"blackprism.org/noyra/internal/agent"
	"blackprism.org/noyra/internal/agent/component"
	"blackprism.org/noyra/internal/etcd"
)

type Config struct {
	Deployment map[string]DeploymentConfig `json:"deployment"`
}

type DeploymentConfig struct {
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	Type     string   `json:"type"`
	Domains  []string `json:"domains"`
	Expose   []string `json:"expose"`
	Replicas int      `json:"replicas"`
}

type Deployment struct {
	Name    string           `json:"name"`
	Image   string           `json:"image"`
	Type    string           `json:"type"`
	Domains []string         `json:"domains"`
	Expose  []string         `json:"expose"`
	Status  DeploymentStatus `json:"status"`
	logger  *slog.Logger
}

type DeploymentStatus struct {
	DesiredReplicas uint16 `json:"desired_replicas"`
	ReadyReplicas   uint16 `json:"ready_replicas"`
}

func (d *Deployment) WriteTo(ctx context.Context, etcdClient *etcd.Client, key string) error {
	buf := new(bytes.Buffer)
	name := d.Name // gosec G115 dont understand math.MaxUint16
	_ = binary.Write(buf, binary.BigEndian, uint16(len(name)))
	_ = binary.Write(buf, binary.BigEndian, []byte(name))
	_ = binary.Write(buf, binary.BigEndian, uint16(len(d.Domains)))

	for _, domain := range d.Domains {
		_ = binary.Write(buf, binary.BigEndian, uint16(len(domain)))
		_ = binary.Write(buf, binary.BigEndian, []byte(domain))
	}

	_ = binary.Write(buf, binary.BigEndian, d.Status.DesiredReplicas)
	_ = binary.Write(buf, binary.BigEndian, d.Status.ReadyReplicas)

	return etcdClient.Put(ctx, key, base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func (d *Deployment) ReadInto(ctx context.Context, etcdClient *etcd.Client, key string, logger *slog.Logger) error {
	valueBase64, err := etcdClient.Get(ctx, key)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error while getting value from etcd", slog.Any("error", err))
		return err
	}

	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error while decoding base64 value", slog.Any("error", err))
		return err
	}
	buf := bytes.NewReader(value)

	var lenName uint16
	binary.Read(buf, binary.BigEndian, &lenName)
	name := make([]byte, lenName)
	binary.Read(buf, binary.BigEndian, &name)
	d.Name = string(name)
	var lenDomains uint16
	binary.Read(buf, binary.BigEndian, &lenDomains)

	var domains []string
	for range lenDomains {
		var lenDomain uint16
		binary.Read(buf, binary.BigEndian, &lenDomain)
		domain := make([]byte, lenDomain)
		binary.Read(buf, binary.BigEndian, &domain)
		domains = append(domains, string(domain))
	}

	d.Domains = domains

	var desiredReplicas uint16
	binary.Read(buf, binary.BigEndian, &desiredReplicas)
	var readyReplicas uint16
	binary.Read(buf, binary.BigEndian, &readyReplicas)

	d.Status = DeploymentStatus{
		DesiredReplicas: desiredReplicas,
		ReadyReplicas:   readyReplicas,
	}

	return nil
}

// ReadFromValue reads a deployment from a base64-encoded value
func (d *Deployment) ReadFromValue(ctx context.Context, valueBase64 string, logger *slog.Logger) error {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error while decoding base64 value", slog.Any("error", err))
		return err
	}

	// Use the existing ReadInto method's logic to parse the binary data
	buf := bytes.NewReader(value)

	var lenName uint16
	binary.Read(buf, binary.BigEndian, &lenName)
	name := make([]byte, lenName)
	binary.Read(buf, binary.BigEndian, &name)
	d.Name = string(name)

	var lenDomains uint16
	binary.Read(buf, binary.BigEndian, &lenDomains)

	var domains []string
	for range lenDomains {
		var lenDomain uint16
		binary.Read(buf, binary.BigEndian, &lenDomain)
		domain := make([]byte, lenDomain)
		binary.Read(buf, binary.BigEndian, &domain)
		domains = append(domains, string(domain))
	}

	d.Domains = domains

	var desiredReplicas uint16
	binary.Read(buf, binary.BigEndian, &desiredReplicas)
	var readyReplicas uint16
	binary.Read(buf, binary.BigEndian, &readyReplicas)

	d.Status = DeploymentStatus{
		DesiredReplicas: desiredReplicas,
		ReadyReplicas:   readyReplicas,
	}

	return nil
}

type Supervisor struct {
	agentService *agent.Agent
	etcdClient   *etcd.Client
	config       *Config
	schema       []byte
	logger       *slog.Logger
}

func BuildSupervisor(agentService *agent.Agent, etcdClient *etcd.Client, schema []byte, logger *slog.Logger) *Supervisor {
	return &Supervisor{
		agentService: agentService,
		etcdClient:   etcdClient,
		schema:       schema,
		logger:       logger,
	}
}

func (s *Supervisor) loadConfig(configDir string) error {
	cuectx := cuecontext.New()

	schemaVal := cuectx.CompileBytes(s.schema)
	if schemaVal.Err() != nil {
		return fmt.Errorf("erreur dans le schéma intégré: %v", schemaVal.Err())
	}

	bis := load.Instances([]string{configDir}, nil)
	if len(bis) == 0 {
		return fmt.Errorf("aucun fichier CUE trouvé dans %s", configDir)
	}

	var value cue.Value
	for _, bi := range bis {
		if bi.Err != nil {
			return fmt.Errorf("erreur lors du chargement du fichier CUE: %v", bi.Err)
		}
		if value.Exists() {
			value = value.FillPath(cue.Path{}, cuectx.BuildInstance(bi))
		} else {
			value = cuectx.BuildInstance(bi)
		}
	}

	if value.Err() != nil {
		return fmt.Errorf("erreur dans la configuration CUE: %v", value.Err())
	}

	value = schemaVal.Unify(value)
	if value.Err() != nil {
		return fmt.Errorf("la configuration n'est pas valide selon le schéma: %v", value.Err())
	}

	var config Config
	if err := value.Decode(&config); err != nil {
		return fmt.Errorf("erreur lors de la conversion en Go: %v", err)
	}

	s.config = &config

	return nil
}

func (s *Supervisor) Run(ctx context.Context) error {
	err := s.loadConfig(os.Getenv("NOYRA_CONFIG"))

	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error in configuration", slog.Any("error", err))
		return err
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "supervisor starting")
	errEtcd := s.startEtcd(ctx)

	if errEtcd != nil {
		return oops.Wrapf(errEtcd, "supervisor can't start etcd")
	}

	errEnvoy := s.startEnvoy(ctx)

	if errEnvoy != nil {
		return oops.Wrapf(errEtcd, "supervisor can't start envoy")
	}

	// @TODO attention etcd n'a pas encore été démarré
	time.Sleep(5 * time.Second)

	s.saveClusterState(ctx)
	s.logger.LogAttrs(ctx, slog.LevelInfo, "deploying toc toc", slog.Int("services", len(s.config.Deployment)))

	for _, service := range s.config.Deployment {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "deploying service", slog.String("service", service.Name))
		s.deployService(ctx, service)
	}

	s.resyncCluster(ctx)
	s.observeCluster(ctx)

	return nil
}

func (s *Supervisor) saveClusterState(ctx context.Context) {
	containerLists, err := s.agentService.ContainerList(ctx, false, nil, nil)

	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error while calling ContainerList", slog.Any("error", err))
	}

	for _, deploymentConfig := range s.config.Deployment {
		readyContainers := 0
		for _, container := range containerLists {
			if container.Labels["noyra.name"] == deploymentConfig.Name && container.State == "running" {
				readyContainers++
			}
		}

		deployment := Deployment{
			Name:    deploymentConfig.Name,
			Domains: deploymentConfig.Domains,
			Image:   deploymentConfig.Image,
			Expose:  deploymentConfig.Expose,
			Type:    deploymentConfig.Type,
			Status: DeploymentStatus{
				DesiredReplicas: uint16(deploymentConfig.Replicas),
				ReadyReplicas:   uint16(readyContainers),
			},
		}

		err := deployment.WriteTo(ctx, s.etcdClient, "/deployment/"+deployment.Name)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelError, "error while writing to etcd", slog.Any("error", err))
		}
	}

	d := Deployment{}
	errRead := d.ReadInto(ctx, s.etcdClient, "/deployment/smallapp", s.logger)
	if errRead != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error while reading deployment", slog.Any("error", errRead))
		return
	}
	fmt.Printf("Deployment: %+v\n", d)
}

func (s *Supervisor) resyncCluster(ctx context.Context) error {
	fmt.Println("BOUHHHHHHHHHHHHHHHHHHHHHH")

	data, errGet := s.etcdClient.GetKeys(ctx)

	fmt.Printf("BOUHHHHHHHHHHHHHHHHHHHHHH %+v\n", data)

	for _, key := range data {
		data2, _ := s.etcdClient.Get(ctx, key)
		fmt.Printf("RESYNC %+v\n", data2)
	}

	if errGet != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error while calling Get", slog.Any("error", errGet))
		return errGet
	}

	return nil
}

func (s *Supervisor) observeCluster(ctx context.Context) error {
	containerListenerResponseChan := make(chan component.ContainerListenerResponse, 1000)
	err := s.agentService.ContainerListener(ctx, containerListenerResponseChan)

	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error while calling ContainerListener", slog.Any("error", err))
		return err
	}

	for {
		select {
		case event := <-containerListenerResponseChan:
			s.logger.LogAttrs(ctx, slog.LevelInfo, "container event received", slog.Any("event", event))

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Supervisor) deployService(ctx context.Context, deploymentConfig DeploymentConfig) {
	containersList, err := s.agentService.ContainerList(
		ctx,
		false,
		nil,
		map[string]string{"noyra.name": deploymentConfig.Name},
	)

	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "failed to get containers", slog.Any("error", err))
		return
	}

	containerToDeploy := max(deploymentConfig.Replicas-len(containersList), 0)

	if containerToDeploy == 0 {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "no new container to deploy for service", slog.String("service", deploymentConfig.Name))
		return
	}

	exposedPorts := make(map[uint32]string)

	for _, portWithProtocol := range deploymentConfig.Expose {
		port := strings.Split(portWithProtocol, "/")

		if len(port) == 1 {
			port = append(port, "tcp")
		}

		portUint32, _ := strconv.Atoi(port[0])

		exposedPorts[uint32(portUint32)] = "tcp"
	}

	for range containerToDeploy {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "starting to deploy container", slog.Any("name", deploymentConfig.Name))

		containerStartRequest := component.ContainerRequest{
			Image:        deploymentConfig.Image,
			Name:         deploymentConfig.Name + "-" + ContainerNameHash(),
			ExposedPorts: exposedPorts,
			Labels: map[string]string{
				"noyra.name":    deploymentConfig.Name,
				"noyra.type":    deploymentConfig.Type,
				"noyra.cluster": deploymentConfig.Name,
				"noyra.domain":  deploymentConfig.Domains[0],
			},
		}

		errContainerStart := s.agentService.ContainerStart(ctx, containerStartRequest)
		if errContainerStart != nil {
			s.logger.LogAttrs(ctx, slog.LevelError, "failed to start container", slog.Any("error", errContainerStart))
		}
	}
}

func (s *Supervisor) startEnvoy(ctx context.Context) error {
	containersList, errList := s.agentService.ContainerList(
		ctx,
		true,
		nil,
		map[string]string{"noyra.name": "noyra-envoy"},
	)

	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "failed to get container", slog.Any("error", errList))
	}

	if len(containersList) > 0 {
		for _, container := range containersList {
			if container.State == "running" {
				s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra envoy already running")
				return nil
			}

			errResume := s.agentService.ContainerRemove(ctx, "noyra-envoy")
			if errResume != nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "failed to remove envoy", slog.Any("error", errResume))
				return errResume
			}
		}
	}

	// @TODO heu a mettre en ENV
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
	containerRequest.Commands = []string{"-c", "/config.yaml", "--drain-time-s", "5"}
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
	err := s.agentService.ContainerStart(timeoutCtx, containerRequest)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "could not start container", slog.Any("error", err))
		return err
	}

	return nil
}

func (s *Supervisor) startEtcd(ctx context.Context) error {
	containersList, errList := s.agentService.ContainerList(ctx, true, nil, map[string]string{"noyra.name": "noyra-etcd"})

	if errList != nil {
		slog.LogAttrs(ctx, slog.LevelError, "failed to get container", slog.Any("error", errList))
	}

	if len(containersList) > 0 {
		for _, container := range containersList {
			if container.State == "running" {
				s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra etcd already running")
				return nil
			}

			errResume := s.agentService.ContainerResume(ctx, "noyra-etcd")
			if errResume != nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "failed to resume etcd", slog.Any("error", errResume))

				return errResume
			}

			s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra etcd resumed")
			return nil
		}
	}

	var mounts []component.ContainerMount

	containerMountEtcdCa := component.ContainerMount{
		Destination: "/certs/etcd-ca.crt",
		Type:        "bind",
		Source:      s.etcdClient.GetCaCertFile(),
		Options:     []string{"rbind", "ro"},
	}
	mounts = append(mounts, containerMountEtcdCa)

	containerMountEtcdServerCert := component.ContainerMount{
		Destination: "/certs/etcd-server.crt",
		Type:        "bind",
		Source:      s.etcdClient.GetServerCertFile(),
		Options:     []string{"rbind", "ro"},
	}
	mounts = append(mounts, containerMountEtcdServerCert)

	containerMountEtcdServerKey := component.ContainerMount{
		Destination: "/certs/etcd-server.key",
		Type:        "bind",
		Source:      s.etcdClient.GetServerKeyFile(),
		Options:     []string{"rbind", "ro"},
	}
	mounts = append(mounts, containerMountEtcdServerKey)

	containerVolume := component.ContainerVolume{
		Destination: "/bitnami/etcd/data",
		Source:      "noyra-etcd-data",
		Options:     []string{"U"},
	}

	containerPortMapping := component.ContainerPortMapping{
		ContainerPort: 2379,
		HostPort:      2379,
	}

	startRequest := component.ContainerRequest{
		Image:  "bitnami/etcd:3.5.21",
		Name:   "noyra-etcd",
		UserNS: true,
		Env: map[string]string{
			"ALLOW_NONE_AUTHENTICATION":  "true",
			"BITNAMI_DEBUG":              "true",
			"ETCD_FORCE_NEW_CLUSTER":     "true",
			"ETCD_NAME":                  "noyra-etcd-node",
			"ETCD_LISTEN_CLIENT_URLS":    "https://0.0.0.0:2379",
			"ETCD_ADVERTISE_CLIENT_URLS": "https://localhost:2379",
			"ETCD_CLIENT_CERT_AUTH":      "true",
			"ETCD_TRUSTED_CA_FILE":       "/certs/etcd-ca.crt",
			"ETCD_CERT_FILE":             "/certs/etcd-server.crt",
			"ETCD_KEY_FILE":              "/certs/etcd-server.key",
		},
		ExposedPorts: map[uint32]string{
			2379: "tcp",
		},
		Network: "noyra",
		Labels: map[string]string{
			"noyra.name": "noyra-etcd",
		},
		Mounts:       mounts,
		Volumes:      []component.ContainerVolume{containerVolume},
		PortMappings: []component.ContainerPortMapping{containerPortMapping},
	}

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	errContainerStart := s.agentService.ContainerStart(timeoutCtx, startRequest)
	if errContainerStart != nil {
		slog.LogAttrs(ctx, slog.LevelError, "could not start etcd", slog.Any("error", errContainerStart))
		return oops.Wrapf(errList, "could not start etcd")
	}
	slog.LogAttrs(ctx, slog.LevelInfo, "container start response")

	return nil
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
	defer mutex.Unlock()

	randomInt63 := rng.Int63()

	for i := range 5 {
		idx := randomInt63 & 0b111111
		b[i] = alphanums[idx%int64(len(alphanums))]
		randomInt63 >>= 6
	}

	return string(b)
}
