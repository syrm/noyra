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

	protoAgent "blackprism.org/noyra/api/agent/v1"
	"blackprism.org/noyra/internal/agent"
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

func (d *Deployment) ReadInto(ctx context.Context, etcdClient *etcd.Client, key string) error {
	valueBase64, err := etcdClient.Get(ctx, key)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while getting value from etcd", slog.Any("error", err))
		return err
	}

	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while decoding base64 value", slog.Any("error", err))
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
func (d *Deployment) ReadFromValue(ctx context.Context, valueBase64 string) error {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while decoding base64 value", slog.Any("error", err))
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
	agentService *agent.Server
	etcdClient   *etcd.Client
	config       *Config
	schema       []byte
}

func BuildSupervisor(agentService *agent.Server, etcdClient *etcd.Client, schema []byte) *Supervisor {
	return &Supervisor{
		agentService: agentService,
		etcdClient:   etcdClient,
		schema:       schema,
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

func (s *Supervisor) Run(ctx context.Context) {
	err := s.loadConfig(os.Getenv("NOYRA_CONFIG"))

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error in configuration", slog.Any("error", err))
		os.Exit(1)
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "supervisor starting")
	s.initEtcd(ctx)
	// @TODO attention etcd n'a pas encore été démarré
	s.saveClusterState(ctx)
	slog.LogAttrs(ctx, slog.LevelInfo, "deploying toc toc", slog.Int("services", len(s.config.Deployment)))

	for _, service := range s.config.Deployment {
		slog.LogAttrs(ctx, slog.LevelInfo, "deploying service", slog.String("service", service.Name))
		s.deployService(ctx, service)
	}

	s.observeCluster(ctx)
}

func (s *Supervisor) saveClusterState(ctx context.Context) {
	containerLists, err := s.agentService.Direct.ContainerList(ctx, &protoAgent.ContainerListRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while calling ContainerList", slog.Any("error", err))
	}

	for _, deploymentConfig := range s.config.Deployment {
		readyContainers := 0
		for _, container := range containerLists.GetContainers() {
			if container.GetLabels()["noyra.name"] == deploymentConfig.Name && container.GetState() == "running" {
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
			slog.LogAttrs(ctx, slog.LevelError, "error while writing to etcd", slog.Any("error", err))
		}
	}

	d := Deployment{}
	errRead := d.ReadInto(ctx, s.etcdClient, "/deployment/smallapp")
	if errRead != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while reading deployment", slog.Any("error", errRead))
		return
	}
	fmt.Printf("Deployment: %+v\n", d)
}

func (s *Supervisor) observeCluster(ctx context.Context) {
	stream, err := s.agentService.Direct.ContainerListener(ctx, &protoAgent.ContainerListenerRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error while calling ContainerListener", slog.Any("error", err))
		os.Exit(1)
	}

	for {
		feature, _ := stream.Recv()
		slog.LogAttrs(ctx, slog.LevelInfo, "container event received", slog.Any("feature", feature))
	}
}

func (s *Supervisor) deployService(ctx context.Context, deploymentConfig DeploymentConfig) {
	// @TODO containersList or containerLists or other ?
	containerListRequest := &protoAgent.ContainerListRequest{}
	containerListRequest.SetLabels(
		map[string]string{
			"noyra.name": deploymentConfig.Name,
		},
	)

	containersList, err := s.agentService.Direct.ContainerList(ctx, containerListRequest)

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "failed to get containers", slog.Any("error", err))
		return
	}

	containerToDeploy := max(deploymentConfig.Replicas-len(containersList.GetContainers()), 0)

	if containerToDeploy == 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "no new container to deploy for service", slog.String("service", deploymentConfig.Name))
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
		slog.LogAttrs(ctx, slog.LevelInfo, "starting to deploy container", slog.Any("name", deploymentConfig.Name))

		containerStartRequest := &protoAgent.ContainerStartRequest{}
		containerStartRequest.SetImage(deploymentConfig.Image)
		containerStartRequest.SetName(deploymentConfig.Name + "-" + ContainerNameHash())
		containerStartRequest.SetExposedPorts(exposedPorts)
		containerStartRequest.SetLabels(
			map[string]string{
				"noyra.name":    deploymentConfig.Name,
				"noyra.type":    deploymentConfig.Type,
				"noyra.cluster": deploymentConfig.Name,
				"noyra.domain":  deploymentConfig.Domains[0],
			},
		)

		_, err := s.agentService.Direct.ContainerStart(ctx, containerStartRequest)
		if err != nil {
			slog.LogAttrs(ctx, slog.LevelError, "failed to start container", slog.Any("error", err))
		}
	}
}

func (s *Supervisor) initEtcd(ctx context.Context) {
	containerListRequest := &protoAgent.ContainerListRequest{}
	containerListRequest.SetLabels(
		map[string]string{
			"noyra.name": "noyra-etcd",
		},
	)
	containersList, err := s.agentService.Direct.ContainerList(ctx, containerListRequest)

	if len(containersList.GetContainers()) > 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "noyra Etcd already running")
		return
	}

	var mounts []*protoAgent.ContainerMount

	containerMountEtcdCa := &protoAgent.ContainerMount{}
	containerMountEtcdCa.SetDestination("/certs/etcd-ca.crt")
	containerMountEtcdCa.SetType("bind")
	containerMountEtcdCa.SetSource(s.etcdClient.GetCaCertFile())
	containerMountEtcdCa.SetOptions([]string{"rbind", "ro"})
	mounts = append(mounts, containerMountEtcdCa)

	containerMountEtcdServerCert := &protoAgent.ContainerMount{}
	containerMountEtcdServerCert.SetDestination("/certs/etcd-server.crt")
	containerMountEtcdServerCert.SetType("bind")
	containerMountEtcdServerCert.SetSource(s.etcdClient.GetServerCertFile())
	containerMountEtcdServerCert.SetOptions([]string{"rbind", "ro"})
	mounts = append(mounts, containerMountEtcdServerCert)

	containerMountEtcdServerKey := &protoAgent.ContainerMount{}
	containerMountEtcdServerKey.SetDestination("/certs/etcd-server.key")
	containerMountEtcdServerKey.SetType("bind")
	containerMountEtcdServerKey.SetSource(s.etcdClient.GetServerKeyFile())
	containerMountEtcdServerKey.SetOptions([]string{"rbind", "ro"})
	mounts = append(mounts, containerMountEtcdServerKey)

	containerVolume := &protoAgent.ContainerVolume{}
	containerVolume.SetDestination("/bitnami/etcd/data")
	containerVolume.SetSource("noyra-etcd-data")
	containerVolume.SetOptions([]string{"U"})

	containerPortMapping := &protoAgent.ContainerPortMapping{}
	containerPortMapping.SetContainerPort(2379)
	containerPortMapping.SetHostPort(2379)

	startRequest := &protoAgent.ContainerStartRequest{}
	startRequest.SetImage("bitnami/etcd:3.5.21")
	startRequest.SetName("noyra-etcd")
	startRequest.SetEnv(
		map[string]string{
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
	)
	startRequest.SetExposedPorts(
		map[uint32]string{
			2379: "tcp",
		},
	)
	startRequest.SetNetwork("noyra")
	startRequest.SetLabels(
		map[string]string{
			"noyra.name": "noyra-etcd",
		},
	)
	startRequest.SetMounts(mounts)
	startRequest.SetVolumes([]*protoAgent.ContainerVolume{containerVolume})
	startRequest.SetPortMappings([]*protoAgent.ContainerPortMapping{containerPortMapping})

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r, err := s.agentService.Direct.ContainerStart(timeoutCtx, startRequest)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "could not start container", slog.Any("error", err))
		os.Exit(1)
	}
	slog.LogAttrs(ctx, slog.LevelInfo, "container start response", slog.String("status", r.GetStatus()))
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
