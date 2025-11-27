package supervisor

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand"
	"net"
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
	podmanComponent "blackprism.org/noyra/internal/podman/component"
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

	errCert := generateCertificate(
		os.Getenv("ETCD_CA_CERT"),
		os.Getenv("ETCD_CA_KEY"),
		os.Getenv("ETCD_SERVER_CERT"),
		os.Getenv("ETCD_SERVER_KEY"),
		os.Getenv("ETCD_CLIENT_CERT"),
		os.Getenv("ETCD_CLIENT_KEY"),
		s.logger,
	)

	if errCert != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "error in cert generation", slog.Any("error", errCert))
		return errCert
	}

	errEtcd := s.startEtcd(ctx)

	if errEtcd != nil {
		return oops.Wrapf(errEtcd, "supervisor can't start etcd")
	}

	errEnvoy := s.startLoadbalancer(ctx)

	if errEnvoy != nil {
		return oops.Wrapf(errEtcd, "supervisor can't start envoy")
	}

	// @TODO attention etcd n'a pas encore été démarré
	time.Sleep(5 * time.Second)

	s.saveClusterState(ctx)
	s.logger.LogAttrs(ctx, slog.LevelInfo, "deploying toc toc", slog.Int("services", len(s.config.Deployment)))

	go func() {
		s.observeCluster(ctx)
	}()

	for _, service := range s.config.Deployment {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "deploying service", slog.String("service", service.Name))
		s.deployService(ctx, service)
	}

	//s.resyncCluster(ctx)

	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) saveClusterState(ctx context.Context) {
	containerLists := s.agentService.ListContainers(ctx, true, nil)

	//if err != nil {
	//	s.logger.LogAttrs(ctx, slog.LevelError, "error while calling ContainerList", slog.Any("error", err))
	//}

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

	//go func() {
	//	err := s.agentService.ContainerListener(ctx, containerListenerResponseChan)
	//	if err != nil {
	//		s.logger.LogAttrs(ctx, slog.LevelError, "error setting up ContainerListener", slog.Any("error", err))
	//	}
	//}()

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
	containersList := s.agentService.ListContainers(
		ctx,
		true,
		map[string][]string{"noyra.name": {deploymentConfig.Name}},
	)

	//if err != nil {
	//	s.logger.LogAttrs(ctx, slog.LevelError, "failed to get containers", slog.Any("error", err))
	//	return
	//}

	containerToDeploy := max(deploymentConfig.Replicas-len(containersList), 0)

	if containerToDeploy == 0 {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "no new container to deploy for service", slog.String("service", deploymentConfig.Name))
		return
	}

	exposedPorts := make(map[uint16]string)

	for _, portWithProtocol := range deploymentConfig.Expose {
		port := strings.Split(portWithProtocol, "/")

		if len(port) == 1 {
			port = append(port, "tcp")
		}

		portInt, _ := strconv.Atoi(port[0])

		exposedPorts[uint16(portInt)] = "tcp"
	}

	for range containerToDeploy {
		s.logger.LogAttrs(ctx, slog.LevelInfo, "starting to deploy container", slog.Any("name", deploymentConfig.Name))

		containerStartRequest := podmanComponent.ContainerRequest{
			Image:  deploymentConfig.Image,
			Name:   deploymentConfig.Name + "-" + ContainerNameHash(),
			Expose: exposedPorts,
			Labels: map[string]string{
				"noyra.name":    deploymentConfig.Name,
				"noyra.type":    deploymentConfig.Type,
				"noyra.cluster": deploymentConfig.Name,
				"noyra.domain":  deploymentConfig.Domains[0],
			},
		}

		_, errContainerStart := s.agentService.ContainerCreate(ctx, containerStartRequest)
		if errContainerStart != nil {
			s.logger.LogAttrs(ctx, slog.LevelError, "failed to start container", slog.Any("error", errContainerStart))
		}
	}
}

func (s *Supervisor) startLoadbalancer(ctx context.Context) error {
	containersList := s.agentService.ListContainers(
		ctx,
		true,
		map[string][]string{"label": {"noyra.name=noyra-loadbalancer"}},
	)

	//if errList != nil {
	//	slog.LogAttrs(ctx, slog.LevelError, "failed to get container", slog.Any("error", errList))
	//}

	if len(containersList) > 0 {
		for _, container := range containersList {
			if container.State == "running" {
				s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra loadbalancer already running")
				return nil
			}

			errResume := s.agentService.ContainerRemove(ctx, "noyra-loadbalancer")
			if errResume != nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "failed to remove loadbalancer", slog.Any("error", errResume))
				return errResume
			}
		}
	}

	containerPortMappingLb := component.ContainerPortMapping{}
	containerPortMappingLb.ContainerPort = 7777
	containerPortMappingLb.HostPort = 7777

	containerPortMappingLb2 := component.ContainerPortMapping{}
	containerPortMappingLb2.ContainerPort = 7778
	containerPortMappingLb2.HostPort = 7778

	containerRequestLb := podmanComponent.ContainerRequest{
		Image: "noyra-loadbalancer",
		Name:  "noyra-loadbalancer",
		Expose: map[uint16]string{
			7777:  "tcp",
			7778:  "tcp",
			50000: "tcp",
		},
		Networks: map[string]podmanComponent.ContainerRequestNetwork{
			"noyra": {},
		},
		Labels: map[string]string{"noyra.name": "noyra-loadbalancer"},
		Portmappings: []podmanComponent.ContainerRequestPortmapping{
			{
				ContainerPort: 7777,
				HostPort:      7777,
			},
			{
				ContainerPort: 7778,
				HostPort:      7778,
			},
		},
	}

	// Contact the server and print out its response.
	timeoutCtx2, cancel2 := context.WithTimeout(ctx, 20*time.Second)
	defer cancel2()
	_, err2 := s.agentService.ContainerCreate(timeoutCtx2, containerRequestLb)
	if err2 != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "could not start container", slog.Any("error", err2))
		return err2
	}

	errContainerStart := s.agentService.ContainerStart(ctx, "noyra-loadbalancer")

	if errContainerStart != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "could not start loadbalancer", slog.Any("error", errContainerStart))
		return oops.Wrapf(errContainerStart, "could not start loadbalancer")
	}

	return nil
}

func (s *Supervisor) startEtcd(ctx context.Context) error {
	containersList := s.agentService.ListContainers(ctx, true, map[string][]string{"label": {"noyra.name=noyra-etcd"}})

	//if errList != nil {
	//	s.logger.LogAttrs(ctx, slog.LevelError, "failed to get container", slog.Any("error", errList))
	//}

	if len(containersList) > 0 {
		for _, container := range containersList {
			if container.State == "running" {
				s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra etcd already running")
				return nil
			}

			errResume := s.agentService.ContainerStart(ctx, "noyra-etcd")
			if errResume != nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "failed to resume etcd", slog.Any("error", errResume))

				return errResume
			}

			s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra etcd resumed")
			return nil
		}
	}

	containerSupervisor, errInspect := s.agentService.InspectContainer(ctx, "noyra-supervisor")

	if errInspect != nil {
		return oops.Wrapf(errInspect, "failed to inspect container")
	}

	var containerMount []podmanComponent.ContainerRequestMount
	for _, m := range containerSupervisor.Mounts {
		containerMount = append(
			containerMount,
			podmanComponent.ContainerRequestMount{
				Destination: m.Destination,
				Type:        "bind",
				Source:      m.Source,
				ReadOnly:    true,
				BindOptions: podmanComponent.ContainerMountBindOptions{
					NonRecursive: false,
				},
			},
		)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "noyra volumes", slog.Any("volumes", containerMount))

	startRequest2 := podmanComponent.ContainerRequest{
		Image: "bitnami/etcd:3.5.21",
		Name:  "noyra-etcd",
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
		Networks: map[string]podmanComponent.ContainerRequestNetwork{
			"noyra": {},
		},
		Labels: map[string]string{
			"noyra.name": "noyra-etcd",
		},
		Mounts: containerMount,
		Volumes: []podmanComponent.ContainerRequestVolume{
			{
				Name:    "noyra-etcd-data",
				Dest:    "/bitnami/etcd/data",
				Options: []string{"U"},
			},
		},
		Portmappings: []podmanComponent.ContainerRequestPortmapping{
			{
				ContainerPort: 2379,
				HostPort:      2379,
			},
		},
	}

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, errContainerCreate := s.agentService.ContainerCreate(timeoutCtx, startRequest2)

	if errContainerCreate != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "could not create etcd", slog.Any("error", errContainerCreate))
		return oops.Wrapf(errContainerCreate, "could not create etcd")
	}

	errContainerStart := s.agentService.ContainerStart(ctx, "noyra-etcd")

	if errContainerStart != nil {
		s.logger.LogAttrs(ctx, slog.LevelError, "could not start etcd", slog.Any("error", errContainerStart))
		return oops.Wrapf(errContainerStart, "could not start etcd")
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "container start response")

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

func generateCertificate(
	caCertFile string,
	caKeyFile string,
	serverCertFile string,
	serverKeyFile string,
	clientCertFile string,
	clientKeyFile string,
	logger *slog.Logger,
) error {
	_, errCrt := os.Stat(caCertFile)
	_, errKey := os.Stat(caKeyFile)

	if errCrt == nil && errKey == nil {
		logger.LogAttrs(context.Background(), slog.LevelInfo, "certificat found")
		return nil
	}

	// Générer une nouvelle autorité de certification (CA) ou réutiliser l'existante
	// Pour cet exemple, nous générons une nouvelle CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1654),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
			CommonName:   "Noyra etcd",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		return err
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate",
			slog.Any("error", err),
		)
		return err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	if errCa := os.WriteFile(caCertFile, caPEM, 0644); errCa != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile caCertFile",
			slog.Any("error", errCa),
			slog.String("caCertFile", caCertFile),
		)
		return errCa
	}
	if errCaPriv := os.WriteFile(caKeyFile, caPrivKeyPEM, 0600); errCaPriv != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile caKeyFile",
			slog.Any("error", errCaPriv),
		)
		return errCaPriv
	}

	// Générer un nouveau certificat serveur
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1659),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
			CommonName:   "localhost",
		},
		DNSNames:    []string{"localhost", "etcd"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"GenerateKey",
			slog.Any("error", err),
		)
		return err
	}

	serverBytes, err := x509.CreateCertificate(cryptoRand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate",
			slog.Any("error", err),
		)
		return err
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	if errCrt := os.WriteFile(serverCertFile, serverPEM, 0644); errCrt != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile serverCertFile",
			slog.Any("error", errCrt),
		)
		return errCrt
	}

	if errPriv := os.WriteFile(serverKeyFile, serverPrivKeyPEM, 0600); errPriv != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile serverKeyFile",
			slog.Any("error", errPriv),
		)
		return errPriv
	}

	// Générer un nouveau certificat client
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(1660),
		Subject: pkix.Name{
			Organization: []string{"Blackprism Noyra"},
			CommonName:   "client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	clientPrivKey, err := rsa.GenerateKey(cryptoRand.Reader, 4096)
	if err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"GenerateKey clientPrivKey",
			slog.Any("error", err),
		)
		return err
	}

	clientBytes, err := x509.CreateCertificate(cryptoRand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"CreateCertificate clientBytes",
			slog.Any("error", err),
		)
		return err
	}

	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	if err := os.WriteFile(clientCertFile, clientPEM, 0644); err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile clientCertFile",
			slog.Any("error", err),
		)
		return err
	}
	if err := os.WriteFile(clientKeyFile, clientPrivKeyPEM, 0600); err != nil {
		logger.LogAttrs(
			context.Background(),
			slog.LevelInfo,
			"WriteFile clientKeyFile",
			slog.Any("error", err),
		)
		return err
	}

	return nil
}
