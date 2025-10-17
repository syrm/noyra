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
	"log"
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

	"blackprism.org/noyra/agent"
	"blackprism.org/noyra/etcd"
	protoAgent "blackprism.org/noyra/grpc-proto/agent"
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
		slog.LogAttrs(ctx, slog.LevelError, "Error while getting value from etcd", slog.Any("error", err))
		return err
	}

	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error while decoding base64 value", slog.Any("error", err))
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
		slog.LogAttrs(ctx, slog.LevelError, "Error while decoding base64 value", slog.Any("error", err))
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
	schema       string
}

func BuildSupervisor(agentService *agent.Agent, etcdClient *etcd.Client, schema string) *Supervisor {
	return &Supervisor{
		agentService: agentService,
		etcdClient:   etcdClient,
		schema:       schema,
	}
}

func (s *Supervisor) loadConfig(configDir string) error {
	cuectx := cuecontext.New()

	schemaVal := cuectx.CompileString(s.schema)
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
		slog.LogAttrs(ctx, slog.LevelError, "Error in configuration", slog.Any("error", err))
		os.Exit(1)
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Supervisor starting")
	s.generateCertificat()
	s.initEtcd(ctx)
	// @TODO attention etcd n'a pas encore été démarré
	s.saveClusterState(ctx)
	slog.LogAttrs(ctx, slog.LevelInfo, "Deploying toc toc", slog.Int("services", len(s.config.Deployment)))

	for _, service := range s.config.Deployment {
		slog.LogAttrs(ctx, slog.LevelInfo, "Deploying service", slog.String("service", service.Name))
		s.deployService(ctx, service)
	}

	s.observeCluster(ctx)
}

func (s *Supervisor) saveClusterState(ctx context.Context) {
	containerLists, err := s.agentService.Direct.ContainerList(ctx, &protoAgent.ContainerListRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error while calling ContainerList", slog.Any("error", err))
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
			slog.LogAttrs(ctx, slog.LevelError, "Error while writing to etcd", slog.Any("error", err))
		}
	}

	d := Deployment{}
	errRead := d.ReadInto(ctx, s.etcdClient, "/deployment/smallapp")
	if errRead != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error while reading deployment", slog.Any("error", errRead))
		return
	}
	fmt.Printf("Deployment: %+v\n", d)
}

func (s *Supervisor) observeCluster(ctx context.Context) {
	stream, err := s.agentService.Direct.ContainerListener(ctx, &protoAgent.ContainerListenerRequest{})

	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error while calling ContainerListener", slog.Any("error", err))
		os.Exit(1)
	}

	for {
		feature, _ := stream.Recv()
		slog.LogAttrs(ctx, slog.LevelInfo, "Container event received", slog.Any("feature", feature))
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
		slog.LogAttrs(ctx, slog.LevelError, "Failed to get containers", slog.Any("error", err))
		return
	}

	containerToDeploy := max(deploymentConfig.Replicas-len(containersList.GetContainers()), 0)

	if containerToDeploy == 0 {
		slog.LogAttrs(ctx, slog.LevelInfo, "No new container to deploy for service", slog.String("service", deploymentConfig.Name))
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
		slog.LogAttrs(ctx, slog.LevelInfo, "Starting to deploy container", slog.Any("name", deploymentConfig.Name))

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
			slog.LogAttrs(ctx, slog.LevelError, "Failed to start container", slog.Any("error", err))
		}
	}
}

func (s *Supervisor) generateCertificat() {
	_, errCrt := os.Stat("certs/etcd-ca.crt")
	_, errKey := os.Stat("certs/etcd-ca.key")

	if errCrt == nil && errKey == nil {
		slog.LogAttrs(context.Background(), slog.LevelInfo, "Certificat existant trouvé")
		return
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
		//log.Fatalf("Erreur: %v", err)
	}

	caBytes, err := x509.CreateCertificate(cryptoRand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatalf("Erreur: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	if errCa := os.WriteFile("certs/etcd-ca.crt", caPEM, 0644); err != nil {
		log.Fatal(errCa)
	}
	if errCaPriv := os.WriteFile("certs/etcd-ca.key", caPrivKeyPEM, 0600); err != nil {
		log.Fatal(errCaPriv)
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
		// log.Fatalf("Erreur: %v", err)
	}

	serverBytes, err := x509.CreateCertificate(cryptoRand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		// log.Fatalf("Erreur: %v", err)
	}

	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	if errCrt := os.WriteFile("certs/etcd-server.crt", serverPEM, 0644); err != nil {
		log.Fatal(errCrt)
	}

	if errPriv := os.WriteFile("certs/etcd-server.key", serverPrivKeyPEM, 0600); err != nil {
		log.Fatal(errPriv)
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
		// log.Fatalf("Erreur: %v", err)
	}

	clientBytes, err := x509.CreateCertificate(cryptoRand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		// log.Fatalf("Erreur: %v", err)
	}

	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	if err := os.WriteFile("certs/etcd-client.crt", clientPEM, 0644); err != nil {
		// log.Fatal(err)
	}
	if err := os.WriteFile("certs/etcd-client.key", clientPrivKeyPEM, 0600); err != nil {
		// log.Fatal(err)
	}

	// log.Println("Nouveaux certificats générés avec succès")
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
		slog.LogAttrs(ctx, slog.LevelInfo, "Noyra Etcd already running")
		return
	}

	certPath := "/mnt/data/src/go/noyra/certs"
	containerMount := &protoAgent.ContainerMount{}
	containerMount.SetDestination("/certs")
	containerMount.SetType("bind")
	containerMount.SetSource(certPath)
	containerMount.SetOptions([]string{"rbind", "ro"})

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
	startRequest.SetMounts([]*protoAgent.ContainerMount{containerMount})
	startRequest.SetVolumes([]*protoAgent.ContainerVolume{containerVolume})
	startRequest.SetPortMappings([]*protoAgent.ContainerPortMapping{containerPortMapping})

	// Contact the server and print out its response.
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r, err := s.agentService.Direct.ContainerStart(timeoutCtx, startRequest)
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Could not start container", slog.Any("error", err))
		os.Exit(1)
	}
	slog.LogAttrs(ctx, slog.LevelInfo, "Container start response", slog.String("status", r.GetStatus()))
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
