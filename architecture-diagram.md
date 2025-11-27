# Noyra Architecture Diagram

## High-Level System Architecture

```mermaid
graph TB
    subgraph "Noyra Container Orchestrator"
        subgraph "Core Services"
            API[API Service<br/>Port: 8080<br/>REST Endpoints]
            Supervisor[Supervisor Service<br/>Deployment Management<br/>CUE Configuration]
            Agent[Agent Service<br/>Port: 4646<br/>Podman Interface]
            Discovery[Discovery Service<br/>Port: 18000<br/>Envoy XDS Server]
        end

        subgraph "Storage Layer"
            etcd[etcd Cluster<br/>Port: 2379<br/>TLS Secured]
        end

        subgraph "Service Mesh"
            Envoy[Envoy Proxy<br/>Dynamic Configuration<br/>Load Balancing]
        end

        subgraph "Container Runtime"
            Podman[Podman v5.4.1<br/>Container Management<br/>Network Bridging]
        end

        subgraph "Configuration"
            CUE[Declarative Config<br/>CUE Language<br/>Schema Validation]
            EnvVars[Environment Variables<br/>Runtime Config]
        end

        subgraph "Container Network"
            Network[Noyra Bridge Network<br/>10.66.0.0/16<br/>Container Isolation]
        end
    end

    subgraph "External Systems"
        Users[Users/Administrators]
        ContainerImages[Container Registries]
        Monitoring[Monitoring Systems]
    end

    %% Connections
    Users --> API
    API --> etcd
    Supervisor --> CUE
    Supervisor --> etcd
    Supervisor --> Agent
    Agent --> Podman
    Podman --> Network
    Agent --> ContainerImages
    Discovery --> Agent
    Discovery --> Envoy
    Envoy --> Network
    Envoy --> Monitoring
    Supervisor --> EnvVars

    %% Styling
    classDef core fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef storage fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef runtime fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef mesh fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef config fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef external fill:#f5f5f5,stroke:#424242,stroke-width:2px

    class API,Supervisor,Agent,Discovery core
    class etcd storage
    class Podman,Network runtime
    class Envoy mesh
    class CUE,EnvVars config
    class Users,ContainerImages,Monitoring external
```

## Detailed Component Architecture

```mermaid
graph TB
    subgraph "Noyra Main Process"
        Main[main.go<br/>Entry Point<br/>Service Orchestration]
    end

    subgraph "Agent Service (Port 4646)"
        AgentGRPC[gRPC Server]
        ContainerMgmt[Container Management]
        NetworkMgmt[Network Management]
        EventStream[Event Streaming]
        ImageMgmt[Image Management]

        AgentGRPC --> ContainerMgmt
        AgentGRPC --> NetworkMgmt
        AgentGRPC --> EventStream
        AgentGRPC --> ImageMgmt
    end

    subgraph "Supervisor Service"
        ConfigParser[CUE Parser<br/>Schema Validation]
        DeploymentMgmt[Deployment Management]
        ClusterState[Cluster State<br/>Replica Management]
        HealthMon[Health Monitoring]
        CertMgmt[Certificate Management]

        ConfigParser --> DeploymentMgmt
        DeploymentMgmt --> ClusterState
        DeploymentMgmt --> HealthMon
        DeploymentMgmt --> CertMgmt
    end

    subgraph "Discovery Service (Port 18000)"
        XDSServer[XDS Server<br/>Envoy Control Plane]
        EndpointDisc[Endpoint Discovery]
        RouteMgmt[Route Management]
        LoadBalance[Load Balancing Config]

        XDSServer --> EndpointDisc
        XDSServer --> RouteMgmt
        XDSServer --> LoadBalance
    end

    subgraph "API Service (Port 8080)"
        RESTServer[HTTP Server]
        DeploymentAPI[Deployments API<br/>GET /deployments]
        APIAuth[Authentication<br/>Authorization]

        RESTServer --> DeploymentAPI
        RESTServer --> APIAuth
    end

    subgraph "etcd Integration"
        etcdClient[etcd Client v3.5.21]
        TLSClient[TLS Client<br/>Certificate Auth]
        KVStore[Key-Value Operations<br/>Prefix Queries]
        Watchers[Real-time Watchers]

        etcdClient --> TLSClient
        etcdClient --> KVStore
        etcdClient --> Watchers
    end

    subgraph "Podman Integration"
        PodmanAPI[Podman API v5.4.1]
        ContainerOps[Container Operations<br/>Start/Stop/Remove]
        NetworkOps[Network Operations<br/>Bridge Creation]
        ImageOps[Image Operations<br/>Pull/Tag]

        PodmanAPI --> ContainerOps
        PodmanAPI --> NetworkOps
        PodmanAPI --> ImageOps
    end

    %% Service Communication
    Main --> AgentGRPC
    Main --> ConfigParser
    Main --> XDSServer
    Main --> RESTServer
    Main --> etcdClient

    DeploymentMgmt --> etcdClient
    HealthMon --> ContainerMgmt
    XDSServer --> EventStream
    ContainerMgmt --> PodmanAPI
    NetworkMgmt --> NetworkOps
    ImageMgmt --> ImageOps

    %% Styling
    classDef main fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef service fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    classDef integration fill:#fff8e1,stroke:#f57c00,stroke-width:2px
    classDef component fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px

    class Main main
    class AgentGRPC,ConfigParser,XDSServer,RESTServer service
    class etcdClient,PodmanAPI integration
    class ContainerMgmt,DeploymentMgmt,EndpointDisc component
```

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Supervisor
    participant Agent
    participant Podman
    participant Discovery
    participant Envoy
    participant etcd

    %% Configuration Deployment
    User->>API: Submit Deployment (CUE)
    API->>Supervisor: Parse Configuration
    Supervisor->>Supervisor: Validate Schema
    Supervisor->>etcd: Store Deployment State
    Supervisor->>Agent: Create Container Request

    %% Container Creation
    Agent->>Podman: Pull Image
    Agent->>Podman: Create Container
    Agent->>Podman: Start Container
    Podman->>Agent: Container Events
    Agent->>Discovery: Container State Update

    %% Service Discovery
    Discovery->>Envoy: Update XDS Configuration
    Envoy->>Envoy: Reload Configuration
    Discovery->>etcd: Update Service State

    %% Health Monitoring
    Supervisor->>Agent: Health Check
    Agent->>Podman: Container Status
    Podman->>Agent: Status Response
    Agent->>Supervisor: Health Report
    Supervisor->>etcd: Update Cluster State

    %% Scaling Operations
    Supervisor->>Supervisor: Evaluate Scaling Rules
    Supervisor->>Agent: Scale Request
    Agent->>Podman: Start/Stop Containers
    Podman->>Agent: Scaling Confirmation
    Agent->>Discovery: Update Endpoints

    %% API Queries
    User->>API: GET /deployments
    API->>etcd: Query Deployment State
    etcd->>API: Return Deployment Data
    API->>User: Deployment List
```

## Network Architecture

```mermaid
graph TB
    subgraph "Host System"
        subgraph "Noyra Network Namespace"
            subgraph "Noyra Bridge Network (10.66.0.0/16)"
                Bridge[noyra-br0<br/>Bridge Interface]
                Subnet[10.66.0.0/16<br/>Container Subnet]

                subgraph "Container Network Endpoints"
                    Container1[Container 1<br/>10.66.0.2:8080]
                    Container2[Container 2<br/>10.66.0.3:8080]
                    ContainerN[Container N<br/>10.66.0.N:8080]
                end

                subgraph "Services Network"
                    etcdNet[etcd<br/>10.66.0.10:2379]
                    EnvoyNet[Envoy<br/>10.66.0.20:80]
                end
            end
        end

        subgraph "Host Network Namespace"
            HostInterfaces[Host Network Interfaces]
            PortBindings[Port Bindings<br/>80->Envoy:80<br/>8080->API:8080<br/>4646->Agent:4646<br/>18000->Discovery:18000]
        end
    end

    subgraph "External Network"
        Internet[Internet/External Clients]
        ContainerRegistries[Container Registries]
    end

    %% Network Connections
    Bridge --> Subnet
    Subnet --> Container1
    Subnet --> Container2
    Subnet --> ContainerN
    Subnet --> etcdNet
    Subnet --> EnvoyNet

    HostInterfaces --> PortBindings
    PortBindings --> Internet
    PortBindings --> ContainerRegistries

    %% Styling
    classDef bridge fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef container fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef service fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef host fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef external fill:#f5f5f5,stroke:#616161,stroke-width:2px

    class Bridge,Subnet bridge
    class Container1,Container2,ContainerN container
    class etcdNet,EnvoyNet service
    class HostInterfaces,PortBindings host
    class Internet,ContainerRegistries external
```

## Security Architecture

```mermaid
graph TB
    subgraph "Security Layers"
        subgraph "Transport Layer Security"
            TLS[TLS 1.3<br/>Certificate-based Auth]
            CACert[CA Certificate<br/>Root of Trust]
            ClientCerts[Client Certificates<br/>Service Identity]

            CACert --> TLS
            ClientCerts --> TLS
        end

        subgraph "Network Security"
            NetworkIsol[Network Isolation<br/>Bridge Network]
            FirewallRules[Firewall Rules<br/>Port Restrictions]
            ContainerLabels[Container Labels<br/>Security Metadata]

            NetworkIsol --> FirewallRules
            ContainerLabels --> FirewallRules
        end

        subgraph "Service Authentication"
            MutualTLS[Mutual TLS<br/>Service-to-Service]
            etcdAuth[etcd Authentication<br/>Certificate-based]
            gRPCAuth[gRPC Authentication<br/>Client Certs]

            MutualTLS --> etcdAuth
            MutualTLS --> gRPCAuth
        end

        subgraph "Container Security"
            PodmanSecurity[Podman Security<br/>Rootless Containers]
            Seccomp[Seccomp Profiles<br/>System Call Filtering]
            ReadOnly[ReadOnly Filesystems<br/>Immutable Config]

            PodmanSecurity --> Seccomp
            PodmanSecurity --> ReadOnly
        end
    end

    subgraph "Trust Boundaries"
        ExternalBoundary[External Trust Boundary<br/>Public API]
        InternalBoundary[Internal Trust Boundary<br/>Service Communication]
        ContainerBoundary[Container Trust Boundary<br/>Isolated Runtime]
    end

    %% Security Flow
    TLS --> ExternalBoundary
    MutualTLS --> InternalBoundary
    PodmanSecurity --> ContainerBoundary

    %% Styling
    classDef security fill:#ffebee,stroke:#b71c1c,stroke-width:2px
    classDef boundary fill:#e8eaf6,stroke:#3f51b5,stroke-width:2px
    classDef component fill:#fff8e1,stroke:#ff8f00,stroke-width:2px

    class TLS,CACert,ClientCerts,NetworkIsol,FirewallRules,MutualTLS,PodmanSecurity security
    class ExternalBoundary,InternalBoundary,ContainerBoundary boundary
    class ContainerLabels,etcdAuth,gRPCAuth,Seccomp,ReadOnly component
```

## Technology Stack

```mermaid
mindmap
  root((Noyra))
    Core Technologies
      Go Programming Language
        Go Modules
        Concurrency
        Standard Library
      Container Runtime
        Podman v5.4.1
        OCI Runtime Spec
        Container Images
    Service Mesh
      Envoy Proxy
        XDS Protocol
        Load Balancing
        Dynamic Configuration
      Go Control Plane
        xDS APIs
        Configuration Management
    Configuration Management
      CUE Language
        Declarative Config
        Schema Validation
        Type Safety
    Distributed Storage
      etcd v3.5.21
        Key-Value Store
        TLS Security
        Watchers
    Communication
      gRPC
        Protocol Buffers
        Inter-Service Communication
      HTTP/REST
        External API
        Client Interface
    Security
      TLS 1.3
        Certificate Management
        Mutual Authentication
      Container Security
        Rootless Containers
        Network Isolation
    Monitoring & Observability
      Event Streaming
        Container Lifecycle
        Real-time Updates
      Health Monitoring
        Container Health
        Service Availability
```

## Deployment Model

```mermaid
graph TB
    subgraph "Single-Server Deployment"
        subgraph "Application Layer"
            NoyraServices[Noyra Services<br/>4 Core Processes]
            Containers[Application Containers<br/>User Deployments]
            ServiceMesh[Service Mesh<br/>Envoy Proxy]
        end

        subgraph "Storage Layer"
            etcdData[etcd Data Directory<br/>/var/lib/noyra/etcd]
            ConfigFiles[Configuration Files<br/>CUE Schemas]
            CertStore[Certificate Store<br/>TLS Certificates]
        end

        subgraph "Network Layer"
            HostNetwork[Host Network<br/>Public Services]
            ContainerNetwork[Container Network<br/>Noyra Bridge]
            PortMapping[Port Mapping<br/>Service Exposure]
        end

        subgraph "System Integration"
            PodmanSocket[Podman Socket<br/>Runtime Communication]
            Systemd[Systemd Services<br/>Process Management]
            Filesystem[Filesystem<br/>Data Persistence]
        end
    end

    subgraph "Configuration Sources"
        EnvVars[Environment Variables]
        ConfigFiles2[Configuration Files]
        CommandLine[Command Line Arguments]
    end

    subgraph "External Dependencies"
        ContainerRegistries[Container Registries]
        PackageRepositories[Package Repositories]
        SystemLibraries[System Libraries]
    end

    %% Deployment Connections
    NoyraServices --> etcdData
    NoyraServices --> ConfigFiles
    NoyraServices --> CertStore
    NoyraServices --> PodmanSocket
    NoyraServices --> Systemd

    Containers --> ContainerNetwork
    ServiceMesh --> PortMapping
    ServiceMesh --> HostNetwork

    EnvVars --> NoyraServices
    ConfigFiles2 --> NoyraServices
    CommandLine --> NoyraServices

    NoyraServices --> ContainerRegistries
    Systemd --> PackageRepositories
    Filesystem --> SystemLibraries

    %% Styling
    classDef deployment fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef storage fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef network fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef integration fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef external fill:#f5f5f5,stroke:#424242,stroke-width:2px

    class NoyraServices,Containers,ServiceMesh deployment
    class etcdData,ConfigFiles,CertStore storage
    class HostNetwork,ContainerNetwork,PortMapping network
    class PodmanSocket,Systemd,Filesystem integration
    class EnvVars,ConfigFiles2,CommandLine,ContainerRegistries,PackageRepositories,SystemLibraries external
```

---

## Summary

Noyra is a sophisticated container orchestrator that provides:

1. **Lightweight Alternative**: Simplified Kubernetes-like functionality for single-server deployments
2. **Modern Architecture**: Microservice-based design with clear separation of concerns
3. **Service Mesh Integration**: Built-in Envoy proxy for advanced load balancing and service discovery
4. **Declarative Configuration**: CUE language for type-safe, validated configurations
5. **Production Ready**: TLS security, health monitoring, and persistent state management

The architecture follows cloud-native principles while remaining simple enough for single-server deployments, making it ideal for edge computing, development environments, or small-scale production workloads.