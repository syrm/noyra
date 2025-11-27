package component

// @TODO j'utilise pas certains champs, à retirer ?

type ContainerRequest struct {
	Name            string                             `json:"name"`
	Image           string                             `json:"image"`
	Userns          ContainerRequestUserns             `json:"userns"`
	Netns           ContainerRequestNetns              `json:"netns"`
	Command         []string                           `json:"command"`
	Env             map[string]string                  `json:"env"`
	Expose          map[uint16]string                  `json:"expose"`
	Networks        map[string]ContainerRequestNetwork `json:"Networks"`
	Labels          map[string]string                  `json:"labels"`
	Mounts          []ContainerRequestMount            `json:"mounts"`
	Volumes         []ContainerRequestVolume           `json:"volumes"`
	Portmappings    []ContainerRequestPortmapping      `json:"portmappings"`
	CapDrop         []string                           `json:"cap_drop"`
	NoNewPrivileges bool                               `json:"no_new_privileges"`
	User            string                             `json:"user"`
}

type ContainerRequestUserns struct {
	Nsmode string `json:"nsmode"`
	Value  string `json:"value"`
}

type ContainerRequestNetns struct {
	Nsmode string `json:"nsmode"`
	Value  string `json:"value"`
}

type ContainerRequestNetwork struct {
	Aliases       []string          `json:"aliases"`
	InterfaceName string            `json:"interface_name"`
	Options       map[string]string `json:"options"`
	StaticIps     []string          `json:"static_ips"`
	StaticMac     string            `json:"static_mac"`
}

type ContainerRequestMount struct {
	BindOptions    ContainerMountBindOptions `json:"ContainerMountBindOptions"`
	ClusterOptions struct{}                  `json:"ClusterOptions"`
	Consistency    string                    `json:"Consistency"`
	ImageOptions   struct {
		Subpath string `json:"Subpath"`
	} `json:"ImageOptions"`
	ReadOnly     bool   `json:"ReadOnly"`
	Source       string `json:"Source"`
	Destination  string `json:"Destination"`
	TmpfsOptions struct {
		Mode      int        `json:"Mode"`
		Options   [][]string `json:"Options"`
		SizeBytes int        `json:"SizeBytes"`
	} `json:"TmpfsOptions"`
	Type          string `json:"Type"`
	VolumeOptions struct {
		DriverConfig struct {
			Name    string            `json:"Name"`
			Options map[string]string `json:"Options"`
		} `json:"DriverConfig"`
		Labels  map[string]string `json:"Labels"`
		NoCopy  bool              `json:"NoCopy"`
		Subpath string            `json:"Subpath"`
	} `json:"VolumeOptions"`
}

type ContainerMountBindOptions struct {
	CreateMountpoint       bool   `json:"CreateMountpoint"`
	NonRecursive           bool   `json:"NonRecursive"`
	Propagation            string `json:"Propagation"`
	ReadOnlyForceRecursive bool   `json:"ReadOnlyForceRecursive"`
	ReadOnlyNonRecursive   bool   `json:"ReadOnlyNonRecursive"`
}

type ContainerRequestVolume struct {
	Dest        string   `json:"Dest"`
	IsAnonymous bool     `json:"IsAnonymous"`
	Name        string   `json:"Name"`
	Options     []string `json:"Options"`
	SubPath     string   `json:"SubPath"`
}

type ContainerRequestPortmapping struct {
	ContainerPort int    `json:"container_port"`
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	Protocol      string `json:"protocol"`
	Range         int    `json:"range"`
}

type containerExtra struct {
	Annotations     map[string]string `json:"annotations"`
	ApparmorProfile string            `json:"apparmor_profile"`
	ArtifactVolumes []struct {
		Destination string `json:"destination"`
		Digest      string `json:"digest"`
		Name        string `json:"name"`
		Source      string `json:"source"`
		Title       string `json:"title"`
	} `json:"artifact_volumes"`
	BaseHostsFile string   `json:"base_hosts_file"`
	CapAdd        []string `json:"cap_add"`
	CgroupParent  string   `json:"cgroup_parent"`
	Cgroupns      struct {
		Nsmode string `json:"nsmode"`
		Value  string `json:"value"`
	} `json:"cgroupns"`
	CgroupsMode            string   `json:"cgroups_mode"`
	ChrootDirectories      []string `json:"chroot_directories"`
	ConmonPidFile          string   `json:"conmon_pid_file"`
	ContainerCreateCommand []string `json:"containerCreateCommand"`
	CreateWorkingDir       bool     `json:"create_working_dir"`
	DependencyContainers   []string `json:"dependencyContainers"`
	DeviceCgroupRule       []struct {
		Access string `json:"access"`
		Allow  bool   `json:"allow"`
		Major  int    `json:"major"`
		Minor  int    `json:"minor"`
		Type   string `json:"type"`
	} `json:"device_cgroup_rule"`
	Devices []struct {
		FileMode int    `json:"fileMode"`
		Gid      int    `json:"gid"`
		Major    int    `json:"major"`
		Minor    int    `json:"minor"`
		Path     string `json:"path"`
		Type     string `json:"type"`
		UID      int    `json:"uid"`
	} `json:"devices"`
	DevicesFrom []string `json:"devices_from"`
	DNSOption   []string `json:"dns_option"`
	DNSSearch   []string `json:"dns_search"`
	DNSServer   []string `json:"dns_server"`
	Entrypoint  []string `json:"entrypoint"`

	EnvHost                    bool     `json:"env_host"`
	Envmerge                   []string `json:"envmerge"`
	GroupEntry                 string   `json:"group_entry"`
	Groups                     []string `json:"groups"`
	HealthCheckOnFailureAction int      `json:"health_check_on_failure_action"`
	HealthLogDestination       string   `json:"healthLogDestination"`
	HealthMaxLogCount          int      `json:"healthMaxLogCount"`
	HealthMaxLogSize           int      `json:"healthMaxLogSize"`
	Healthconfig               struct {
		Interval      int      `json:"Interval"`
		Retries       int      `json:"Retries"`
		StartInterval int      `json:"StartInterval"`
		StartPeriod   int      `json:"StartPeriod"`
		Test          []string `json:"Test"`
		Timeout       int      `json:"Timeout"`
	} `json:"healthconfig"`
	HostDeviceList []struct {
		FileMode int    `json:"fileMode"`
		Gid      int    `json:"gid"`
		Major    int    `json:"major"`
		Minor    int    `json:"minor"`
		Path     string `json:"path"`
		Type     string `json:"type"`
		UID      int    `json:"uid"`
	} `json:"host_device_list"`
	Hostadd    []string `json:"hostadd"`
	Hostname   string   `json:"hostname"`
	Hostusers  []string `json:"hostusers"`
	Httpproxy  bool     `json:"httpproxy"`
	Idmappings struct {
		AutoUserNs     bool `json:"AutoUserNs"`
		AutoUserNsOpts struct {
			AdditionalGIDMappings []struct {
				ContainerID int `json:"container_id"`
				HostID      int `json:"host_id"`
				Size        int `json:"size"`
			} `json:"AdditionalGIDMappings"`
			AdditionalUIDMappings []struct {
				ContainerID int `json:"container_id"`
				HostID      int `json:"host_id"`
				Size        int `json:"size"`
			} `json:"AdditionalUIDMappings"`
			GroupFile   string `json:"GroupFile"`
			InitialSize int    `json:"InitialSize"`
			PasswdFile  string `json:"PasswdFile"`
			Size        int    `json:"Size"`
		} `json:"AutoUserNsOpts"`
		GIDMap []struct {
			ContainerID int `json:"container_id"`
			HostID      int `json:"host_id"`
			Size        int `json:"size"`
		} `json:"GIDMap"`
		HostGIDMapping bool `json:"HostGIDMapping"`
		HostUIDMapping bool `json:"HostUIDMapping"`
		UIDMap         []struct {
			ContainerID int `json:"container_id"`
			HostID      int `json:"host_id"`
			Size        int `json:"size"`
		} `json:"UIDMap"`
	} `json:"idmappings"`
	ImageArch       string `json:"image_arch"`
	ImageOs         string `json:"image_os"`
	ImageVariant    string `json:"image_variant"`
	ImageVolumeMode string `json:"image_volume_mode"`
	ImageVolumes    []struct {
		Destination string `json:"Destination"`
		ReadWrite   bool   `json:"ReadWrite"`
		Source      string `json:"Source"`
		SubPath     string `json:"subPath"`
	} `json:"image_volumes"`
	Init              bool   `json:"init"`
	InitContainerType string `json:"init_container_type"`
	InitPath          string `json:"init_path"`
	IntelRdt          struct {
		ClosID           string   `json:"closID"`
		EnableMonitoring bool     `json:"enableMonitoring"`
		L3CacheSchema    string   `json:"l3CacheSchema"`
		MemBwSchema      string   `json:"memBwSchema"`
		Schemata         []string `json:"schemata"`
	} `json:"intelRdt"`
	Ipcns struct {
		Nsmode string `json:"nsmode"`
		Value  string `json:"value"`
	} `json:"ipcns"`
	LabelNested bool `json:"label_nested"`

	LogConfiguration struct {
		Driver  string `json:"driver"`
		Options struct {
			Property1 string `json:"property1"`
			Property2 string `json:"property2"`
		} `json:"options"`
		Path string `json:"path"`
		Size int    `json:"size"`
	} `json:"log_configuration"`
	ManagePassword bool     `json:"manage_password"`
	Mask           []string `json:"mask"`

	NetworkOptions struct {
		Property1 []string `json:"property1"`
		Property2 []string `json:"property2"`
	} `json:"network_options"`
	OciRuntime     string `json:"oci_runtime"`
	OomScoreAdj    int    `json:"oom_score_adj"`
	OverlayVolumes []struct {
		Destination string   `json:"destination"`
		Options     []string `json:"options"`
		Source      string   `json:"source"`
	} `json:"overlay_volumes"`
	PasswdEntry string `json:"passwd_entry"`
	Personality struct {
		Domain string   `json:"domain"`
		Flags  []string `json:"flags"`
	} `json:"personality"`
	Pidns struct {
		Nsmode string `json:"nsmode"`
		Value  string `json:"value"`
	} `json:"pidns"`
	Pod               string   `json:"pod"`
	Privileged        bool     `json:"privileged"`
	ProcfsOpts        []string `json:"procfs_opts"`
	PublishImagePorts bool     `json:"publish_image_ports"`
	RLimits           []struct {
		Hard int    `json:"hard"`
		Soft int    `json:"soft"`
		Type string `json:"type"`
	} `json:"r_limits"`
	RawImageName       string `json:"raw_image_name"`
	ReadOnlyFilesystem bool   `json:"read_only_filesystem"`
	ReadWriteTmpfs     bool   `json:"read_write_tmpfs"`
	Remove             bool   `json:"remove"`
	RemoveImage        bool   `json:"removeImage"`
	ResourceLimits     struct {
		BlockIO struct {
			LeafWeight            int `json:"leafWeight"`
			ThrottleReadBpsDevice []struct {
				Major int `json:"major"`
				Minor int `json:"minor"`
				Rate  int `json:"rate"`
			} `json:"throttleReadBpsDevice"`
			ThrottleReadIOPSDevice []struct {
				Major int `json:"major"`
				Minor int `json:"minor"`
				Rate  int `json:"rate"`
			} `json:"throttleReadIOPSDevice"`
			ThrottleWriteBpsDevice []struct {
				Major int `json:"major"`
				Minor int `json:"minor"`
				Rate  int `json:"rate"`
			} `json:"throttleWriteBpsDevice"`
			ThrottleWriteIOPSDevice []struct {
				Major int `json:"major"`
				Minor int `json:"minor"`
				Rate  int `json:"rate"`
			} `json:"throttleWriteIOPSDevice"`
			Weight       int `json:"weight"`
			WeightDevice []struct {
				LeafWeight int `json:"leafWeight"`
				Major      int `json:"major"`
				Minor      int `json:"minor"`
				Weight     int `json:"weight"`
			} `json:"weightDevice"`
		} `json:"blockIO"`
		CPU struct {
			Burst           int    `json:"burst"`
			Cpus            string `json:"cpus"`
			Idle            int    `json:"idle"`
			Mems            string `json:"mems"`
			Period          int    `json:"period"`
			Quota           int    `json:"quota"`
			RealtimePeriod  int    `json:"realtimePeriod"`
			RealtimeRuntime int    `json:"realtimeRuntime"`
			Shares          int    `json:"shares"`
		} `json:"cpu"`
		Devices []struct {
			Access string `json:"access"`
			Allow  bool   `json:"allow"`
			Major  int    `json:"major"`
			Minor  int    `json:"minor"`
			Type   string `json:"type"`
		} `json:"devices"`
		HugepageLimits []struct {
			Limit    int    `json:"limit"`
			PageSize string `json:"pageSize"`
		} `json:"hugepageLimits"`
		Memory struct {
			CheckBeforeUpdate bool `json:"checkBeforeUpdate"`
			DisableOOMKiller  bool `json:"disableOOMKiller"`
			Kernel            int  `json:"kernel"`
			KernelTCP         int  `json:"kernelTCP"`
			Limit             int  `json:"limit"`
			Reservation       int  `json:"reservation"`
			Swap              int  `json:"swap"`
			Swappiness        int  `json:"swappiness"`
			UseHierarchy      bool `json:"useHierarchy"`
		} `json:"memory"`
		Network struct {
			ClassID    int `json:"classID"`
			Priorities []struct {
				Name     string `json:"name"`
				Priority int    `json:"priority"`
			} `json:"priorities"`
		} `json:"network"`
		Pids struct {
			Limit int `json:"limit"`
		} `json:"pids"`
		Rdma struct {
			Property1 struct {
				HcaHandles int `json:"hcaHandles"`
				HcaObjects int `json:"hcaObjects"`
			} `json:"property1"`
			Property2 struct {
				HcaHandles int `json:"hcaHandles"`
				HcaObjects int `json:"hcaObjects"`
			} `json:"property2"`
		} `json:"rdma"`
		Unified struct {
			Property1 string `json:"property1"`
			Property2 string `json:"property2"`
		} `json:"unified"`
	} `json:"resource_limits"`
	RestartPolicy      string `json:"restart_policy"`
	RestartTries       int    `json:"restart_tries"`
	Rootfs             string `json:"rootfs"`
	RootfsMapping      string `json:"rootfs_mapping"`
	RootfsOverlay      bool   `json:"rootfs_overlay"`
	RootfsPropagation  string `json:"rootfs_propagation"`
	SdnotifyMode       string `json:"sdnotifyMode"`
	SeccompPolicy      string `json:"seccomp_policy"`
	SeccompProfilePath string `json:"seccomp_profile_path"`
	SecretEnv          struct {
		Property1 string `json:"property1"`
		Property2 string `json:"property2"`
	} `json:"secret_env"`
	Secrets []struct {
		Key    string `json:"Key"`
		Secret string `json:"Secret"`
	} `json:"secrets"`
	SelinuxOpts         []string `json:"selinux_opts"`
	ShmSize             int      `json:"shm_size"`
	ShmSizeSystemd      int      `json:"shm_size_systemd"`
	StartupHealthConfig struct {
		Interval      int      `json:"Interval"`
		Retries       int      `json:"Retries"`
		StartInterval int      `json:"StartInterval"`
		StartPeriod   int      `json:"StartPeriod"`
		Successes     int      `json:"Successes"`
		Test          []string `json:"Test"`
		Timeout       int      `json:"Timeout"`
	} `json:"startupHealthConfig"`
	Stdin       bool `json:"stdin"`
	StopSignal  int  `json:"stop_signal"`
	StopTimeout int  `json:"stop_timeout"`
	StorageOpts struct {
		Property1 string `json:"property1"`
		Property2 string `json:"property2"`
	} `json:"storage_opts"`
	Sysctl struct {
		Property1 string `json:"property1"`
		Property2 string `json:"property2"`
	} `json:"sysctl"`
	Systemd               string `json:"systemd"`
	Terminal              bool   `json:"terminal"`
	ThrottleReadBpsDevice struct {
		Property1 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property1"`
		Property2 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property2"`
	} `json:"throttleReadBpsDevice"`
	ThrottleReadIOPSDevice struct {
		Property1 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property1"`
		Property2 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property2"`
	} `json:"throttleReadIOPSDevice"`
	ThrottleWriteBpsDevice struct {
		Property1 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property1"`
		Property2 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property2"`
	} `json:"throttleWriteBpsDevice"`
	ThrottleWriteIOPSDevice struct {
		Property1 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property1"`
		Property2 struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Rate  int `json:"rate"`
		} `json:"property2"`
	} `json:"throttleWriteIOPSDevice"`
	Timeout  int    `json:"timeout"`
	Timezone string `json:"timezone"`
	Umask    string `json:"umask"`
	Unified  struct {
		Property1 string `json:"property1"`
		Property2 string `json:"property2"`
	} `json:"unified"`
	Unmask              []string `json:"unmask"`
	Unsetenv            []string `json:"unsetenv"`
	Unsetenvall         bool     `json:"unsetenvall"`
	UseImageHostname    bool     `json:"use_image_hostname"`
	UseImageHosts       bool     `json:"use_image_hosts"`
	UseImageResolveConf bool     `json:"use_image_resolve_conf"`
	User                string   `json:"user"`

	Utsns struct {
		Nsmode string `json:"nsmode"`
		Value  string `json:"value"`
	} `json:"utsns"`
	Volatile bool `json:"volatile"`

	VolumesFrom  []string `json:"volumes_from"`
	WeightDevice struct {
		Property1 struct {
			LeafWeight int `json:"leafWeight"`
			Major      int `json:"major"`
			Minor      int `json:"minor"`
			Weight     int `json:"weight"`
		} `json:"property1"`
		Property2 struct {
			LeafWeight int `json:"leafWeight"`
			Major      int `json:"major"`
			Minor      int `json:"minor"`
			Weight     int `json:"weight"`
		} `json:"property2"`
	} `json:"weightDevice"`
	WorkDir string `json:"work_dir"`
}
