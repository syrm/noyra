package component

type Container struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	IPAddress   string            `json:"ip_address"`
	ExposedPort uint16            `json:"exposed_port"`
	State       string            `json:"state"`
}
