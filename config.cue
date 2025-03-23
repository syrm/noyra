package config

service: {
	"smallapp": {
		domains: ["smallapp.local"]
		image: "nginx:latest"
		expose: ["80/tcp"]

		deploy: {
			type:     "http"
			replicas: 3
		}
	}
}
