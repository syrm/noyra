package noyra

deployment: {
	"smallapp": {
		domains: ["smallapp.local"]
		image: "nginx:latest"
		expose: ["80/tcp"]
	  type: "http"
	  replicas: 3
	}
}
