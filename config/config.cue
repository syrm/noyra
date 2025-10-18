package noyra

deployment: {
	"smallapp": {
		domains: ["smallapp.local"]
		image: "stefanprodan/podinfo"
		expose: ["9898/tcp"]
	  type: "http"
	  replicas: 3
	}
}
