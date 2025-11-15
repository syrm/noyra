package noyra

deployment: {
		"smallapp": {
				domains: ["smallapp.local"]
				image: "stefanprodan/podinfo"
				expose: ["9898/tcp"]
				type: "http"
				replicas: 3
		}

		"bigapp": {
				domains: ["bigapp.local"]
				image: "stefanprodan/podinfo"
				expose: ["9898/tcp"]
				type: "http"
				replicas: 5
		}
}
