package noyra

#Deployment: {
	name: string
	domains: [...string]
	image: string
	expose: [...=~"^[0-9]+(/(tcp|udp))?$"]
	type:     "http"
	replicas: int & >1
}

deployment: [deploymentName=string]: #Deployment & {
	name: deploymentName
}

deployment: [_]: _
if len(deployment) == 0 {
	_error: "At least one deployment must be configured"
}
