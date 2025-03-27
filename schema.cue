package noyra

// Définition d'un service individuel
#Service: {
	name: string
	domains: [...string]
	image: string
	expose: [...=~"^[0-9]+(/(tcp|udp))?$"]

	deploy: #Deploy
}

// Configuration du déploiement
#Deploy: {
	type:     "http"
	replicas: int & >1
}

service: [serviceName=string]: #Service & {
	name: serviceName // Ajoute automatiquement le nom du service
}

service: [_]: _
if len(service) == 0 {
	_error: "Au moins un service doit être défini"
}
