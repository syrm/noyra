//go:build ignore
// +build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	protoContainer "blackprism.org/noyra/grpc-proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)

	// Vérifier les arguments
	if len(os.Args) < 2 {
		fmt.Println("Utilisation: go run test_client.go [start|list]")
		os.Exit(1)
	}

	// Établir la connexion gRPC
	conn, err := grpc.Dial("localhost:4646", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Impossible de se connecter au serveur: %v", err)
	}
	defer conn.Close()

	client := protoContainer.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch os.Args[1] {
	case "start":
		startCmd.Parse(os.Args[2:])

		// Créer un conteneur de test (NGINX)
		startRequest := &protoContainer.ContainerStartRequest{
			Name:  "test-nginx",
			Image: "nginx:latest",
			ExposedPorts: map[uint32]string{
				80: "TCP",
			},
			Labels: map[string]string{
				"app":        "test",
				"service":    "web",
				"noyra.type": "http",
			},
		}

		resp, err := client.ContainerStart(ctx, startRequest)
		if err != nil {
			log.Fatalf("Erreur lors du démarrage du conteneur: %v", err)
		}

		fmt.Printf("Réponse: %s\n", resp.Status)
		fmt.Printf("Message: %s\n", resp.Message)

		if resp.Status == "OK" {
			fmt.Println("\nLe conteneur a été démarré avec succès.")
			fmt.Println("Pour vérifier que le service discovery fonctionne:")
			fmt.Println("1. Attendez quelques secondes pour que le service discovery détecte le conteneur")
			fmt.Println("2. Vérifiez les logs du service pour voir s'il y a des mises à jour envoyées à Envoy")
			fmt.Println("3. Essayez d'accéder au service via le proxy Envoy (port 10000)")
		}

	case "list":
		listCmd.Parse(os.Args[2:])

		// Lister les conteneurs (si la méthode List est implémentée)
		// Actuellement la méthode List est commentée dans le code source
		fmt.Println("La méthode List n'est pas encore implémentée dans le service.")
		fmt.Println("Utilisez 'podman ps' pour lister les conteneurs en cours d'exécution.")

	default:
		fmt.Println("Commande inconnue")
		fmt.Println("Utilisation: go run test_client.go [start|list]")
		os.Exit(1)
	}
}
