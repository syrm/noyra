//go:build ignore
// +build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
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

		for range 2 {
			// Créer un conteneur de test (NGINX)
			startRequest := &protoContainer.ContainerStartRequest{
				Name:  "test-nginx-" + ContainerNameHash(),
				Image: "nginx:latest",
				ExposedPorts: map[uint32]string{
					80: "TCP",
				},
				Labels: map[string]string{
					"app":           "test",
					"service":       "web",
					"noyra.type":    "http",
					"noyra.cluster": "web",
					"noyra.domain":  "test-nginx",
				},
			}

			resp, err := client.ContainerStart(ctx, startRequest)
			if err != nil {
				log.Fatalf("Erreur lors du démarrage du conteneur: %v", err)
			}

			fmt.Printf("Réponse: %s\n", resp.Status)
			fmt.Printf("Message: %s\n", resp.Message)
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

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

const (
	// We omit vowels from the set of available characters to reduce the chances
	// of "bad words" being formed.
	alphanums = "bcdfghjklmnpqrstvwxz2456789"
	// No. of bits required to index into alphanums string.
	alphanumsIdxBits = 5
	// Mask used to extract last alphanumsIdxBits of an int.
	alphanumsIdxMask = 1<<alphanumsIdxBits - 1
	// No. of random letters we can extract from a single int63.
	maxAlphanumsPerInt = 63 / alphanumsIdxBits
)

// @TODO attention si appelé dans goroutine soucis de concurrence
func ContainerNameHash() string {
	b := make([]byte, 5)

	randomInt63 := rng.Int63()
	remaining := maxAlphanumsPerInt
	for i := 0; i < 5; {
		if remaining == 0 {
			randomInt63, remaining = rng.Int63(), maxAlphanumsPerInt
		}
		if idx := int(randomInt63 & alphanumsIdxMask); idx < len(alphanums) {
			b[i] = alphanums[idx]
			i++
		}
		randomInt63 >>= alphanumsIdxBits
		remaining--
	}
	return string(b)
}
