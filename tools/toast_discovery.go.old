// +build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Établir la connexion gRPC avec le service discovery
	conn, err := grpc.Dial("localhost:18000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Impossible de se connecter au serveur discovery: %v", err)
	}
	defer conn.Close()

	// Créer un client pour le service AggregatedDiscoveryService
	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Créer une demande de découverte pour les endpoints
	req := &discoveryv3.DiscoveryRequest{
		VersionInfo:   "0",
		ResourceNames: []string{},
		TypeUrl:       "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
		ResponseNonce: "",
		Node: &discoveryv3.Node{
			Id:      "test-node",
			Cluster: "test-cluster",
		},
	}

	// Établir un stream bidirectionnel pour recevoir les mises à jour
	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		log.Fatalf("Erreur lors de l'établissement du stream: %v", err)
	}

	// Envoyer la demande initiale
	if err := stream.Send(req); err != nil {
		log.Fatalf("Erreur lors de l'envoi de la demande: %v", err)
	}

	fmt.Println("Demande envoyée, en attente de réponse...")

	// Attendre la réponse
	resp, err := stream.Recv()
	if err != nil {
		log.Fatalf("Erreur lors de la réception de la réponse: %v", err)
	}

	fmt.Printf("Réponse reçue:\n")
	fmt.Printf("  Version: %s\n", resp.GetVersionInfo())
	fmt.Printf("  Type: %s\n", resp.GetTypeUrl())
	fmt.Printf("  Nonce: %s\n", resp.GetNonce())
	fmt.Printf("  Nombre de ressources: %d\n", len(resp.GetResources()))

	// Afficher les détails des ressources
	for i, res := range resp.GetResources() {
		fmt.Printf("Ressource %d: %d octets\n", i+1, len(res.Value))
	}
}
