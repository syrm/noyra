#!/bin/bash

# Arrêter tous les conteneurs existants
podman rm -f noyra-envoy test-nginx 2>/dev/null || true

# Arrêter le service Go (s'il est en cours d'exécution)
pkill -f "go run ." || true

# Recréer le réseau
podman network rm noyra 2>/dev/null || true
podman network create noyra

# Démarrer le service Noyra
echo "Démarrage du service Noyra..."
go run . &
NOYRA_PID=$!

# Attendre que le service soit prêt
sleep 2

# Démarrer un conteneur NGINX pour tester
echo "Démarrage du conteneur NGINX de test..."
go run test_client.go start

# Attendre que le conteneur NGINX soit prêt
sleep 2

# Vérifier que les conteneurs sont en cours d'exécution
echo "Conteneurs en cours d'exécution :"
podman ps

# Attendre un moment pour que le service discovery détecte les conteneurs
echo "Attente de 5 secondes pour que le service discovery détecte les conteneurs..."
sleep 5

# Tester l'accès via Envoy
echo "Test d'accès à NGINX via Envoy (port 10000)..."
curl -v http://localhost:10000

# Afficher les logs d'Envoy pour le débogage
echo -e "\nLogs d'Envoy :"
podman logs noyra-envoy | tail -n 20

echo -e "\nTest terminé. Appuyez sur Ctrl+C pour arrêter le service Noyra."
wait $NOYRA_PID
