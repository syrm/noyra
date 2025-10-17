package api_server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"blackprism.org/noyra/etcd"
	"blackprism.org/noyra/supervisor"
)

type ApiServer struct {
	etcdClient *etcd.Client
}

// BuildAPIServer creates a new API server
func BuildAPIServer(etcdClient *etcd.Client) *ApiServer {
	return &ApiServer{
		etcdClient: etcdClient,
	}
}

// Run starts the API server
func (a *ApiServer) Run(ctx context.Context) {
	http.HandleFunc("/deployments", a.handleDeployments)

	slog.LogAttrs(ctx, slog.LevelInfo, "API server started", slog.Int("port", 8080))
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error starting API server", slog.Any("error", err))
	}
}

// handleDeployments handles the /deployments endpoint
func (a *ApiServer) handleDeployments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get all deployments from etcd
	deployments, err := a.etcdClient.GetWithPrefix(ctxWithTimeout, "/deployment/")
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error getting deployments from etcd", slog.Any("error", err))
		http.Error(w, "Error getting deployments", http.StatusInternalServerError)
		return
	}

	// Parse deployments and convert to JSON
	result := make(map[string]supervisor.Deployment)
	for key, value := range deployments {
		// Extract deployment name from key
		name := strings.TrimPrefix(key, "/deployment/")

		// Decode deployment from etcd
		deployment := supervisor.Deployment{}
		deployment.ReadFromValue(ctx, value)

		result[name] = deployment
	}

	// Set content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Encode result as JSON and write to response
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "Error encoding deployments as JSON", slog.Any("error", err))
		http.Error(w, "Error encoding deployments", http.StatusInternalServerError)
		return
	}
}
