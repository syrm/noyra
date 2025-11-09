package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"blackprism.org/noyra/internal/etcd"
	"blackprism.org/noyra/internal/supervisor"
)

type Server struct {
	etcdClient *etcd.Client
}

// BuildAPIServer creates a new Client server
func BuildAPIServer(etcdClient *etcd.Client) *Server {
	return &Server{
		etcdClient: etcdClient,
	}
}

// Run starts the Client server
func (a *Server) Run(ctx context.Context) {
	http.HandleFunc("/deployments", a.handleDeployments)

	slog.LogAttrs(ctx, slog.LevelInfo, "client server started", slog.Int("port", 8080))
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error starting Client server", slog.Any("error", err))
	}
}

// handleDeployments handles the /deployments endpoint
func (a *Server) handleDeployments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get all deployments from etcd
	deployments, err := a.etcdClient.GetWithPrefix(ctxWithTimeout, "/deployment/")
	if err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "error getting deployments from etcd", slog.Any("error", err))
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
		slog.LogAttrs(ctx, slog.LevelError, "error encoding deployments as JSON", slog.Any("error", err))
		http.Error(w, "Error encoding deployments", http.StatusInternalServerError)
		return
	}
}
