package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"blackprism.org/noyra/agent"
)

type API struct {
	agent     *agent.Agent
	serverMux *http.ServeMux
}

func BuildAPI() *API {
	return &API{
		serverMux: http.NewServeMux(),
	}
}

func (api *API) Run() {
	api.serverMux.HandleFunc("/containers", api.ListContainer())
}

func (api *API) ListContainer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filters := make(map[string][]string)

		var labels []string
		for name, values := range r.URL.Query() {
			if name == "id" {
				filters[name] = values
			}

			if strings.Index(name, "label.") == -1 {
				continue
			}

			// we can't filter several values for the same name, so we take the first value
			labels = append(labels, name[6:]+"="+values[0])
		}

		if len(labels) > 0 {
			filters["label"] = labels
		}

		containersList := api.agent.ListContainer(filters)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(containersList)
	}
}
