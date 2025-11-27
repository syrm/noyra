package loadbalancer

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"blackprism.org/noyra/internal/loadbalancer/component"
)

type Server struct {
	chanConfiguration <-chan component.Configuration
	config            component.Configuration
	tourniquetIndex   int
	tourniquetIndexMu sync.Mutex
	logger            *slog.Logger
}

func BuildServer(chanConfiguration <-chan component.Configuration, logger *slog.Logger) *Server {
	g := &Server{
		chanConfiguration: chanConfiguration,
		logger:            logger,
	}

	return g
}

func (s *Server) Run(ctx context.Context) error {

	errChan := make(chan error)

	go func() {
		proxy := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				s.tourniquetIndexMu.Lock()
				defer s.tourniquetIndexMu.Unlock()

				var targetURL url.URL
				for _, host := range s.config.Hosts {
					// @TODO use string type instead of URL for performance
					if host.Host.String() == r.In.Host {
						targetURL = host.Targets[s.tourniquetIndex]

						if s.tourniquetIndex+1 == len(host.Targets) {
							s.tourniquetIndex = 0
							break
						}

						s.tourniquetIndex += 1
						break
					}
				}

				r.SetURL(&targetURL)
				r.Out.Host = r.In.Host

				log.Printf("%d -> Redirection vers : %s", s.tourniquetIndex, targetURL.String())
			},
		}

		http.Handle("/", proxy)

		err := http.ListenAndServe(":7777", nil)
		if err != nil {
			errChan <- err
		}
	}()

	go func() {
		for config := range s.chanConfiguration {
			s.config = config
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errChan:
		return err
	}
}
