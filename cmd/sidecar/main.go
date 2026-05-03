package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type Cert struct {
	filename string
	cert     x509.Certificate
}

const (
	certExtension = ".pem"
	keyExtension  = "-key.pem"
)

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	r := Renewer{logger: logger}

	go r.RotateHandler(ctx, "/certs")

	a, e := BuildClient("host.containers.internal:4545", logger)

	if e != nil {
		println(e.Error())
	}

	for {
		time.Sleep(10 * time.Second)
		println("ListContainer:")

		a.ContainerList(ctx)
	}
}

type Renewer struct {
	logger *slog.Logger
}

func (r Renewer) RotateHandler(ctx context.Context, certsDir string) error {
	certsSorted, err := r.loadAndSortCerts(certsDir)
	if err != nil {
		return fmt.Errorf("initial load: %w", err)
	}

	if len(certsSorted) == 0 {
		return nil
	}

	for {
		cert := certsSorted[0]
		certsSorted = certsSorted[1:]

		newCert, err := r.renew(ctx, cert)
		if err != nil {
			slog.Error("renewal failed", "subject", cert.cert.Subject.CommonName, "err", err)
			// Retry dans 30s — on réinsère avec un NotAfter fictif
			retryCert := cert
			retryCert.cert.NotAfter = time.Now().Add(45 * time.Second)
			certsSorted = r.insertSorted(certsSorted, retryCert)
			continue
		}

		certsSorted = r.insertSorted(certsSorted, *newCert)
	}
}

func (r Renewer) loadAndSortCerts(certsDir string) ([]Cert, error) {
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil, fmt.Errorf("read certs dir: %w", err)
	}

	var certs []Cert
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), certExtension) {
			continue
		}

		data, err := os.ReadFile(filepath.Join(certsDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read cert %s: %w", entry.Name(), err)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			// log warn
			continue
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert %s: %w", entry.Name(), err)
		}

		// Ignorer les CA
		if cert.IsCA {
			continue
		}

		certs = append(certs, Cert{filename: strings.TrimSuffix(entry.Name(), certExtension), cert: *cert})
	}

	slices.SortFunc(certs, func(a, b Cert) int {
		return r.renewAt(a).Compare(r.renewAt(b))
	})

	return certs, nil
}

func (r Renewer) renewAt(cert Cert) time.Time {
	lifetime := cert.cert.NotAfter.Sub(cert.cert.NotBefore)
	return cert.cert.NotAfter.Add(-(lifetime / 3))
}

func (r Renewer) insertSorted(certs []Cert, cert Cert) []Cert {
	idx, _ := slices.BinarySearchFunc(certs, cert, func(a, b Cert) int {
		return r.renewAt(a).Compare(r.renewAt(b))
	})
	return slices.Insert(certs, idx, cert)
}

func (r Renewer) renew(ctx context.Context, old Cert) (*Cert, error) {
	time.Sleep(time.Until(r.renewAt(old)))

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:     old.cert.Subject,
		DNSNames:    old.cert.DNSNames,
		IPAddresses: old.cert.IPAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	body, err := json.Marshal(map[string]string{
		"csr": string(csrPEM),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	_ = keyPEM
	_ = body

	return nil, nil

	/*
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.supervisorURL+"/certs/renew", bytes.NewReader(body))
			if err != nil {
				return nil, fmt.Errorf("build request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+s.token)

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("http request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("supervisor error %d: %s", resp.StatusCode, body)
			}

			var result struct {
				Certificate string `json:"certificate"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return nil, fmt.Errorf("decode response: %w", err)
			}

			block, _ := pem.Decode([]byte(result.Certificate))
			if block == nil {
				return nil, fmt.Errorf("invalid certificate PEM in response")
			}

			newCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}

			// Écriture atomique — la clé ne quitte jamais le sidecar
			if err := writePEMAtomic(s.certsDir, old.filename+keyExtension, keyPEM); err != nil {
				return nil, fmt.Errorf("write key: %w", err)
			}
			if err := writePEMAtomic(s.certsDir, old.filename+certExtension, []byte(result.Certificate)); err != nil {
				return nil, fmt.Errorf("write cert: %w", err)
			}

		return &Cert{filename: old.filename, cert: *newCert}, nil

	*/
}

func (r Renewer) writePEMAtomic(dir, filename string, data []byte) error {
	path := filepath.Join(dir, filename)
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
