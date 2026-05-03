package certificate

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/samber/oops"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	protoCertificate "blackprism.org/noyra/api/certificate/v1"
	"blackprism.org/noyra/internal/certificate/component"
	noyraGrpc "blackprism.org/noyra/internal/grpc"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1_000_000
)

type Option func(s *Server)

type Server struct {
	protoCertificate.UnimplementedSignerServiceServer

	cert              component.Certificate
	signer            Signer
	grpcServer        *grpc.Server
	loggerInterceptor noyraGrpc.LoggerInterceptor
	logger            *slog.Logger
}

func BuildServer(cert component.Certificate, signer Signer, logger *slog.Logger, opts ...Option) *Server {
	s := &Server{
		cert:              cert,
		signer:            signer,
		loggerInterceptor: noyraGrpc.BuildLogger(logger),
		logger:            logger,
	}

	for _, opt := range opts {
		opt(s)
	}

	go func() {
		for {
			renewAt := s.cert.Cert.NotAfter.Add(-(s.cert.Cert.NotAfter.Sub(s.cert.Cert.NotBefore) / 3))
			time.Sleep(time.Until(renewAt))

			csrPem, newKey, errGen := generateCSR()

			if errGen != nil {
				s.logger.Error("failed to decode PEM block", slog.Any("error", errGen))
				continue
			}

			csr := component.CertifyRequest{
				SigningRequest: csrPem,
			}

			certifyResponse, errCertify := s.signer.Certify(s.cert.Cert.Subject.CommonName, s.cert.Cert.ExtKeyUsage, csr, 20*time.Minute)

			if errCertify != nil {
				s.logger.Error("failed to certify CSR", slog.Any("error", errCertify))
				continue
			}

			block, _ := pem.Decode(certifyResponse.LeafCertificate)
			if block == nil {
				s.logger.Error("failed to decode PEM block", slog.String("leaf_certificate", string(certifyResponse.LeafCertificate)))
				continue
			}

			newCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				s.logger.Error("failed to parse certificate signing request", slog.Any("error", err))
				continue
			}

			s.logger.Info("cert renewed", slog.String("expiration", newCert.NotAfter.Format("2006-01-02 15:04:05")))

			s.cert.Cert = newCert
			s.cert.Key = newKey
		}
	}()

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			s.logger.Info("tls handshake",
				slog.String("signer_server_name", hi.ServerName),
				slog.String("signer_expiry", s.cert.Cert.NotAfter.Format("2006-01-02 15:04:05")),
				slog.String("signer_ca_cn", s.cert.Cert.Subject.CommonName),
				slog.Bool("signer_ca_raw_empty", len(s.cert.Cert.Raw) == 0),
			)

			s.logger.Info("client TLS handshake",
				slog.String("client_server_name", hi.ServerName),
				slog.Any("client_expiry", hi.Context()),
			)

			if len(s.cert.Cert.Raw) == 0 {
				return nil, oops.New("CA certificate not yet initialized")
			}

			s.logger.Info("ca used for client verification",
				slog.String("ca_cn", s.cert.Ca.Subject.CommonName),
				slog.String("ca_issuer", s.cert.Ca.Issuer.CommonName),
				slog.String("notAfter", s.cert.Cert.NotAfter.Format("2006-01-02 15:04:05")),
				slog.String("ca", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Ca.Raw}))),
				slog.String("ca_ski", fmt.Sprintf("%X", s.cert.Ca.SubjectKeyId)),
			)

			caPool := x509.NewCertPool()
			caPool.AddCert(s.cert.Ca)

			tlsCert := tls.Certificate{
				Certificate: [][]byte{s.cert.Cert.Raw},
				PrivateKey:  s.cert.Key,
				Leaf:        s.cert.Cert,
			}

			s.logger.Info("tls handshake return config")

			return &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				RootCAs:      caPool,
				ClientCAs:    caPool,
				Certificates: []tls.Certificate{tlsCert},
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					s.logger.Info("verify peer certificate",
						slog.Int("raw_certs", len(rawCerts)),
						slog.Int("verified_chains", len(verifiedChains)), // 0 = vérification échouée
					)
					for i, raw := range rawCerts {
						c, err := x509.ParseCertificate(raw)
						if err != nil {
							continue
						}
						s.logger.Info("peer cert",
							slog.Int("index", i),
							slog.String("cn", c.Subject.CommonName),
							slog.Time("not_after", c.NotAfter),
							slog.Bool("expired", time.Now().After(c.NotAfter)),
						)
					}
					return nil
				},
				VerifyConnection: func(cs tls.ConnectionState) error { // ← ajout
					s.logger.Info("tls verify connection",
						slog.Int("peer_certs", len(cs.PeerCertificates)),
						slog.Bool("handshake_complete", cs.HandshakeComplete),
					)
					s.logger.Info("ca pool",
						slog.String("ca_cn", s.cert.Ca.Subject.CommonName),
						slog.Time("ca_not_after", s.cert.Ca.NotAfter),
						slog.Bool("ca_raw_empty", len(s.cert.Ca.Raw) == 0),
					)
					for i, c := range cs.PeerCertificates {
						if c == nil {
							s.logger.Info("peer cert nil", slog.Int("index", i))
							continue
						}
						s.logger.Info("peer cert",
							slog.Int("index", i),
							slog.String("cn", c.Subject.CommonName),
							slog.Time("not_after", c.NotAfter),
							slog.Any("key_usage", c.ExtKeyUsage),
						)
					}
					return nil
				},
			}, nil
		},
	}

	s.grpcServer = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: grpcKeepaliveMinTime,
		}),
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		// Logging centralisé ici — les handlers ne loguent rien eux-mêmes (single handling rule)
		grpc.ChainUnaryInterceptor(
			s.loggerInterceptor.LoggingUnaryInterceptor,
			s.loggerInterceptor.RecoveryUnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			s.loggerInterceptor.LoggingStreamInterceptor,
			s.loggerInterceptor.RecoveryStreamInterceptor,
		),
	)

	protoCertificate.RegisterSignerServiceServer(s.grpcServer, s)
	// Health check obligatoire — Kubernetes readiness/liveness probes
	healthpb.RegisterHealthServer(s.grpcServer, health.NewServer())

	return s
}

func WithLoggerInterceptor(loggerInterceptor noyraGrpc.LoggerInterceptor) Option {
	return func(s *Server) {
		s.logger = loggerInterceptor.GetLogger()
		s.loggerInterceptor = loggerInterceptor
	}
}

func (s *Server) Run(ctx context.Context, port uint) error {
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("listen on :"+strconv.Itoa(int(port))+" : %w", err)
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo, "grpc server listening", slog.String("address", lis.Addr().String()))

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("grpc server: %w", err)
	case <-ctx.Done():
		return nil
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	stopped := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		s.logger.LogAttrs(ctx, slog.LevelInfo, "grpc server stopped gracefully")
	case <-ctx.Done():
		s.logger.LogAttrs(ctx, slog.LevelWarn, "grpc graceful stop timed out, forcing stop")
		s.grpcServer.Stop()
	}
}

func (s *Server) Certify(
	ctx context.Context,
	certifyRequest *protoCertificate.CertifyRequest,
) (*protoCertificate.CertifyResponse, error) {
	s.logger.Info("certify request lets go")

	s.logger.Info("certify request",
		slog.Int("csr_len", len(certifyRequest.GetCertificateSigningRequest())),
		slog.String("csr_prefix", string(certifyRequest.GetCertificateSigningRequest()[:min(64, len(certifyRequest.GetCertificateSigningRequest()))])),
	)

	request := component.CertifyRequest{
		SigningRequest: certifyRequest.GetCertificateSigningRequest(),
	}

	identity, extKeyUsage, err := s.identityFromTLS(ctx)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract identity from TLS peer")
	}

	certificate, errCert := s.signer.Certify(identity, extKeyUsage, request, 2*time.Minute)

	if errCert != nil {
		return nil, oops.Wrapf(errCert, "certify failed")
	}

	if len(certificate.LeafCertificate) > 0 {
		block, _ := pem.Decode(certificate.LeafCertificate)
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			if ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
				raw := elliptic.Marshal(ecKey.Curve, ecKey.X, ecKey.Y)
				log.Printf("[server] leaf cert public key raw: %02x", raw)
			}
		}
	}

	return protoCertificate.CertifyResponse_builder{
		LeafCertificate:          certificate.LeafCertificate,
		IntermediateCertificates: certificate.IntermediateCertificates,
		NotAfter:                 timestamppb.New(certificate.NotAfter),
	}.Build(), nil
}

func (s *Server) identityFromTLS(ctx context.Context) (string, []x509.ExtKeyUsage, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil, oops.New("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", nil, oops.New("peer connection is not TLS")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", nil, oops.New("no client certificate presented")
	}

	peerCert := tlsInfo.State.PeerCertificates[0]

	return peerCert.Subject.CommonName, peerCert.ExtKeyUsage, nil
}

func generateCSR() ([]byte, crypto.Signer, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return csrPEM, privKey, nil
}
