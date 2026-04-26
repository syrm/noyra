package agent

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/samber/oops"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	protoAgent "blackprism.org/noyra/api/agent/v1"
)

type Client struct {
	conn   *grpc.ClientConn
	client protoAgent.AgentServiceClient
	logger *slog.Logger
}

func BuildClient(url string, logger *slog.Logger) (*Client, error) {
	conn, errGrpc := grpc.NewClient(
		url,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // mTLS !!!!!!!!!!!!!!!!
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)

	if errGrpc != nil {
		return nil, oops.Wrapf(errGrpc, "failed to build client")
	}

	return &Client{
		conn:   conn,
		client: protoAgent.NewAgentServiceClient(conn),
		logger: logger,
	}, nil
}

func (c *Client) Close() error {
	return oops.Wrapf(c.conn.Close(), "failed to close client")
}

func (c *Client) ContainerList(ctx context.Context) {
	containers, err := c.client.ContainerList(ctx, &protoAgent.ContainerListRequest{})

	if err != nil {
		return
	}

	fmt.Println(containers)
}
