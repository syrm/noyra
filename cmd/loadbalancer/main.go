package main

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"blackprism.org/noyra/internal/loadbalancer"
	"blackprism.org/noyra/internal/loadbalancer/component"

	gopsAgent "github.com/google/gops/agent"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}))

	errgrp, ctx := errgroup.WithContext(ctx)

	errgrp.Go(func() error {
		err := gopsAgent.Listen(gopsAgent.Options{Addr: "0.0.0.0:50000"})
		if err != nil {
			logger.LogAttrs(context.Background(), slog.LevelError, "unable to start gops agent", slog.Any("error", err))

			os.Exit(1)
		}

		return nil
	})

	chanConfiguration := make(chan component.Configuration, 1000)

	errgrp.Go(func() error {
		grpcServer := loadbalancer.BuildGrpcServer(chanConfiguration, logger)
		return grpcServer.Run(ctx)
	})

	errgrp.Go(func() error {
		server := loadbalancer.BuildServer(chanConfiguration, logger)
		return server.Run(ctx)
	})

	if errWait := errgrp.Wait(); errWait != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error starting supervisor", slog.Any("error", errWait))
	}
}
