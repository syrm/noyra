package grpc

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoggerInterceptor interface {
	GetLogger() *slog.Logger

	LoggingUnaryInterceptor(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error)

	LoggingStreamInterceptor(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error

	RecoveryUnaryInterceptor(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error)

	RecoveryStreamInterceptor(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error)
}

type Logger struct {
	logger *slog.Logger
}

func BuildLogger(logger *slog.Logger) *Logger {
	return &Logger{logger: logger}
}

func (l *Logger) GetLogger() *slog.Logger {
	return l.logger
}

func (l *Logger) LoggingUnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	l.logger.LogAttrs(ctx, slog.LevelInfo, "interceptor reached",
		slog.String("method", info.FullMethod),
	)

	start := time.Now()
	resp, err := handler(ctx, req)
	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelError
	}
	l.logger.LogAttrs(ctx, level, "grpc unary",
		slog.String("method", info.FullMethod),
		slog.Duration("duration", time.Since(start)),
		slog.String("code", status.Code(err).String()),
	)
	return resp, err
}

func (l *Logger) LoggingStreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	start := time.Now()
	err := handler(srv, ss)
	l.logger.LogAttrs(ss.Context(), slog.LevelInfo, "grpc stream",
		slog.String("method", info.FullMethod),
		slog.Duration("duration", time.Since(start)),
		slog.String("code", status.Code(err).String()),
	)
	return err
}

func (l *Logger) RecoveryUnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp any, err error) {
	println("on RecoveryUnaryInterceptor")

	defer func() {
		if r := recover(); r != nil {
			l.logger.LogAttrs(ctx, slog.LevelError, "grpc panic recovered",
				slog.String("method", info.FullMethod),
				slog.Any("panic", r),
			)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

func (l *Logger) RecoveryStreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			l.logger.LogAttrs(ss.Context(), slog.LevelError, "grpc stream panic recovered",
				slog.String("method", info.FullMethod),
				slog.Any("panic", r),
			)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(srv, ss)
}
