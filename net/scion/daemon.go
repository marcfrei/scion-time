package scion

import (
	"context"

	"go.uber.org/zap"

	"github.com/scionproto/scion/pkg/daemon"
)

func NewDaemonConnector(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func NewDaemonConnectorOption(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
	if daemonAddr == "" {
		return nil
	}
	return NewDaemonConnector(ctx, log, daemonAddr)
}
