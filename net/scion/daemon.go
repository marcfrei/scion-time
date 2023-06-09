package scion

import (
	"context"

	"github.com/scionproto/scion/pkg/daemon"
)

func NewDaemonConnector(ctx context.Context, daemonAddr string) daemon.Connector {
	if daemonAddr == "" {
		return nil
	}
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		return nil
	}
	return c
}
