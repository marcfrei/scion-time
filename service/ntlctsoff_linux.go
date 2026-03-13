//go:build linux

package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/driver/ntl"
)

const (
	ntlCTSOffInterval = time.Second
)

func ntlCTSOffConfig(log *slog.Logger, config string) (ctsDev string, idx0, idx1 int, doff time.Duration) {
	t := strings.Split(config, ",")
	if len(t) != 3 && len(t) != 4 {
		logbase.Fatal(log, "unexpected NTL CTS offset config format",
			slog.String("config", config))
	}

	ctsDev = t[0]
	if ctsDev == "" {
		logbase.Fatal(log, "unexpected NTL CTS offset config format",
			slog.String("config", config))
	}

	var err error
	idx0, err = strconv.Atoi(t[1])
	if err != nil {
		logbase.Fatal(log, "unexpected NTL CTS offset clock index",
			slog.String("config", config), slog.Any("error", err))
	}

	idx1, err = strconv.Atoi(t[2])
	if err != nil {
		logbase.Fatal(log, "unexpected NTL CTS offset clock index",
			slog.String("config", config), slog.Any("error", err))
	}

	var o int
	if len(t) > 3 {
		o, err = strconv.Atoi(t[3])
		if err != nil {
			logbase.Fatal(log, "unexpected NTL CTS offset reference delta",
				slog.String("config", config), slog.Any("error", err))
		}
	}
	doff = time.Duration(o) * time.Second

	return ctsDev, idx0, idx1, doff
}

func StartNTLCTSOff(log *slog.Logger, config string) {
	if config == "" {
		return
	}

	ctsDev, idx0, idx1, doff := ntlCTSOffConfig(log, config)

	cts, err := ntl.OpenCrossTimestamper(log, ctsDev)
	if err != nil {
		logbase.Fatal(log, "failed to open NTL cross timestamper",
			slog.String("dev", ctsDev), slog.Any("error", err))
	}

	n, err := cts.NumSources()
	if err != nil {
		logbase.Fatal(log, "failed to get NTL source count",
			slog.String("dev", ctsDev), slog.Any("error", err))
	}
	if n < 0 || n > 1<<8 {
		logbase.Fatal(log, "invalid NTL source count",
			slog.String("dev", ctsDev), slog.Int("count", n))
	}
	if idx0 < 0 || idx0 >= n {
		logbase.Fatal(log, "NTL CTS offset clock index out of range",
			slog.String("dev", ctsDev),
			slog.Int("clockIndex", idx0),
			slog.Int("count", n))
	}
	if idx1 < 0 || idx1 >= n {
		logbase.Fatal(log, "NTL CTS offset clock index out of range",
			slog.String("dev", ctsDev),
			slog.Int("clockIndex", idx1),
			slog.Int("count", n))
	}

	log.LogAttrs(context.Background(), slog.LevelInfo,
		"starting NTL CTS offset service",
		slog.String("cts", ctsDev),
		slog.Int("idx0", idx0),
		slog.Int("idx1", idx1),
		slog.Duration("doff", doff),
		slog.Duration("interval", ntlCTSOffInterval),
	)

	go func() {
		for {
			time.Sleep(ntlCTSOffInterval)

			err := cts.Trigger()
			if err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL CTS trigger failed",
					slog.String("dev", ctsDev), slog.Any("error", err))
				continue
			}

			ts0, err := cts.Timestamp(idx0)
			if err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL CTS timestamp failed",
					slog.String("dev", ctsDev),
					slog.Int("index", idx0),
					slog.Any("error", err))
				continue
			}
			if !ts0.Valid() {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL CTS timestamp not valid",
					slog.String("dev", ctsDev),
					slog.Int("index", idx0))
				continue
			}

			ts1, err := cts.Timestamp(idx1)
			if err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL CTS timestamp failed",
					slog.String("dev", ctsDev),
					slog.Int("index", idx1),
					slog.Any("error", err))
				continue
			}
			if !ts1.Valid() {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL CTS timestamp not valid",
					slog.String("dev", ctsDev),
					slog.Int("index", idx1))
				continue
			}

			off := ts0.Time.Sub(ts1.Time) + doff
			slog.Default().LogAttrs(context.Background(), slog.LevelInfo, "NTL CTS offset",
				slog.String("offset", fmt.Sprintf("%+.9f", off.Seconds())))
		}
	}()
}
