package logbase

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"time"
)

func logFatal(ctx context.Context, log *slog.Logger, msg string, attrs ...slog.Attr) {
	// See https://pkg.go.dev/log/slog#hdr-Wrapping_output_methods
	var pcs [1]uintptr
	n := runtime.Callers(3, pcs[:]) // skip [runtime.Callers, logFatal, Fatal/FatalContext]
	if n != 1 {
		panic("unexpected call stack")
	}
	r := slog.NewRecord(time.Now(), slog.LevelError, msg, pcs[0])
	r.AddAttrs(attrs...)
	_ = log.Handler().Handle(ctx, r)
	os.Exit(1)
}

func Fatal(log *slog.Logger, msg string, attrs ...slog.Attr) {
	logFatal(context.Background(), log, msg, attrs...)
}

func FatalContext(ctx context.Context, log *slog.Logger, msg string, attrs ...slog.Attr) {
	logFatal(ctx, log, msg, attrs...)
}
