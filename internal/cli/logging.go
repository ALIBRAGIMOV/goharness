package cli

import (
	"errors"
	"fmt"
	"io"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogOptions configures the single logger a run uses.
type LogOptions struct {
	Verbosity int
	JSON      bool
	Quiet     bool
}

// newLogger builds the run's logger. It is constructed once here and injected
// explicitly; there is no package-level logger and no zap.ReplaceGlobals, so a
// caller can always tell where a line came from. Every line goes to stderr
// because stdout is reserved for reports.
func newLogger(stderr io.Writer, opts LogOptions) *zap.Logger {
	level := zapcore.WarnLevel
	switch {
	case opts.Verbosity >= 2:
		level = zapcore.DebugLevel
	case opts.Verbosity == 1:
		level = zapcore.InfoLevel
	}

	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncodeDuration = zapcore.StringDurationEncoder

	encoder := zapcore.Encoder(zapcore.NewConsoleEncoder(config))
	if opts.JSON {
		encoder = zapcore.NewJSONEncoder(config)
	}
	// Checks log concurrently, so the sink must serialise writes. Without the
	// lock two goroutines interleave into one io.Writer, which is both a data
	// race and a source of shredded log lines.
	sink := zapcore.Lock(zapcore.AddSync(stderr))
	return zap.New(zapcore.NewCore(encoder, sink, level))
}

// syncLogger flushes the logger and returns anything that went wrong. Callers
// decide how to surface it; a character device rejecting a sync is normal and
// is filtered here.
func syncLogger(logger *zap.Logger) error {
	if logger == nil {
		return nil
	}
	err := logger.Sync()
	switch {
	case err == nil,
		errors.Is(err, syscall.ENOTTY),
		errors.Is(err, syscall.EINVAL),
		errors.Is(err, syscall.EBADF),
		errors.Is(err, syscall.ENODEV):
		return nil
	default:
		return fmt.Errorf("flushing diagnostic logs: %w", err)
	}
}
