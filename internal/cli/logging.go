package cli

import (
	"io"
	"log/slog"
)

// LogOptions configures the single logger a run uses.
type LogOptions struct {
	Verbosity int
	JSON      bool
}

// newLogger builds the run's logger. It is constructed once here and injected
// explicitly; there is no package-level logger and no slog.SetDefault, so a
// caller can always tell where a line came from. Every line goes to stderr
// because stdout is reserved for reports. Checks log concurrently; the
// handlers serialise their own writes, so two goroutines never interleave
// inside one line.
func newLogger(stderr io.Writer, opts LogOptions) *slog.Logger {
	level := slog.LevelWarn
	switch {
	case opts.Verbosity >= 2:
		level = slog.LevelDebug
	case opts.Verbosity == 1:
		level = slog.LevelInfo
	}
	handlerOptions := &slog.HandlerOptions{Level: level}
	if opts.JSON {
		return slog.New(slog.NewJSONHandler(stderr, handlerOptions))
	}
	return slog.New(slog.NewTextHandler(stderr, handlerOptions))
}
