// Command goharness decides whether a Go change is admissible.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
)

func main() {
	// The first signal cancels the run so it can drain, clean up and still
	// report INCONCLUSIVE; the context carries which signal it was, so the
	// report can say so. The second signal abandons the process at once. The
	// watcher is process-scoped on purpose: it ends when the process does,
	// which is the only lifetime that makes sense for a signal handler.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	abort := make(chan os.Signal, 1)
	signal.Notify(abort, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(abort)
	go func() {
		<-ctx.Done()
		<-abort
		os.Exit(cli.ExitAborted)
	}()

	os.Exit(cli.Run(ctx))
}
