// Command goharness decides whether a Go change is admissible.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
)

// signalBuffer holds both signals the harness reacts to, so the second one is
// never dropped while the first is being handled.
const signalBuffer = 2

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, signalBuffer)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	// The watcher is deliberately process-scoped: the first signal cancels the
	// run so it can drain and clean up and still report INCONCLUSIVE, and the
	// second abandons the process immediately. It ends when the process does,
	// which is the only lifetime that makes sense for a signal handler.
	go func() {
		<-signals
		cancel()
		<-signals
		os.Exit(cli.ExitAborted)
	}()

	os.Exit(cli.Run(ctx))
}
