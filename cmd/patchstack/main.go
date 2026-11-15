// Command patchstack checks and reproduces a declared series of local patches.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/firmdura/patchstack-audit/internal/cli"
	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func main() {
	// Let a closed output pipe produce a write error. The CLI can then return
	// exit code 2 and keep any complete output that was already published.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, cli.API{
		LoadManifest:  patchstack.LoadManifest,
		Audit:         patchstack.Audit,
		WriteJSON:     patchstack.WriteJSON,
		WriteMarkdown: patchstack.WriteMarkdown,
	})
	stop()
	os.Exit(code)
}
