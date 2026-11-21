// Package cli reads command-line arguments and runs audits through the shared API.
// The executable supplies the API functions, so this internal package does not
// import the public library or maintain a separate audit implementation.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

// API supplies the command version and the manifest loader, audit function and
// report writers used by both the command and library callers.
type API struct {
	Version       string
	LoadManifest  func(io.Reader) (contracts.Manifest, error)
	Audit         func(context.Context, contracts.Manifest, contracts.Options) (contracts.Report, error)
	WriteJSON     func(io.Writer, contracts.Report) error
	WriteMarkdown func(io.Writer, contracts.Report) error
}

// Run handles a help or version request or one audit command, writing output to stdout
// and diagnostics to stderr. It returns 0 for success, 1 for an expected mismatch,
// or 2 for a usage or operational error. It does not exit the calling process.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, api API) int {
	if len(args) == 1 && args[0] == "--version" {
		version := api.Version
		if version == "" {
			version = "dev"
		}
		if _, err := fmt.Fprintf(stdout, "patchstack %s\n", version); err != nil {
			fmt.Fprintln(stderr, "cannot write version:", err)
			return 2
		}
		return 0
	}
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the version 1 YAML manifest")
	input := flags.String("input-root", "", "existing directory containing the source archive and patches")
	output := flags.String("output", "", "new directory for the patched source and reports; its parent must already exist")
	format := flags.String("format", "json", "report format printed to standard output: json or markdown")
	patch := flags.String("patch-executable", "patch", "path or command name of the local GNU patch executable")
	const synopsis = "usage: patchstack --help | --version\n" +
		"usage: patchstack audit --manifest stack.yaml --input-root ./inputs --output ./out [--format json|markdown] [--patch-executable patch]\n"
	if standaloneHelp(args) {
		var help strings.Builder
		help.WriteString(synopsis + "\nAudit options:\n")
		flags.SetOutput(&help)
		flags.PrintDefaults()
		if _, err := io.WriteString(stdout, help.String()); err != nil {
			fmt.Fprintln(stderr, "cannot write help:", err)
			return 2
		}
		return 0
	}
	usage := func() int {
		fmt.Fprint(stderr, synopsis)
		return 2
	}
	if len(args) == 0 || args[0] != "audit" {
		return usage()
	}
	if flags.Parse(args[1:]) != nil {
		return usage()
	}
	if flags.NArg() != 0 || *manifestPath == "" || *input == "" || *output == "" || (*format != "json" && *format != "markdown") {
		return usage()
	}
	if api.LoadManifest == nil || api.Audit == nil || api.WriteJSON == nil || api.WriteMarkdown == nil {
		fmt.Fprintln(stderr, "audit: cannot start because required audit functions are unavailable")
		return 2
	}
	file, err := os.Open(*manifestPath)
	if err != nil {
		fmt.Fprintln(stderr, "cannot open manifest:", err)
		return 2
	}
	manifest, loadErr := api.LoadManifest(file)
	if err := errors.Join(loadErr, file.Close()); err != nil {
		fmt.Fprintln(stderr, "cannot load manifest:", err)
		return 2
	}
	report, auditErr := api.Audit(ctx, manifest, contracts.Options{InputRoot: *input, OutputDir: *output, PatchExecutable: *patch})
	if auditErr != nil {
		fmt.Fprintln(stderr, auditErr)
	}
	write := api.WriteJSON
	if *format == "markdown" {
		write = api.WriteMarkdown
	}
	if err := write(stdout, report); err != nil {
		fmt.Fprintln(stderr, "cannot write report:", err)
		if report.ExitCode(nil) == 0 {
			location, pathErr := filepath.Abs(*output)
			if pathErr != nil {
				location = *output
			}
			fmt.Fprintf(stderr, "complete output retained at %q\n", location)
		}
		return 2
	}
	return report.ExitCode(auditErr)
}

func standaloneHelp(args []string) bool {
	if len(args) == 2 && args[0] == "audit" {
		args = args[1:]
	}
	if len(args) != 1 {
		return false
	}
	switch args[0] {
	case "-h", "--h", "-help", "--help":
		return true
	}
	return false
}
