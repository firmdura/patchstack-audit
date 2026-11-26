# Using the Go library

Import `github.com/firmdura/patchstack-audit/pkg/patchstack` to run an audit from
Go. The library checks inputs, applies patches and writes the output directory
using the same rules as the CLI. It requires Linux, access to `/proc/<pid>/fd`
for the audit process and its GNU patch child, and a filesystem that supports
atomic creation of the completed output directory without replacing an existing
path. Verification uses Go 1.27.4 and GNU patch 2.7.6.

## Load a manifest and run an audit

The main functions are:

```go
func LoadManifest(io.Reader) (Manifest, error)
func Audit(context.Context, Manifest, Options) (Report, error)
func WriteJSON(io.Writer, Report) error
func WriteMarkdown(io.Writer, Report) error
```

`LoadManifest` reads a single YAML document, up to 1 MiB, and validates its fields.
It does not open the declared input files, extract an archive, start a process
or write an output directory. You can also construct a `Manifest` in Go and call
`Manifest.Validate()` to check its values. `Audit` validates the manifest again,
including any changes made after loading it.

Pass the local input and output paths in `Options`:

```go
options := patchstack.Options{
    InputRoot:       "/existing/inputs",
    OutputDir:       "/existing/results/new-run",
    PatchExecutable: "/usr/bin/patch", // Leave empty to find GNU patch on PATH.
}
```

`InputRoot` must be an existing directory. `OutputDir` must be a new path outside
that directory, and its parent must already exist on a supported filesystem.
Neither the input path nor the output parent may contain symlink components.

The library leaves the original inputs unchanged and makes no network calls.
It never exits the calling process, builds or tests the patched software, or
makes a partially patched tree available at `OutputDir`. See the
[usage guide](usage.md) for supported formats and fixed limits.

## Handle results and errors

For a valid manifest, `Audit` returns a report with one of these results:

| Result | Report and error | Output directory |
| --- | --- | --- |
| The complete series was reproduced. | `OutcomeReproduced`, stage `complete`, reason `none`, and a nil error. Every patch is `applied`; the report includes sorted file records and the final tree hash. | Contains the completed source tree and both reports. |
| A source or patch hash did not match, the patch directory differed from the manifest, or a patch failed to apply exactly. | `OutcomeFailed`, a specific reason, and a **nil error**. | No output is published. |
| A setup, I/O, tooling or cancellation error prevented completion. | A failed report and a `*RunError`. | No output is published. |

An invalid manifest returns an empty `Report` value and an error, so there is no
report to render. There is also one exception to the table: if temporary cleanup
fails after the complete output has been published, `Audit` returns the successful
report together with an error. The error identifies the output that was retained.

Always pass the returned error to `report.ExitCode(err)`. It returns 0 for success,
1 for an expected mismatch, and 2 for an operational error or an invalid report.
Checking `Outcome` alone would miss an error that occurred after publication.

To handle errors in Go, inspect their typed fields rather than parsing diagnostic
text:

```go
var runErr *patchstack.RunError
if errors.As(err, &runErr) {
    fmt.Fprintf(os.Stderr, "Audit stage: %s; reason: %s\n", runErr.Stage, runErr.Reason)
}
if errors.Is(err, context.Canceled) {
    // The caller cancelled. Any running patch process group has been stopped.
}
```

`report.Validate()` checks the report's structure and the consistency of its
claims. It does not repeat the audit or authenticate a report supplied by someone
else.

## Write a report

`WriteJSON` and `WriteMarkdown` validate the report before writing any bytes.
An invalid report therefore produces an error and no output. Both formats preserve
patch order, and the Markdown writer escapes supplied text.

A writer failure returns a `RunError` with stage `output` and reason
`output_write_failure`. You can still use `errors.Is` to inspect the underlying
writer error. If writing fails after a successful `Audit`, keep the completed
output directory and treat the write failure as an operational error.

Reports include the source declaration, ordered patch results, schema version,
outcome, stage and reason. Successful reports also include `Files` and
`FinalTreeSHA256`. The report explains how the tree hash is calculated and what
the audit proves. It contains no raw process logs, local operational paths or
wall-clock timestamps. HTTPS references, `local:` descriptions and CVE IDs record
what the manifest declares; the audit does not authenticate them.

The report writers do not reopen published source files. This matters for a file
whose final permissions are `0000`: its contents were hashed before those
permissions were restored, while the file was still readable in the private
workspace.

## Run a complete example from a separate module

The following program takes three positional arguments, in this order: a manifest
path, an input directory and a new output path. The output parent must already
exist. The program handles cancellation, prints JSON to stdout and returns the
same exit codes as the CLI.

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func main() {
    // Handle a closed stdout pipe as a write error so the program can
    // report where the completed output was saved.
    signal.Ignore(syscall.SIGPIPE)
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    code := run(ctx)
    stop()
    os.Exit(code)
}

func run(ctx context.Context) int {
    if len(os.Args) != 4 {
        fmt.Fprintln(os.Stderr, "Usage: consumer MANIFEST INPUT_ROOT NEW_OUTPUT")
        return 2
    }
    file, err := os.Open(os.Args[1])
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        return 2
    }
    manifest, loadErr := patchstack.LoadManifest(file)
    if err := errors.Join(loadErr, file.Close()); err != nil {
        fmt.Fprintln(os.Stderr, err)
        return 2
    }
    // On success, Audit saves the source tree and both reports before returning.
    report, auditErr := patchstack.Audit(ctx, manifest, patchstack.Options{
        InputRoot: os.Args[2], OutputDir: os.Args[3],
    })
    if auditErr != nil {
        fmt.Fprintln(os.Stderr, auditErr)
    }
    if err := patchstack.WriteJSON(os.Stdout, report); err != nil {
        fmt.Fprintln(os.Stderr, err)
        if report.ExitCode(nil) == 0 {
            fmt.Fprintf(os.Stderr, "The complete output is saved at %q.\n", os.Args[3])
        }
        return 2
    }
    return report.ExitCode(auditErr)
}
```

See the [v1.0.8 API reference](https://pkg.go.dev/github.com/firmdura/patchstack-audit@v1.0.8/pkg/patchstack)
for the library's exported types and functions. To try the program, first prepare
Go and dependencies as described in the [usage guide](usage.md). Then run these
commands from the PatchStack Audit checkout root:

```sh
work=$(mktemp -d)
go run ./examples/demo --output "$work/inputs"
consumer=$(mktemp -d)
printf '%s\n' "$consumer"
```

Save the program above as `main.go` in the directory printed by the last command.
Then prepare the consumer's dependency with networking enabled:

```sh
cd "$consumer"
go mod init example.com/patchstack-consumer
go mod edit -go=1.27.0 -toolchain=go1.27.4
go mod edit -require=github.com/firmdura/patchstack-audit@v1.0.8
GOTOOLCHAIN=go1.27.4 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod tidy
```

Run the consumer offline in the same shell:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go run . \
  "$work/inputs/stack.yaml" "$work/inputs" "$work/library-output"
```

For local development, use `go mod edit -replace` with an absolute checkout path
to select your working copy. The repository's `./scripts/test-library.sh` creates
and tests a separate module this way. It checks successful reproduction,
repeatable reports, and a failed run that leaves no partial output.
