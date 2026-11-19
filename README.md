# PatchStack Audit

[![Latest release](https://img.shields.io/github/v/release/firmdura/patchstack-audit)](https://github.com/firmdura/patchstack-audit/releases/latest)
[![CI status](https://img.shields.io/github/check-runs/firmdura/patchstack-audit/main?label=CI)](https://github.com/firmdura/patchstack-audit/actions)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/firmdura/patchstack-audit/pkg/patchstack.svg)](https://pkg.go.dev/github.com/firmdura/patchstack-audit/pkg/patchstack)

PatchStack Audit checks that a set of patches can be applied, in a specified
order, to an exact copy of local source code. You provide a source archive,
patches and a YAML manifest containing their SHA-256 hashes. The tool verifies
those inputs, applies the patches and saves the resulting source tree alongside
JSON and Markdown reports.

Use it from the command line or through the Go library at `pkg/patchstack`.
Given the same accepted inputs, it produces identical reports and a matching
hash of the final source tree.

A successful audit shows that the declared patches reproduce a particular source
tree. Hashes identify the bytes used; they do not establish who supplied them.
The audit does not determine whether a vulnerability is fixed, a CVE applies, the
software builds or works, or a compliance requirement is met. It uses local
inputs and does not download fixes, build software or run the software's tests.

## Install the CLI

[Release v1.0.2](https://github.com/firmdura/patchstack-audit/releases/tag/v1.0.2)
includes source archives, Linux binaries for amd64 and arm64, and a `SHA256SUMS`
file. The binary archives include a ready-to-run example and do not require Go.
See the [archive instructions](docs/usage.md#ci-and-release-preparation) for
checksum verification and an example command.

To install with Go on Linux, use Go 1.27.4 and enable network access for this step:

```sh
GOTOOLCHAIN=go1.27.4 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go install github.com/firmdura/patchstack-audit/cmd/patchstack@v1.0.2
```

Add Go's installation directory for executables to your `PATH` so you can run
`patchstack`. GNU patch is also required, whichever installation method you use.
See the [Go API reference for v1.0.2](https://pkg.go.dev/github.com/firmdura/patchstack-audit@v1.0.2/pkg/patchstack)
for the library's exported types and functions.

Run `patchstack --version` to identify an installed release without providing
inputs or invoking GNU patch. Builds without version metadata report
`patchstack dev`.

## Build and try the example

The tool runs on Linux. Building from source requires **Go 1.27.4**; the tested
GNU patch version is **2.7.6**. Linux must expose `/proc/<pid>/fd` to the tool and
its GNU patch child process. The output filesystem must support an atomic rename
that refuses to replace an existing destination. This lets the tool make the
complete result visible at once without overwriting other files.

On macOS or Windows, use the [local Linux container
workflow](docs/usage.md#local-linux-verification), which requires Docker and a
POSIX shell.

On Linux, first make sure `go` on your `PATH` is Go 1.27.4. From the repository
root, download the pinned dependency while network access is enabled:

```sh
GOTOOLCHAIN=go1.27.4 go mod download
```

Then build and run the example offline:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
go build -o bin/patchstack ./cmd/patchstack
work=$(mktemp -d)
go run ./examples/demo --output "$work/inputs"
./bin/patchstack audit \
  --manifest "$work/inputs/stack.yaml" \
  --input-root "$work/inputs" \
  --output "$work/result" \
  --format json > "$work/stdout.json"
cmp "$work/stdout.json" "$work/result/report.json"
```

The generator creates a tiny C source archive, two patches and a manifest with
their actual hashes. All example source and patches are original to this project.
Both patches use `local:demonstration` to describe their origin; the example makes
no claim about a real CVE. You do not need a C compiler to run it.

After a successful run, `$work/result` contains:

```text
source/       the complete patched source tree
report.json   the JSON report
report.md     the Markdown report
```

The output directory must be new, its parent must already exist, and it must be
outside the input directory. Both reports are saved regardless of `--format`;
that flag selects the report also printed to standard output.

Always check the command's exit status:

| Status | Meaning |
| --- | --- |
| `0` | Input verification, patch application and output publication succeeded. |
| `1` | An input hash, patch directory inventory or patch application did not match the declaration. No output was published. |
| `2` | A usage or operational error occurred. |

If writing to standard output fails after the result has been published, the
command returns `2`, keeps the complete result and prints its location to standard
error. See [troubleshooting](docs/troubleshooting.md) for other errors and cleanup
behavior.

## Read more

- [CLI, input formats, limits and local verification](docs/usage.md)
- [Go API and an example in a separate module](docs/api.md)
- [Error reasons, diagnostics and troubleshooting](docs/troubleshooting.md)
- [Detailed version 1 contracts](docs/contracts.md)

## About Firmdura

This repository contains a standalone verification utility from
[Firmdura](https://firmdura.com). Firmdura's commercial offer is shared embedded
Linux security maintenance through versioned security layers or patch overlays
for agreed user-space components.

## License

Original code and the original example and test fixtures use
[Apache-2.0](LICENSE). The YAML dependency retains its
[third-party notices](LICENSES/go-yaml-v3.txt). Binary archives also include the
Go runtime's [BSD-3-Clause license](LICENSES/Go-LICENSE.txt) and
[PATENTS grant](LICENSES/Go-PATENTS.txt), copied verbatim from Go 1.27.4.
These notices accompany binary distributions. References to upstream patches do
not change the licenses of third-party inputs.
