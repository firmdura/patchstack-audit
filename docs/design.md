# PatchStack Audit v1.0.0 design

This document describes PatchStack Audit v1.0.0 behavior, input contracts, and
verification requirements. For installation and current usage, start with the
[README](../README.md).

## Purpose and scope

PatchStack Audit is a local Go CLI and importable library. It applies a declared
sequence of patches to source files whose exact bytes are identified by hashes,
and reports which inputs produced the resulting source tree. It does not
determine whether a CVE is fixed or whether the resulting software builds or
works.

Version 1 includes:

- A strict, versioned YAML manifest describing one `.tar.gz` source archive,
  its SHA-256 hash and root directory, and an ordered list of unified text patches.
  Each patch has a SHA-256 hash, a declared origin and optional CVE IDs.
- Verification of source and patch bytes, safe extraction into a private temporary
  workspace, a complete check of the patch directory, and strict sequential
  execution with GNU patch.
- Repeatable JSON and Markdown reports, including a final source tree hash on
  success. The completed source tree and both reports become available together
  in a new output directory, only after every patch and check succeeds.
- A Linux CLI, a public `pkg/patchstack` Go API, small local test fixtures, and tests
  for repeatability and hostile or invalid inputs.

The tool does not download inputs, discover fixes or dependencies, assess the
meaning of a patch, determine CVE applicability, build or test patched software,
or perform Git operations. It does not parse recipes, BitBake or Buildroot data,
extract firmware, generate SBOM or VEX documents, or provide a hosted service.
It makes no security or compliance verdict.

Only regular files and directories are accepted in source archives. Symlinks,
hardlinks, devices and FIFOs are rejected. Binary patches and patches that only
change permissions are unsupported.

## CLI behavior

A typical invocation is:

```sh
patchstack audit \
  --manifest stack.yaml \
  --input-root ./inputs \
  --output ./out \
  --format json
```

Use `--format markdown` for Markdown on stdout. A successful run creates
`out/source/`, `out/report.json` and `out/report.md`, and prints the selected
report to stdout. An existing output path is refused and remains unchanged.

| Exit code | Meaning |
| --- | --- |
| `0` | The inputs were verified, the complete series was reproduced, and output was published. |
| `1` | The run found an input hash mismatch, patch inventory mismatch or patch application failure. |
| `2` | Invalid usage or an operational failure, including an invalid manifest, unavailable tool, unsafe input, I/O error, timeout or cancellation. |

Earlier successful patches never turn a failed series into a successful result.
After a valid manifest is accepted, a failed run prints a deterministic failure
report to stdout. Invalid usage or a malformed manifest produces diagnostics
only. Diagnostics go to stderr. A stdout write failure returns 2; the retention
rule under “Output publication” applies if the output was already published.

## Manifest requirements

```yaml
schema_version: 1
source:
  path: source.tar.gz
  sha256: '<64 lowercase hex digits>'
  root_dir: demo-1.0
patch_dir: patches
patches:
  - id: fix-parser
    file: 0001-fix-parser.patch
    sha256: '<64 lowercase hex digits>'
    upstream: https://example.org/project/commit/abc
    cves: [CVE-2024-0001]
```

The hash placeholders, URL and CVE ID illustrate the format; they do not identify
verified inputs or authenticated origins. Every manifest path is a relative
slash-separated path beneath `--input-root`. Absolute paths, `..` components and
symlink components are rejected. Patch filenames are single names within
`patch_dir`.

Patch IDs, filenames and hashes must each be unique. The patch directory must
contain exactly the declared regular files, with no unlisted files or nested
directories. `upstream` must be a nonempty HTTPS URL or `local:<reason>`.
The tool reports that declared origin without independently authenticating it.
Optional CVE IDs must match `^CVE-[0-9]{4}-[0-9]{4,}$`.

Unknown or duplicate YAML fields, aliases, malformed hashes and unsupported
schema versions are rejected. The [contract reference](../docs/contracts.md)
describes the full loading rules.

| Resource | Fixed version 1 limit |
| --- | --- |
| Manifest | 1 MiB |
| Compressed source archive | 2 GiB |
| Number of patches | 256 |
| Size of each patch | 16 MiB |
| Archive entries | 100,000 |
| Total extracted bytes | 2 GiB |
| Combined stdout and stderr per patch | 1 MiB |
| Runtime of each patch | 30 seconds |

Limits apply while data is read and decompressed; sizes declared in untrusted
archive headers are not sufficient. These limits cannot be disabled.

## Verified inputs and safe extraction

Source and patch bytes are copied into private staging files while their hashes
are checked. Extraction and patch application use those same verified copies,
without reopening the original input paths. The original inputs remain unchanged.
No patch process starts until the manifest, inventory, hashes and extraction have
passed their checks.

The source hash is verified before extraction. `root_dir` must be one nonempty
name other than `.` or `..`. Source paths must use valid UTF-8, with no ASCII
control characters or backslashes. Extraction removes exactly the declared root
from each entry's path. It rejects paths outside that root, duplicate normalized
paths, absolute or traversal paths, links, special files, and conflicting file
and directory paths. Dangerous path forms are rejected before any write.

Only the source files' `0777` permission bits are preserved for the final tree.
Setuid, setgid and sticky bits, owner/group IDs and timestamps are discarded.
In the private workspace, files temporarily remain readable and writable by the
owner and directories remain accessible. After all patches succeed, file contents
are hashed with their intended final permissions recorded in the hash input.
Those permissions are restored before publication. New files receive `0644`,
and output directories receive `0755`. Changes to permissions alone are
unsupported.

## Strict GNU patch execution

The tool checks GNU patch's identity and version before use. It runs on Linux
with `LC_ALL=C`, an explicit workspace directory, and these arguments:

```text
--batch --forward --fuzz=0 --strip=1 --no-backup-if-mismatch
```

Arguments are passed directly to the process, without shell interpolation.
Before execution, the inventory parser validates the supported unified headers
and every counted hunk. After removing one leading component, every target path
must remain beneath the workspace. `/dev/null` is allowed only for additions
and deletions.

Ordinary Git text patches may use a `diff --git` envelope with a required
`index` line, provided both normalized wrapper paths agree with the unified
headers. When both operation and index metadata specify regular-file modes,
those modes must agree. Metadata is descriptive: it preserves the existing permission rules and never overrides
`0644` for new files. Binary, mode-change, rename-only and link operations,
unsupported prologues, and malformed hunk counts are rejected.

A nonzero exit, rejected hunk, reversed or already-applied hunk, fuzz, or nonzero
offset fails the series. An offset is rejected even when GNU patch returns zero.
GNU patch has no reliable no-offset mode, so the tool checks its C-locale output
and rejects unexpected diagnostic forms. Tests cover that parsing behavior.

Each patch may produce at most 1 MiB of combined stdout and stderr. Exceeding
the limit fails explicitly. A patch that runs longer than 30 seconds has its
process group killed, and the private workspace is cleaned up. The workspace
remains private until the whole series and all checks succeed.

## Final tree hash and reports

The canonical final source tree hash is SHA-256 over a file inventory. Sort regular
files lexicographically by their relative paths' UTF-8 bytes. For each file, write:

```text
path NUL four-digit-octal-mode NUL lowercase-file-sha256 LF
```

`NUL` is a zero byte, and `LF` is a newline byte. Concatenate those records and
hash the resulting UTF-8 data. The mode is exactly four octal digits representing
the intended final `0777` permissions, rather than temporary workspace access.
Empty directories, owner/group IDs, timestamps and extraction paths are excluded.

Content is hashed before final permissions are restored. Even a file with final
mode `0000` can therefore be reproduced by an ordinary user. The report includes
the hash definition and individual file hashes. Repeated runs with identical
input bytes and modes must produce identical reports and tree hashes.

Reports include schema version, outcome, reason, source archive identity and hash,
declared origins, and ordered patch hashes and application results. Only a fully
successful run has a final tree hash. Hash identity and clean application do not
prove trusted origins, a security repair or compliance.

Expected input or patch mismatches return a typed result. Operational, setup and
cancellation failures also return a typed error. Deterministic reports contain
no absolute machine paths or wall-clock timestamps. Bounded raw patch logs are
for failure diagnostics on stderr, and never enter a successful output package.

## Output publication

The output parent must already exist, and output must be outside the input root.
Preparation uses a temporary sibling directory on the output filesystem. Only
when the complete source tree and both reports are ready does a Linux atomic
rename make them visible at the final path. The rename must refuse replacement,
for example through `renameat2` with `RENAME_NOREPLACE`. A check followed by an
ordinary, potentially overwriting `os.Rename` is insufficient. A filesystem that
cannot provide this guarantee is refused with an explicit error.

Any failure before publication removes the temporary tree and leaves original
inputs and any existing destination unchanged. If writing stdout fails after
publication, the CLI returns 2 and reports that the completed output was retained.
It does not delete completed evidence because a downstream pipe closed.

## Public API and internal boundaries

The module is `github.com/firmdura/patchstack-audit`. Its public API includes:

```go
func LoadManifest(io.Reader) (Manifest, error)
func Audit(context.Context, Manifest, Options) (Report, error)
func WriteJSON(io.Writer, Report) error
func WriteMarkdown(io.Writer, Report) error
```

`Options` supplies the input root, output directory and GNU patch executable.
`Audit` uses the same staging, validation, result rules and atomic publication as
the CLI. The library does not call `os.Exit`, use global state or make implicit
network calls.

The authoritative shared models, enums and adapter interfaces live in
`internal/contracts`. `pkg/patchstack/types.go` exposes type and constant aliases.
Internal packages import `internal/contracts` and never import the public facade.
The public package calls the internal implementations.

Input readers preserve the identity of verified inputs. Source preparation keeps
extraction confined to the workspace. The executor determines strict application
results, the publisher makes output available all at once, and report writers
only display results. Preparation reads original inputs without modifying them;
execution sees only validated private workspace files. CLI callers and library
callers cannot bypass these shared path checks.

## Verification

Final acceptance runs these commands from a clean checkout in the documented
Linux environment:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/patchstack ./cmd/patchstack
./scripts/acceptance.sh
./scripts/test-library.sh
./scripts/verify-linux.sh
```

Integration tests use real GNU patch and small locally generated source archives.
A missing required tool fails verification; it is never silently skipped.
Acceptance reproduces a two-patch series twice and compares reports, tree hashes
and source files. It then checks second-patch failure, offsets, traversal, hash
mismatch, stale inventory and refusal of existing output, with no partial output.
A temporary external Go module proves that the public API is importable and has
the same behavior.

Unit and integration tests cover error precedence, unchanged inputs and repeatable
output. The [usage guide](usage.md) documents the supported inputs, digest
algorithm, GNU patch rules and exit codes. The [Go API guide](api.md) shows how
to run the same audit from another module. The example C source and patches are
original fixtures with `local:demonstration` origins.

## Build and release

The Linux verification environment pins Go 1.27.4 and its dependencies. Other
hosts can use the [Linux container](usage.md#local-linux-verification).
Dependencies and the toolchain are prepared before offline verification.

Releases include reproducible source and Linux amd64/arm64 binary archives,
checksums, the original demonstration, documentation, the Apache-2.0 license
and third-party notices. The [Go package reference](https://pkg.go.dev/github.com/firmdura/patchstack-audit/pkg/patchstack)
lists the public API.
