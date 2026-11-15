# Version 1 behavior and component contracts

This reference explains the rules shared by the CLI and Go library, including
how the internal components pass verified data to one another. For a first run,
start with the [usage guide](usage.md). For calling the library from Go, see the
[API guide](api.md).

## Toolchain, dependency and licenses

The project uses Go 1.27.4, selected from the official
[Go downloads](https://go.dev/dl/) on November 15, 2026. `go.mod` sets the Go 1.27
language baseline and records `toolchain go1.27.4`. Verification uses that exact
compiler. `GOTOOLCHAIN=go1.27.4` selects it, and the prepared Linux image already
contains it. Download dependencies while networking is enabled. Then use the
prepared compiler with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off` for offline
checks. An audit itself never accesses the network.

The only module dependency is `go.yaml.in/yaml/v3 v3.0.6`, maintained by the
[YAML organization](https://github.com/yaml/go-yaml/tree/v3). `go.sum` records its
checksums. Original PatchStack Audit code and fixtures use
[Apache-2.0](../LICENSE). The YAML dependency's Apache/MIT notices are preserved
verbatim in [LICENSES/go-yaml-v3.txt](../LICENSES/go-yaml-v3.txt).

The compiled CLI also contains Go runtime and standard-library code. Their
[BSD-3-Clause license](../LICENSES/Go-LICENSE.txt) and
[PATENTS grant](../LICENSES/Go-PATENTS.txt) are copied verbatim from the Go 1.27.4
distribution. Binary distributions must include all of these notices and the
original-code license. The manifest fixture is original demonstration data; its
local descriptions and example references do not claim to represent an upstream
security repair.

## Manifest loading and validation

`patchstack.LoadManifest(io.Reader) (Manifest, error)` reads one YAML document
of at most 1 MiB. Loading checks the declaration without opening the files it
names. Those files need not exist yet. The loader does not extract files, invoke
tools, create an output directory or access the network.

A reader failure is returned as a wrapped operational I/O error. Invalid YAML
or invalid field values return a typed invalid-manifest error. A failure never
returns a partially decoded manifest.

The required top-level fields are `schema_version`, `source`, `patch_dir` and
`patches`. `source` requires `path`, `sha256` and `root_dir`. Each patch requires
`id`, `file`, `sha256` and `upstream`; `cves` is optional. All text values must be
YAML strings, and `schema_version` must be written as the integer `1`.

The loader rejects unknown or duplicate fields, additional documents, nulls,
aliases, anchors, merge keys, custom tags, automatic type conversions and values
with the wrong structure. Quote hashes that contain only digits so YAML reads
them as strings rather than numbers.

A source path must end in `.tar.gz`. Source and patch hashes must each contain
exactly 64 lowercase hexadecimal characters. Patch IDs must contain at least one non-whitespace character. IDs,
filenames and patch hashes must each be unique within the series. A manifest may
contain zero through 256 patches; an empty series still verifies the source.

Each optional CVE ID must match `^CVE-[0-9]{4}-[0-9]{4,}$`. The `upstream` value
must be an absolute HTTPS URL with a nonempty host, or `local:` followed by a
nonempty reason. These values record declared origins; the tool does not
authenticate them.

`Manifest.Validate() error` applies the same value checks to manifests constructed
or changed in Go. `Audit` calls it again before using a manifest. The
`testdata/contracts/valid.yaml` fixture illustrates a valid two-patch declaration;
its hashes are sample values, not verified hashes of accompanying input files.

## Input and target paths

Manifest paths must be nonempty relative paths written with `/` separators and
valid UTF-8. Absolute paths, Windows drive paths, backslashes, ASCII control
characters, empty components, and `.` or `..` components are rejected.
`source.root_dir` and patch filenames must each be a single name, without path
separators.

Checking the spelling of a path is only the first step. Input reads also reject
symlinks in every component and reject files that are not regular files. They use
operations relative to an already-open directory, so replacing a pathname during
a read cannot redirect it. An `Lstat` check followed by a separate open of the
same pathname would not provide that guarantee.

Archive extraction removes exactly the declared root directory from each entry's
path. It rejects entries outside that root, duplicate normalized paths, conflicting
file and directory paths, links and special files. Only regular files and
directories are supported.

Patch paths lose exactly one leading component, matching GNU patch's `--strip=1`.
For example, `a/src/main.c` becomes `src/main.c`. The resulting path must remain
inside the workspace. A modification must name the same normalized old and new
path. `/dev/null` is allowed only to mark the missing old file in an addition or
the missing new file in a deletion. Target paths containing quotes or whitespace,
including Unicode whitespace, are unsupported.

## Supported patch syntax

The inventory parser checks the entire supported diff syntax before execution,
including both file headers and the line counts in every hunk. It accepts plain
unified `---`/`+++` headers and `@@` hunks, including patches that change multiple
files, standard no-newline markers, and optional GNU timestamps separated from
header paths by a tab.

Patches must use LF line endings. NUL and CR bytes are unsupported. Header paths
must be valid UTF-8; hunk contents need not be.

Git text patches may use an envelope before the unified headers. This consists
of a `diff --git` line, optional `new file mode` or `deleted file mode` metadata,
and a required `index` line.
Both paths in `diff --git` must normalize to the same path and agree with the
unified headers. Git blob IDs describe the diff; they are not verified input
hashes or proof of origin.

An `index` line may specify regular-file mode `100644` or `100755`. New-file and
deleted-file metadata accepts the same two modes. When both the operation line
and the index line specify a mode, they must agree. This metadata does not change
the permission rules: existing files keep their intended permissions, and every
new file receives `0644`, even if a Git addition says `100755`.

The parser rejects mode-change operations, nonregular modes, links, rename/copy
operations, binary patches, mail and `Index:` prologues, context and normal diffs,
unexplained text, and malformed or incomplete hunk counts. Each addition or
deletion section using `/dev/null` must contain one complete hunk. No patch process
starts until the whole series has passed preparation checks.

## Fixed limits

| Resource | Version 1 limit |
| --- | --- |
| Manifest | 1 MiB |
| Compressed source archive | 2 GiB |
| Number of patches | 256 |
| Size of each patch | 16 MiB |
| Archive entries | 100,000 |
| Total extracted bytes | 2 GiB |
| Combined stdout and stderr per patch process | 1 MiB |
| Runtime of each patch process | 30 seconds |

Byte limits are enforced as data is read or decompressed, rather than relying
on sizes declared in archive headers. These limits cannot be changed by callers.

## Internal component boundaries

The authoritative models, enums and interfaces live in `internal/contracts`.
`pkg/patchstack/types.go` exposes aliases for the public API. Internal packages
import `internal/contracts` and never import the public `pkg/patchstack` package.
Local operational paths belong in `Options` or component state, not in reports.

`ConfinedInputs` gives source and patch preparation a read-only view of an input
root that remains open throughout preparation. `OpenRegular` opens a normalized
relative regular-file path. `ReadDir` returns every entry, including hidden files,
and rejects symlinks and special files. The implementation keeps using the same
root directory even if its original pathname changes. It rejects symlink
components even when they point inside the root. The owner closes the root after
preparation.

Read failures use `InputError` with an unsafe-input, I/O or cancellation reason.
The source or inventory caller adds its own stage through `FailureFromError`.
Diagnostic strings remain outside the report.

`SourcePreparer.Prepare(context.Context, SourceRequest)` takes this input view,
a source declaration, and private staging and workspace directories. It returns
a `SourceResult` containing a `PreparedSource` or an expected `Failure`.

`PatchInventory.Prepare(context.Context, PatchRequest)` takes the same input view,
the complete patch declarations, and a private staging directory. It returns
ordered `StagedPatch` values or an expected `Failure`.

Both preparation steps copy input bytes into private staging files while hashing
them. Each staged file records its private path, verified hash and byte size.
Extraction and patch application then use those verified copies; they never
reopen the original input paths. Source verification, complete patch inventory
and hash verification, and extraction all finish before any patch process starts.

`Executor.Execute(context.Context, ExecuteRequest)` takes the prepared source,
verified patches in their declared order, parsed old and new target paths, and
the selected local GNU patch executable. `ExecutionResult` contains ordered patch
results. It includes sorted file records and a final tree hash only when the
entire series succeeds. An expected failure returns `Failure` and a nil error;
an operational failure returns `*RunError`. Callers must ignore success-only
result fields whenever an error is returned.

The executor checks GNU patch's identity and version, passes arguments directly
without a shell, sets `LC_ALL=C`, and checks the tool's diagnostics strictly.
It also handles process-group cancellation and timeouts. GNU patch 2.7.6 is the
version used for Linux verification. Raw diagnostics are bounded and kept out
of deterministic reports and successful output directories.

## Permissions and the final tree hash

Files in the private workspace temporarily remain readable and writable by the
owner, and directories remain accessible to the owner.
`PreparedSource.IntendedModes` records the original regular-file permissions,
masked to `0777`. New files receive `0644`, and all output directories receive
`0755`. Privileged permission bits, archive owner/group IDs and timestamps are
discarded.

The executor hashes file contents while the files are still readable. It records
their intended final permissions in the hash input, then restores those
permissions before the output is published. A final mode of `0000` is valid:
the hash does not depend on reopening the unreadable published file.

The canonical tree hash is calculated as follows:

1. Sort regular files lexicographically by the UTF-8 bytes of their relative paths.
2. For each file, write the record shown below.
3. Concatenate the records and calculate their SHA-256 hash.

```text
relative-path NUL four-digit-octal-mode NUL lowercase-file-sha256 LF
```

Here, `NUL` means a zero byte and `LF` means a newline byte. Modes have a leading
zero followed by three octal digits, including `0000`. Empty directories,
owner/group IDs, timestamps and host paths do not enter the hash. If there are no
regular files, the result is the SHA-256 hash of an empty byte string. A change to
a file's path, intended permissions or contents changes the hash input.

## Results and report validity

Reports contain the schema version, outcome, stage, reason, source declaration,
ordered patch identities and declared origins. They also explain the tree hash
and the limits of the evidence.

A patch's application status is `not_run`, `applied` or `failed`. A preparation or
tooling failure leaves every patch `not_run`. Once execution stops, all later
patches stay `not_run`; no patch after that point can be marked `applied`.

A failed report contains neither a final tree hash nor file records. A successful
report requires every patch to be applied, stage `complete`, reason `none`, a
valid final hash, and sorted, unique regular-file records. Each record must have
a safe path, valid content hash and four-digit mode within `0777`.

`Report.Validate()` checks these structural rules. It does not verify external
claims or repeat patch application. Report writers validate before writing, and
always retain the fixed explanation of what the evidence proves. Reports contain
no absolute machine paths, timestamps or raw process logs.

`hash_mismatch`, `inventory_mismatch` and `patch_failed` are expected failures:
they return typed result values with a nil error. Invalid manifests or usage,
unsafe inputs, exceeded limits, unavailable or unsupported tools, I/O errors,
timeouts, cancellation, and output failures also return a typed `RunError`.
It contains a stage, reason and optional diagnostic cause. `errors.As` and
`errors.Is` work through the wrapper. Causes are for stderr diagnostics only.

`Report.ExitCode(error)` returns 0 for a valid, completely reproduced result,
1 for a valid expected failure, and 2 for an operational error or an invalid or
incomplete report. Any non-nil error takes precedence. If stdout writing fails
after publication, the exit code is 2 and the completed output is retained.
No library function calls `os.Exit`.
