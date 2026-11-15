# CLI usage and input formats

This guide covers installation, running an audit and preparing your own inputs.
The format restrictions later in the guide explain which archives and patches
version 1 accepts. For error codes and recovery steps, see
[troubleshooting](troubleshooting.md).

## Install v1.0.0

The [v1.0.0 release](https://github.com/firmdura/patchstack-audit/releases/tag/v1.0.0)
provides source archives, Linux binaries for amd64 and arm64, and a `SHA256SUMS`
file. Binary archives include a ready-to-run example and do not require Go.
[Verify the checksums](#ci-and-release-preparation) before extracting an archive.
The Linux runtime requirements below apply to both binary and source installations.

To install from the published Go module on Linux, use Go 1.27.4 and enable network
access for this command:

```sh
GOTOOLCHAIN=go1.27.4 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go install github.com/firmdura/patchstack-audit/cmd/patchstack@v1.0.0
```

Add Go's installation directory for executables to your `PATH` so you can run
`patchstack`. See the [Go API reference for v1.0.0](https://pkg.go.dev/github.com/firmdura/patchstack-audit@v1.0.0/pkg/patchstack)
for the library's exported types and functions. Audits use only local inputs and
make no network calls.

## Build from this checkout

The supported runtime is Linux. Before following these commands, make sure `go`
on your `PATH` is Go **1.27.4**, the exact compiler version used by this project.
The module's language version is Go 1.27.0, and its only module dependency is
`go.yaml.in/yaml/v3 v3.0.6`.

From the repository root, download the dependency with network access enabled.
Then disable Go's network access and build:

```sh
GOTOOLCHAIN=go1.27.4 go mod download
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
go version
go build -o bin/patchstack ./cmd/patchstack
patch --version
```

Check that `go version` reports Go 1.27.4. GNU patch **2.7.6** is the tested
version. Other GNU patch versions must produce the same recognized output for
cleanly applied patches; unexpected diagnostics cause the audit to fail.
BSD patch and other patch tools are rejected.

The tool and its GNU patch child process need access to Linux's
`/proc/<pid>/fd` paths. The output filesystem must support
`renameat2(RENAME_NOREPLACE)`: a Linux operation that makes the complete output
visible at once and refuses to replace an existing destination. If the kernel,
architecture or filesystem does not support it, the audit fails explicitly.
The implementation supports Linux amd64, arm64, riscv64 and loong64; released
binary archives are available for amd64 and arm64.

On macOS or Windows, use the [Linux container workflow](#local-linux-verification).

## Run a series

```sh
./bin/patchstack audit \
  --manifest stack.yaml \
  --input-root ./inputs \
  --output ./out \
  --format json
```

| Flag | What it selects |
| --- | --- |
| `--manifest` | Required. The YAML manifest. A relative path is resolved from the current working directory. |
| `--input-root` | Required. The directory containing the source archive and patch directory. Paths declared inside the manifest are relative to this directory. |
| `--output` | Required. A new directory for the patched source and reports. Its parent must already exist. |
| `--format` | The report format printed to standard output: `json` (the default) or `markdown`. Both formats are always saved in the output directory. |
| `--patch-executable` | The local GNU patch executable. Defaults to `patch` on `PATH`; use an explicit path to select another installation. |

Unknown flags and extra positional arguments are usage errors.

The input root and every component of an input path must be actual files or
directories, with no symbolic links. The output parent must also have no symbolic
links in its path. Choose an output directory outside the actual input directory.
The tool does not create missing parent directories. It refuses to replace an
existing file, directory or symbolic link at the destination, including one
created by another process during the run.

On success, the tool makes these three items visible together in the new output
directory:

```text
out/
  source/       the complete patched source tree
  report.json   the JSON report
  report.md     the Markdown report
```

The selected report is also written to standard output; diagnostics go to
standard error. If a run fails before the output is published, the tool removes
its private temporary output and leaves no partial destination. Once it has
accepted a valid manifest, it writes a failure report even if the failure concerns
tooling or output setup. Invalid usage and malformed manifests produce
only diagnostics.

Always check the exit status. If writing to standard output fails after
publication, the command returns `2`, retains the complete output and prints its
location to standard error. A temporary cleanup error after publication also
returns an error while preserving the completed output and its successful
reports. See the [exit status reference](troubleshooting.md) for details.

## Try the two-patch example

Build the CLI first, then run these commands from the repository root. They apply
the same inputs twice and compare both reports and the resulting source:

```sh
work=$(mktemp -d)
go run ./examples/demo --output "$work/inputs"
./bin/patchstack audit --manifest "$work/inputs/stack.yaml" \
  --input-root "$work/inputs" --output "$work/run1" --format json \
  > "$work/stdout.json"
./bin/patchstack audit --manifest "$work/inputs/stack.yaml" \
  --input-root "$work/inputs" --output "$work/run2" --format markdown \
  > "$work/stdout.md"
cmp "$work/run1/report.json" "$work/run2/report.json"
cmp "$work/run1/report.md" "$work/run2/report.md"
cmp "$work/stdout.json" "$work/run1/report.json"
cmp "$work/stdout.md" "$work/run2/report.md"
diff -r "$work/run1/source" "$work/run2/source"
```

The C source and patches in `examples/demo/` are original Apache-2.0 examples.
The generator uses those embedded files without fetching any upstream source.
It creates `source.tar.gz`, `patches/` and `stack.yaml`, with actual hashes and
`local:demonstration` references describing the patches' origin. Each successful
run produces `source/main.c` beneath its output directory. No C compiler is
needed because the audit does not compile the program.

## Prepare a manifest and patch directory

A typical input directory looks like this:

```text
inputs/
  source.tar.gz
  stack.yaml
  patches/
    0001.patch
```

The manifest below describes that layout. Its hashes are placeholders; replace
them with the actual SHA-256 hashes of your files. Use the generated example above
if you want inputs that are ready to run.

```yaml
schema_version: 1
source:
  path: source.tar.gz
  sha256: '<64 lowercase hexadecimal digits>'
  root_dir: demo-1.0
patch_dir: patches
patches:
  - id: first-change
    file: 0001.patch
    sha256: '<64 lowercase hexadecimal digits>'
    upstream: local:demonstration
    cves: []
```

Here, `source.tar.gz` contains files under `demo-1.0/`. The tool removes that one
root directory when extracting, so `demo-1.0/main.c` becomes `source/main.c` in
the final output.

### YAML fields and values

Version 1 accepts exactly one YAML document. The top-level fields are
`schema_version`, `source`, `patch_dir` and `patches`. Every field shown in the
example is required except `cves`. All text values must be YAML strings; in
particular, quote hashes that contain only digits. Write `schema_version` as the
integer `1`.

The parser rejects unknown or duplicate fields, null values, extra documents,
aliases, anchors, merge keys and custom tags. It also rejects the wrong value
type, such as a number where a string is required or a scalar where a list is
required.

List patches in the order in which they must be applied. A series can contain
zero through 256 patches. For an empty series, write `patches: []`; the empty
patch directory must still exist, and GNU patch is still required.

Each patch ID must contain at least one non-whitespace character. Patch IDs,
filenames and hashes must each be unique within the series. All SHA-256 values
must contain exactly 64 lowercase hexadecimal digits. When present, `cves` is a
list of identifiers matching `CVE-[0-9]{4}-[0-9]{4,}`: `CVE-`, a four-digit year,
a hyphen and at least four digits.

Use `upstream` to declare an absolute HTTPS URL with a nonempty host, or
`local:<reason>` with a nonempty reason. The tool records these references as
supplied. It does not fetch the URLs or verify the claimed origin of a patch.

### Paths and inventory

`source.path` must end in `.tar.gz`. The archive root (`source.root_dir`) and each
patch filename must be a single name, without directory separators. Other paths
in the manifest are relative to `--input-root`, use `/` as the separator and must
be valid UTF-8. Absolute paths, Windows drive paths, backslashes, ASCII control
characters, empty path components, `.` and `..` are rejected.

The patch directory must contain exactly the regular files listed in the
manifest. The check includes hidden files. Missing files, extra files, nested
directories, symbolic links and special files all cause validation to fail.

The tool copies the source archive and patches into a private staging area while
checking their hashes. Extraction and patch application use those same verified
copies, so they do not depend on the original paths remaining unchanged. The tool
does not modify the original inputs.

## Source archive restrictions

Use a gzip-compressed tar archive with regular files and directories beneath the
single root named by `source.root_dir`. A separate entry for the root directory
is optional if the other entries identify it. The gzip stream must decode fully
with valid checksums, and the tar data must include a complete end marker.

After removing the declared root, every entry must have a safe relative path.
The tool rejects entries outside that root, absolute paths, `..` traversal,
backslashes, ASCII control characters and invalid UTF-8. It also rejects duplicate
normalized names and cases where a path would have to be both a file and a
directory. Symbolic links, hard links, devices, FIFOs (named pipes) and other
special entries are unsupported. Directory entries must contain no file data.
Nonzero data after the tar end marker is rejected.

Metadata headers count toward the entry limit. Decompressed metadata and padding
are also subject to limits; the tool does not rely solely on file sizes declared
in archive headers. See [fixed limits](#fixed-limits-and-reports).

### File permissions

The tool discards archive ownership, timestamps and the setuid, setgid and sticky
permission bits. It records each existing regular file's remaining `0777`
permission bits as that file's intended final mode. During preparation and patch
application, it temporarily gives the owner read and write access to these files.

New files created by patches use mode `0644`. Deleting a file and recreating it
also gives it mode `0644`. All published directories use `0755`, and report files
use `0644`.

Before restoring the final permissions, the tool hashes each file while it can
still read it and records the intended mode in the final tree digest. This allows
a file with final mode `0000` (no access permissions) to be audited by an ordinary
user. The tool does not need to reopen the unreadable published file.

## Patch formats and application rules

A supported patch is a nonempty unified text diff with `---` and `+++` file
headers and `@@` hunk headers. A hunk describes one group of changed lines and its
surrounding context. Hunk counts must be correct, and every hunk must change text.
Patch lines must end with LF; CR and NUL bytes are rejected. Hunk content need
not be valid UTF-8, but header paths must be.

The parser accepts multiple file sections, ordered nonoverlapping hunks, optional
hunk descriptions, GNU header timestamps separated from paths by a tab, and the
standard `\ No newline at end of file` marker. It rejects malformed counts,
impossible ranges, misplaced markers, incomplete sections and unexplained text
before or after the diff. All patches are checked before any patch process runs.

### Paths in patches

The tool removes exactly one leading path component from each header path.
For example, both `a/src/main.c` and `b/src/main.c` become `src/main.c`. The
remaining path must stay inside the workspace. For a modification, the old and
new paths must match after this removal.

For an addition or deletion, exactly one header path must be `/dev/null`, and
the file section must contain one complete hunk. `/dev/null` is a marker for a
missing old or new file; it does not permit other absolute paths. Patch target
paths cannot contain whitespace (including Unicode whitespace), quotes, control
characters or backslashes.

### Git text patches

The parser also accepts ordinary Git text patches. These begin with `diff --git`,
may include `new file mode` or `deleted file mode`, and must then include `index`
metadata before the unified diff headers. Both paths on the `diff --git` line
must match the unified diff's target after the leading component is removed.

The blob IDs in `index` metadata must contain 4–64 lowercase hexadecimal digits.
The all-zero ID must be on the side representing a missing file for an addition
or deletion. These IDs are descriptive metadata; they are not verified input
hashes. The only accepted mode descriptions are the regular-file modes `100644`
and `100755`. If both operation metadata and the `index` line specify a mode,
they must agree.

Mode descriptions do not change existing intended permissions, and additions
always use `0644`, even when Git metadata describes `100755`. Binary patches,
actual permission changes, links, Git submodule entries, renames and copies are
unsupported. The parser also rejects email preambles, `Index:` preambles, context
diffs, normal diffs and unsupported Git metadata.

### Strict GNU patch execution

GNU patch runs directly, without a shell, in a private workspace. It receives
explicit arguments and a minimal environment with the C locale. The main flags
are `--batch --forward --fuzz=0 --strip=1 --no-backup-if-mismatch`; version-control
checkout helpers are disabled.

Every hunk must apply exactly where declared. An **offset** means that GNU patch
found the change at a different line number; **fuzz** means it ignored some
surrounding context to find a match. Both cause the audit to fail. An offset is
rejected even if GNU patch itself exits successfully.

A nonzero process exit, rejected hunk, reversed or already-applied patch, or
unrecognized diagnostic also fails the series. Execution stops at the first
failure, and later patches retain status `not_run`.

## Fixed limits and reports

Version 1 has the following fixed limits. They cannot be raised through options.

| Resource | Limit |
| --- | --- |
| Manifest size | 1 MiB |
| Compressed source archive size | 2 GiB |
| Number of patches | 256 |
| Size of each patch | 16 MiB |
| Archive entries, including metadata headers | 100,000 |
| Total extracted regular-file data | 2 GiB |
| Combined standard output and standard error per patch process | 1 MiB |
| Time per patch process | 30 seconds |

Byte limits are enforced while reading and decompressing. On timeout or
cancellation, the tool kills the patch process group and cleans up temporary
output. SIGINT and SIGTERM cancel a CLI run. Abrupt termination such as SIGKILL
cannot run cleanup; see [temporary directories](troubleshooting.md#temporary-directories-and-interrupted-runs).

Reports preserve the declared patch order and origin references. Each patch has
status `not_run`, `applied` or `failed`. A preparation or tooling failure leaves
all patches `not_run`. Failed reports contain no final tree digest or file
inventory, even if earlier patches were applied.

Reports contain no machine-specific paths, timestamps or raw process logs.
Supplied text is escaped in Markdown. Both formats explain the limits of the
evidence: hashes identify input bytes, and successful application reproduces a
source tree. Neither authenticates provenance nor proves a security repair.

### How the final source digest is calculated

The final tree digest is a SHA-256 hash that identifies the paths, contents and
intended permissions of every regular file in the patched source tree.
To calculate it, sort relative file paths by their UTF-8 bytes, then create one
record per file in this format:

```text
relative-path NUL four-digit-octal-intended-mode NUL lowercase-content-sha256 LF
```

Here, `NUL` means a zero byte and `LF` means a newline byte; these are separators,
not literal text. Concatenate the records and take the SHA-256 hash of the result.
The report stores this value in `final_tree_sha256`.

Modes use exactly four octal digits, including the leading zero; `0000` is valid.
Empty directories, ownership and timestamps do not contribute. A tree with no
regular files hashes the empty byte string. Changing a path, intended mode or
file content changes the digest. Identical accepted input bytes and modes produce
identical reports, regardless of the chosen output path.

## Local Linux verification

Full verification requires Go 1.27.4, GNU patch 2.7.6, GCC for Go's race detector,
a POSIX shell and standard shell utilities, including `mktemp`, `cmp` and `diff`.
Preparing release archives also requires Git, GNU tar, gzip, `sha256sum`, `install`
and GNU `mv`. The pinned Linux image supplies these tools. If you use `make`, its
`build`, `prepare`, `verify` and `release` targets wrap the commands in this guide.

Run verification as an ordinary user. Root bypasses the permission restrictions
that some tests need to exercise, so those tests fail when run as root. Prepare
the compiler and dependencies with network access, then disable networking for
audit execution and acceptance checks.

With the compiler selected and offline Go settings from the build section in
place, the full local acceptance sequence is:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/patchstack ./cmd/patchstack
./scripts/acceptance.sh
./scripts/test-library.sh
./scripts/verify-linux.sh
```

These checks require real GNU patch. Missing tools cause a failure rather than a
skipped check. The acceptance script runs the two-patch example twice and tests
hash mismatches, extra patch files, second-patch failure, offsets, archive
traversal and an existing output destination. The library script builds a separate
Go module that imports `github.com/firmdura/patchstack-audit/pkg/patchstack`, checks
a successful run, and verifies that a failed run publishes no partial output.
Neither script downloads audit inputs.

On Linux, `verify-linux.sh` runs the suite directly. On other hosts, it uses Docker
to create a fresh writable copy of the files in the current Git commit (`HEAD`)
and runs verification with `--network=none`. Docker must be installed and running.
First prepare the pinned image and dependency caches with networking enabled,
then run verification offline:

```sh
./scripts/verify-linux.sh --prepare
./scripts/verify-linux.sh
```

The image is defined in `build/linux.Dockerfile`, uses Go 1.27.4 and GNU patch
2.7.6, and is named `patchstack-audit-linux:go1.27.4`. Commit the changes you want
to test before using the Docker flow. Uncommitted changes and untracked files are
excluded because that flow tests `HEAD`.

To keep an example result on a non-Linux host, run the CLI inside the prepared
image with a writable output directory mounted from the host. From the source
checkout, create that directory under `bin/`; this also works with Docker backends
that do not share the host's `/tmp`:

```sh
mkdir -p bin
work=$(mktemp -d "$PWD/bin/demo.XXXXXX")
docker run --rm --network=none --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off \
  -e GOFLAGS=-mod=readonly -e GOCACHE=/cache -e GOMODCACHE=/deps \
  -v patchstack-audit-gomodcache:/deps -v patchstack-audit-gocache:/cache \
  -v "$PWD:/repo:ro" -v "$work:/runs" -w /repo \
  patchstack-audit-linux:go1.27.4 sh -eu -c '
    go build -buildvcs=false -o /tmp/patchstack ./cmd/patchstack
    go run ./examples/demo --output /runs/inputs
    /tmp/patchstack audit --manifest /runs/inputs/stack.yaml \
      --input-root /runs/inputs --output /runs/result --format json
  '
```

The result remains at `$work/result` on the host. This container build omits
version-control information from the executable to avoid Git ownership checks on
the read-only host mount. The normal source build above keeps Go's default
version-control behavior.

## CI and release preparation

Use the same Linux environment, running as an ordinary user, in continuous
integration (CI). Prepare pinned dependencies in a separate step with networking
enabled, then run the verification commands without network access.

Check the process exit status to decide whether a job passed. A report written
to standard output can describe either success or failure. You can save a
successful output directory as one CI artifact. For failed runs, capture standard
output and standard error separately; there is no partial output directory.

### Reproduce the release archives

Use a clean Git checkout on Linux, with the release tag and pinned dependencies
already available. The following commands build from the immutable `v1.0.0` tag.
The destination `/tmp/patchstack-v1.0.0-release` must not already exist:

```sh
./scripts/release.sh v1.0.0 v1.0.0 /tmp/patchstack-v1.0.0-release
cd /tmp/patchstack-v1.0.0-release
sha256sum -c SHA256SUMS
```

The script creates these files:

```text
patchstack-audit-v1.0.0-source.tar.gz
patchstack-audit-v1.0.0-linux-amd64.tar.gz
patchstack-audit-v1.0.0-linux-arm64.tar.gz
SHA256SUMS
```

It uses only the selected Git revision, includes the original and third-party
licenses, and produces reproducible archives. Running the script prepares files
locally; it does not create a tag, publish a release or request pkg.go.dev indexing.
The `make release` target defaults to version `v1.0.0` and the current commit.
Set `RELEASE_VERSION`, `RELEASE_REF` and `RELEASE_DIR` to choose another supported
version, Git revision or output directory.

Binary archives include the project's [Apache-2.0 license](../LICENSE), the
[YAML dependency notices](../LICENSES/go-yaml-v3.txt), and the Go runtime's
[BSD-3-Clause license](../LICENSES/Go-LICENSE.txt) and
[PATENTS grant](../LICENSES/Go-PATENTS.txt). The Go notices are exact copies from
the pinned Go 1.27.4 compiler distribution. They do not change the license of the
project's original code.

### Verify and use a binary archive

Place `SHA256SUMS` and the downloaded archives in the same directory. On Linux,
run the checksum command above before extracting an archive. If you downloaded
only one archive, select its entry from `SHA256SUMS`:

```sh
grep '  patchstack-audit-v1.0.0-linux-amd64.tar.gz$' SHA256SUMS | sha256sum -c -
```

Use `linux-arm64` in that command if you downloaded the arm64 archive. A matching
checksum confirms that the archive matches the checksum file; it does not
authenticate the publisher of either file.

Each binary archive contains the `patchstack` executable, licenses, documentation
and generated `example-inputs/`. Extract the archive for your Linux architecture,
change into its directory, and run:

```sh
./patchstack audit --manifest example-inputs/stack.yaml \
  --input-root example-inputs --output result --format json
```

`result` must not already exist. This example requires GNU patch and the Linux
filesystem and `/proc` support described above, but no Go compiler or C compiler.
Building from source, running acceptance scripts and trying the library example
require the complete source checkout or source archive. Preparing release archives
also requires a Git checkout.
