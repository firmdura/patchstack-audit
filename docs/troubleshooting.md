# Results and troubleshooting

## Read the exit status first

| Exit code | Meaning |
| --- | --- |
| `0` | All inputs were verified, every patch applied exactly, and the complete output directory was published. |
| `1` | The run found a `hash_mismatch`, `inventory_mismatch` or `patch_failed` result. No output directory was published. |
| `2` | Invalid usage or an operational error prevented completion. This includes invalid manifests, unsafe input, tooling, I/O, limits, timeouts, cancellation, publication and stdout errors. |

An error after publication needs special care. If writing to stdout or cleaning
up temporary files fails after the completed output is available, the command
returns 2 and keeps that output. The stderr diagnostic identifies its location.
Keep the completed directory even if a program reading stdout closed its pipe.

## Read reports and diagnostics

Once a valid manifest has been accepted, the CLI writes a deterministic report
in the selected format to stdout, unless writing stdout itself fails. Invalid
usage or a malformed manifest produces diagnostics only. Operational details go
to stderr and may include local paths; report fields do not.

A failed report has `outcome: failed` and contains no final tree hash or file
records. Patch statuses show which patches applied before a failure, which patch
failed, and which patches were never run. If preparation failed before patch
execution, all patches are `not_run`.

The `stage` identifies where the result arose: `manifest`, `source`, `inventory`,
`tool`, `execution`, `digest`, `publication` or `output`. A successful report uses
`complete` with `reason: none`. A patch marked `not_run` also uses reason `none`:
there is no application result for that patch.

## Find the reason

| Reason | What to check |
| --- | --- |
| `invalid_manifest` | Check required flags or options, the schema version, field names and types, hashes, duplicate IDs or files, and path spelling. Quote hashes made up entirely of digits. |
| `hash_mismatch` | Compare the source or patch bytes with the input you intended to use. Changing a hash changes the declaration; it does not prove the input's origin. |
| `inventory_mismatch` | The patch directory must contain exactly the listed regular files. Look for missing files, extra files, hidden files and nested directories. |
| `patch_failed` | Check the base source, patch order and hunk positions. Patches that require offsets or fuzz, or are reversed or already applied, fail. |
| `unsafe_input` | Look for traversal or absolute paths, links, special files, unsupported diff syntax, malformed archive data, or output located inside the input root. |
| `limit_exceeded` | A fixed size, entry-count, decompression or process-output limit was exceeded. Version 1 provides no override. |
| `io_failure` | Check permissions, free storage, input readability, the output parent, `/proc` access and any cleanup diagnostics. |
| `tool_unavailable` | Check that GNU patch is installed, executable and on `PATH`. Use `--patch-executable` to select an explicit path. |
| `unsupported_tool` | Use real GNU patch on Linux. Version 2.7.6 is tested; BSD patch is unsupported. |
| `timeout` | A patch process ran for more than 30 seconds. Its process group was killed. Check the selected tool and input size. |
| `cancelled` | The caller cancelled the context, or the CLI received SIGINT or SIGTERM. Temporary output is removed before return unless cleanup itself fails. |
| `output_exists` | Choose a new destination. Existing files, directories and symlinks are never replaced, including paths another process creates during the run. |
| `unsupported_publication` | The Linux kernel, architecture or filesystem does not support the required atomic rename without replacement. Choose a supported local Linux filesystem. |
| `output_write_failure` | A report writer failed, often because a stdout pipe closed. If the diagnostic says complete output was retained, keep that directory. |

For Go callers, an expected mismatch returns a report and a nil error.
Operational errors return `*patchstack.RunError`. Use `errors.As` to inspect
`Stage` and `Reason`, and `errors.Is` to inspect the underlying cause. Pass the
error to `Report.ExitCode`; a non-nil error always takes precedence.
`Report.Validate` checks the report's structure, not the truth of external claims.

## Common setup problems

### The host uses macOS, Windows or BSD patch

Build and run in the [documented Linux container](usage.md#local-linux-verification).
Compiling on another host does not make that host a supported runtime. Linux
must expose `/proc/<pid>/fd` to the audit process and its GNU patch child.

### Go tries to download files during verification

Prepare Go 1.27.4 and the module cache while networking is available. Select that
compiler, then set:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
```

Offline verification fails if a prerequisite is missing. It does not download
a replacement toolchain or dependency.

### Permission tests fail when run as root

Run acceptance as an ordinary user. Root can bypass the permission failures
those tests need to exercise. The race detector also requires a supported C
toolchain for the platform.

### The output path is rejected

The output parent must already exist and be writable; the destination itself
must not exist. Choose a destination outside the input root. Neither input paths
nor output parents may contain symlinks, even when those symlinks point somewhere
that appears safe. Moving or replacing the output parent during execution is
rejected so it cannot redirect the result.

### A published file with mode `0000` cannot be opened

The file has the final permissions recorded for it in the source archive. Its
hash was calculated in the private workspace before those permissions were
restored. A user without elevated privileges cannot read it without changing
its permissions.

### A patch applies manually but fails in an audit

A manual GNU patch run may accept an offset, ignore context lines through fuzz,
recognize extra diff formats, or ask an interactive question. PatchStack Audit
requires a supported unified text patch against the exact declared source.
It rejects offsets even when GNU patch returns exit code 0, and rejects tool
diagnostics it does not recognize.

## Temporary directories and interrupted runs

Failures before publication, timeouts and normal cancellation remove temporary
output. If cleanup fails, the command returns 2 with diagnostics. Resolve the
underlying I/O problem before removing any leftover private files.

SIGKILL, a host crash or power loss prevents cleanup from running. After such an
interruption, a `.patchstack-*` temporary directory may remain beside the intended
output path. Confirm that no active run uses it before removing it manually.
Never remove a completed output directory as part of temporary cleanup.

Publishing the output makes the whole result visible at once; it does not
guarantee that storage survives a power loss. The tool keeps no server-side state
and makes no network calls during an audit.
