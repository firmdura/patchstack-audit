// Package patchstack verifies a local source archive and applies a declared
// sequence of patches using GNU patch on Linux. A successful audit writes the
// complete source tree and JSON and Markdown reports to a new output directory.
// It leaves the original inputs unchanged and makes no network calls.
//
// Start with [LoadManifest], then call [Audit] with local input and output paths.
// Always inspect both the returned [Report] and error: an input hash mismatch or
// patch failure is a failed result with a nil error. Use report.ExitCode(err)
// to choose the corresponding CLI exit code.
//
// Hashes identify exact bytes, and clean patch application shows that those
// inputs produce the reported source tree. Neither establishes their origin,
// proves a security repair, or shows that the patched software builds or works.
package patchstack

import "github.com/firmdura/patchstack-audit/internal/contracts"

// Manifest describes the source archive and the patches to apply, in order.
// Source identifies the archive, PatchDir names the patch directory relative to
// Options.InputRoot, and Patches gives the application order. Its SchemaVersion
// field must equal the package's SchemaVersion constant (1).
// Call Manifest.Validate to check a value constructed in Go. Audit repeats that
// validation before using it.
type Manifest = contracts.Manifest

// Source identifies a local .tar.gz archive. Path is relative to Options.InputRoot,
// SHA256 is its expected lowercase SHA-256 hash, and RootDir is the single archive
// root directory removed during extraction. These fields describe the declared
// input; Audit verifies its bytes before extracting it.
type Source = contracts.Source

// Patch describes one patch file. ID identifies it in reports, File is a single
// filename within Manifest.PatchDir, and SHA256 is the expected file hash.
// Upstream is a declared HTTPS reference or local:<reason>; CVEs is an optional
// list of declared CVE IDs. The audit does not authenticate those declarations.
type Patch = contracts.Patch

// Options selects the local paths used by Audit. These paths are not report data.
//
// InputRoot must be an existing directory containing the declared source archive
// and patch directory. OutputDir must not exist, must be outside InputRoot, and
// must have an existing parent on a supported Linux filesystem. Neither the input
// path nor the output parent may contain symlink components.
//
// PatchExecutable selects a local GNU patch executable. An empty value finds
// "patch" on PATH. GNU patch is required even when the patch series is empty.
type Options = contracts.Options

// Outcome says whether the complete patch series was reproduced. Check the
// returned error as well: an error after publication can accompany a successful
// report while the completed output remains available.
type Outcome = contracts.Outcome

// Stage identifies the part of the audit associated with a result or error.
// StageComplete marks a successful report.
type Stage = contracts.Stage

// Reason is a stable classification for a result or error. Use these values
// instead of parsing diagnostic text. Reason.Expected identifies input and patch
// mismatches that are returned as results with a nil error.
type Reason = contracts.Reason

// Failure describes the stage and reason for a failed operation, without local
// paths or diagnostic text. Audit records those fields in its returned Report;
// operational failures also have a RunError.
type Failure = contracts.Failure

// RunError describes invalid input, a setup or I/O problem, unavailable tools,
// timeout or cancellation. Stage and Reason provide stable classifications;
// Err is the optional diagnostic cause. Use errors.As to inspect RunError and
// errors.Is to inspect its cause. Diagnostic causes do not enter reports.
type RunError = contracts.RunError

// PatchStatus describes application of one patch: not run, applied, or failed.
// An applied patch does not imply that the rest of the series succeeded.
type PatchStatus = contracts.PatchStatus

// PatchResult combines a patch declaration with its application Status and Reason.
// Results remain in manifest order. A preparation or tooling failure leaves every
// patch not_run; after execution stops, all later patches also remain not_run.
type PatchResult = contracts.PatchResult

// FileRecord describes a regular file in the completed source tree. Path is
// relative to that tree, SHA256 hashes the file's contents, and Mode is its final
// permissions as four octal digits, such as "0644". Temporary workspace permissions
// are not reported.
type FileRecord = contracts.FileRecord

// Report records the audit's inputs and result. Patches remain in application
// order. On success, Files contains regular-file records sorted by UTF-8 path
// bytes, and FinalTreeSHA256 identifies their paths, final permissions and contents.
// Failed reports have neither Files nor FinalTreeSHA256.
//
// DigestDefinition explains the tree hash, and Limitations states what the audit
// proves. Reports contain no absolute machine paths, timestamps or raw tool logs.
// Report.Validate checks this structure; it does not repeat the audit or
// authenticate a report supplied by someone else.
type Report = contracts.Report

const (
	// SchemaVersion is the supported manifest and report schema version.
	SchemaVersion = contracts.SchemaVersion
	// MaxManifestBytes is the largest accepted YAML manifest, in bytes.
	MaxManifestBytes = contracts.MaxManifestBytes
	// MaxArchiveBytes limits the compressed source archive size, in bytes.
	MaxArchiveBytes = contracts.MaxArchiveBytes
	// MaxPatches is the largest accepted number of patches in a series.
	MaxPatches = contracts.MaxPatches
	// MaxPatchBytes is the largest accepted size of one patch, in bytes.
	MaxPatchBytes = contracts.MaxPatchBytes
	// MaxArchiveEntries limits source archive entries, including metadata headers.
	MaxArchiveEntries = contracts.MaxArchiveEntries
	// MaxExtractedBytes limits total extracted regular-file contents, in bytes.
	MaxExtractedBytes = contracts.MaxExtractedBytes
	// MaxPatchLogBytes limits combined stdout and stderr from one patch process.
	MaxPatchLogBytes = contracts.MaxPatchLogBytes
	// PatchTimeoutSeconds is the time limit for each patch process, in seconds.
	PatchTimeoutSeconds = contracts.PatchTimeoutSeconds
	// NewFileMode is the final permission mode for a file created by a patch.
	NewFileMode = contracts.NewFileMode
	// DirectoryMode is the final permission mode for output directories.
	DirectoryMode = contracts.DirectoryMode
	// DigestDefinition is the fixed schema 1 description of the final tree hash.
	DigestDefinition = contracts.DigestDefinition
	// EvidenceLimitations is the fixed schema 1 statement of what the audit proves.
	EvidenceLimitations = contracts.EvidenceLimitations
	// OutcomeReproduced means every required check and patch succeeded.
	OutcomeReproduced = contracts.OutcomeReproduced
	// OutcomeFailed means the complete patch series was not reproduced.
	OutcomeFailed = contracts.OutcomeFailed
	// StageComplete marks a completed, successful audit.
	StageComplete = contracts.StageComplete
	// StageManifest identifies manifest and required-option validation.
	StageManifest = contracts.StageManifest
	// StageSource identifies source verification and extraction.
	StageSource = contracts.StageSource
	// StageInventory identifies patch directory, hash and syntax checks.
	StageInventory = contracts.StageInventory
	// StageTool identifies GNU patch availability and identity checks.
	StageTool = contracts.StageTool
	// StageExecution identifies patch application.
	StageExecution = contracts.StageExecution
	// StageDigest identifies final file inventory and tree hashing.
	StageDigest = contracts.StageDigest
	// StagePublication identifies preparation and publication of the output directory.
	StagePublication = contracts.StagePublication
	// StageOutput identifies report writing.
	StageOutput = contracts.StageOutput
	// ReasonNone means no failure was reported; it also accompanies a not-run patch.
	ReasonNone = contracts.ReasonNone
	// ReasonInvalidManifest identifies an invalid manifest or missing required options.
	ReasonInvalidManifest = contracts.ReasonInvalidManifest
	// ReasonHashMismatch means source or patch bytes did not match their declared hash.
	ReasonHashMismatch = contracts.ReasonHashMismatch
	// ReasonInventoryMismatch means the patch directory differed from the manifest.
	ReasonInventoryMismatch = contracts.ReasonInventoryMismatch
	// ReasonPatchFailed means a patch did not apply exactly as required.
	ReasonPatchFailed = contracts.ReasonPatchFailed
	// ReasonUnsafeInput identifies unsafe paths, archive entries or patch syntax.
	ReasonUnsafeInput = contracts.ReasonUnsafeInput
	// ReasonLimitExceeded means a fixed resource limit was exceeded.
	ReasonLimitExceeded = contracts.ReasonLimitExceeded
	// ReasonIO identifies an input, output or cleanup I/O failure.
	ReasonIO = contracts.ReasonIO
	// ReasonToolUnavailable means the selected patch executable could not be run.
	ReasonToolUnavailable = contracts.ReasonToolUnavailable
	// ReasonUnsupportedTool identifies an unsupported tool or runtime.
	ReasonUnsupportedTool = contracts.ReasonUnsupportedTool
	// ReasonTimeout means an operation exceeded its time limit.
	ReasonTimeout = contracts.ReasonTimeout
	// ReasonCancelled means the calling context was cancelled.
	ReasonCancelled = contracts.ReasonCancelled
	// ReasonOutputExists means the destination already exists and was not replaced.
	ReasonOutputExists = contracts.ReasonOutputExists
	// ReasonUnsupportedPublication means atomic publication without replacement is unavailable.
	ReasonUnsupportedPublication = contracts.ReasonUnsupportedPublication
	// ReasonOutputWrite means a report writer failed.
	ReasonOutputWrite = contracts.ReasonOutputWrite
	// PatchNotRun means the patch was not executed.
	PatchNotRun = contracts.PatchNotRun
	// PatchApplied means this patch applied exactly; later patches can still fail.
	PatchApplied = contracts.PatchApplied
	// PatchFailed means this patch failed and subsequent patches were not run.
	PatchFailed = contracts.PatchFailed
)
