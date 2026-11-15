// Package contracts defines the shared version 1 types, validation rules and
// component interfaces. It contains no archive extraction, tool execution or
// output publication.
package contracts

const (
	SchemaVersion              = 1
	MaxManifestBytes    int64  = 1 << 20
	MaxArchiveBytes     int64  = 2 << 30
	MaxPatches                 = 256
	MaxPatchBytes       int64  = 16 << 20
	MaxArchiveEntries          = 100000
	MaxExtractedBytes   int64  = 2 << 30
	MaxPatchLogBytes    int64  = 1 << 20
	PatchTimeoutSeconds        = 30
	NewFileMode         uint32 = 0644
	DirectoryMode       uint32 = 0755
	DigestDefinition           = "SHA-256 of the UTF-8 manifest, sorted by relative path bytes; each regular file contributes path NUL four-digit octal intended mode NUL lowercase content SHA-256 LF; empty directories, uid, gid and timestamps are excluded."
	EvidenceLimitations        = "Hashes establish byte identity and clean patch application establishes reproduction of declared inputs. Neither proves trusted provenance, a security repair, CVE applicability, a successful build, or compliance."
)

// Manifest describes a source archive and a sequence of patches. It records
// declarations, not verified input bytes. Validate checks values constructed or
// changed in Go as well as values returned by the YAML loader.
type Manifest struct {
	SchemaVersion int     `json:"schema_version" yaml:"schema_version"`
	Source        Source  `json:"source" yaml:"source"`
	PatchDir      string  `json:"patch_dir" yaml:"patch_dir"`
	Patches       []Patch `json:"patches" yaml:"patches"`
}

// Source identifies a source archive by its relative path and expected hash.
// RootDir is the single archive root directory removed during extraction.
type Source struct {
	Path    string `json:"path" yaml:"path"`
	SHA256  string `json:"sha256" yaml:"sha256"`
	RootDir string `json:"root_dir" yaml:"root_dir"`
}

// Patch identifies one file in the patch directory. Upstream and CVEs describe
// declared origins and CVE associations; the audit does not authenticate them.
type Patch struct {
	ID       string   `json:"id" yaml:"id"`
	File     string   `json:"file" yaml:"file"`
	SHA256   string   `json:"sha256" yaml:"sha256"`
	Upstream string   `json:"upstream" yaml:"upstream"`
	CVEs     []string `json:"cves,omitempty" yaml:"cves,omitempty"`
}

// Options selects the local input, output and GNU patch paths for an audit.
// These paths are used to run the audit and do not enter its report.
type Options struct {
	// InputRoot is an existing directory containing the declared inputs.
	// Symlinks are rejected in every path component.
	InputRoot string
	// OutputDir is a new path outside InputRoot, beneath an existing parent.
	// The parent must have no symlink components and support atomic rename
	// without replacement on Linux.
	OutputDir string
	// PatchExecutable selects GNU patch. Empty uses "patch" from PATH.
	PatchExecutable string
}

// Outcome says whether the complete patch series was reproduced.
type Outcome string

const (
	OutcomeReproduced Outcome = "reproduced"
	OutcomeFailed     Outcome = "failed"
)

// Stage identifies the part of an audit associated with a result or error.
type Stage string

const (
	StageComplete    Stage = "complete"
	StageManifest    Stage = "manifest"
	StageSource      Stage = "source"
	StageInventory   Stage = "inventory"
	StageTool        Stage = "tool"
	StageExecution   Stage = "execution"
	StageDigest      Stage = "digest"
	StagePublication Stage = "publication"
	StageOutput      Stage = "output"
)

// Reason is a stable classification for an audit result or error.
type Reason string

const (
	ReasonNone                   Reason = "none"
	ReasonInvalidManifest        Reason = "invalid_manifest"
	ReasonHashMismatch           Reason = "hash_mismatch"
	ReasonInventoryMismatch      Reason = "inventory_mismatch"
	ReasonPatchFailed            Reason = "patch_failed"
	ReasonUnsafeInput            Reason = "unsafe_input"
	ReasonLimitExceeded          Reason = "limit_exceeded"
	ReasonIO                     Reason = "io_failure"
	ReasonToolUnavailable        Reason = "tool_unavailable"
	ReasonUnsupportedTool        Reason = "unsupported_tool"
	ReasonTimeout                Reason = "timeout"
	ReasonCancelled              Reason = "cancelled"
	ReasonOutputExists           Reason = "output_exists"
	ReasonUnsupportedPublication Reason = "unsupported_publication"
	ReasonOutputWrite            Reason = "output_write_failure"
)

// Failure records a stage and reason without host paths, timestamps or tool logs.
// Hash, inventory and patch application mismatches return this result with a nil
// error. Operational failures also return a RunError.
type Failure struct {
	Stage  Stage  `json:"stage"`
	Reason Reason `json:"reason"`
}

// PatchStatus describes whether a patch was not run, applied or failed.
type PatchStatus string

const (
	PatchNotRun  PatchStatus = "not_run"
	PatchApplied PatchStatus = "applied"
	PatchFailed  PatchStatus = "failed"
)

// PatchResult combines a patch declaration with its application status and reason.
// Results stay in manifest order. Preparation or tooling failures leave every
// patch not_run. Once execution stops, all later patches remain not_run.
type PatchResult struct {
	Patch
	Status PatchStatus `json:"status"`
	Reason Reason      `json:"reason"`
}

// FileRecord describes a regular file in the completed source tree. Path is
// relative to that tree and SHA256 hashes the contents. Mode is the file's final
// permissions as four octal digits, such as "0644". It excludes temporary access
// permissions used during preparation.
type FileRecord struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Report records an audit's input declarations and result without host paths,
// timestamps or raw tool logs. Patches remain in application order. Files are
// sorted by their relative paths' UTF-8 bytes. Files and FinalTreeSHA256 are
// present only on success. Writers validate the report without repeating the audit.
type Report struct {
	SchemaVersion    int           `json:"schema_version"`
	Outcome          Outcome       `json:"outcome"`
	Stage            Stage         `json:"stage"`
	Reason           Reason        `json:"reason"`
	Source           Source        `json:"source"`
	Patches          []PatchResult `json:"patches"`
	FinalTreeSHA256  string        `json:"final_tree_sha256,omitempty"`
	Files            []FileRecord  `json:"files,omitempty"`
	DigestDefinition string        `json:"digest_definition"`
	Limitations      string        `json:"limitations"`
}
