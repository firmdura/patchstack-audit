package contracts

import (
	"context"
	"io"
)

// ConfinedInputs is a read-only view of an input directory kept open throughout
// source and patch preparation. Paths are normalized relative slash paths.
// Implementations reject symlink components and nonregular input files. They open
// paths relative to retained directory handles so a changed pathname cannot
// redirect a read. ReadDir includes hidden entries and rejects symlinks and
// special files. The owner closes the root after preparation.
//
// Reads return InputError with an unsafe-input, I/O or cancellation reason.
// Source and inventory callers add their stage with FailureFromError. Preparation
// hashes bytes while copying them into private files for all later use.
type ConfinedInputs interface {
	OpenRegular(context.Context, string) (io.ReadCloser, error)
	ReadDir(context.Context, string) ([]InputEntry, error)
}

type InputEntry struct {
	Name      string
	Directory bool
}

// StagedFile identifies a private verified copy of an input file. SHA256 and Size
// describe those exact bytes. Path is used to run the audit, not stored in reports.
type StagedFile struct {
	Path   string
	SHA256 string
	Size   int64
}

type SourceRequest struct {
	Inputs       ConfinedInputs
	Source       Source
	StagingDir   string
	WorkspaceDir string
}

// PreparedSource describes the extracted workspace. Files remain readable and
// writable by their owner until final hashing. IntendedModes records original
// file permissions masked to 0777; output directories receive 0755. Archive owner
// and group IDs and timestamps are discarded.
type PreparedSource struct {
	Archive       StagedFile
	WorkspaceDir  string
	IntendedModes map[string]uint32
}

type SourceResult struct {
	Source  PreparedSource
	Failure *Failure
}

type SourcePreparer interface {
	Prepare(context.Context, SourceRequest) (SourceResult, error)
}

type PatchRequest struct {
	Inputs     ConfinedInputs
	PatchDir   string
	Patches    []Patch
	StagingDir string
}

type Operation string

const (
	OperationModify Operation = "modify"
	OperationAdd    Operation = "add"
	OperationDelete Operation = "delete"
)

// PatchTarget describes a target that passed diff header validation. Paths have
// their first component removed. OldPath is empty for an addition, and NewPath
// is empty for a deletion; a modification uses equal paths. Renames and mode
// changes are unsupported. Git mode metadata does not override version 1 final
// permissions, and multiple mode declarations must agree. Targets remain in diff
// order. Patch inventory is responsible for parsing hunks.
type PatchTarget struct {
	OldPath   string
	NewPath   string
	Operation Operation
}

type StagedPatch struct {
	Patch   Patch
	Input   StagedFile
	Targets []PatchTarget
}

type InventoryResult struct {
	Patches []StagedPatch
	Failure *Failure
}

type PatchInventory interface {
	Prepare(context.Context, PatchRequest) (InventoryResult, error)
}

type ExecuteRequest struct {
	Source          PreparedSource
	Patches         []StagedPatch
	PatchExecutable string
}

// ExecutionResult contains ordered patch results and, only after the whole series
// succeeds, file records and a final tree hash. Contents are hashed while readable,
// with intended final permissions included; final modes are then restored. New
// files receive 0644 and directories 0755. Failure stops execution, leaves later
// patches not_run, and returns no file records or tree hash. Diagnostics are
// bounded stderr material, excluded from reports and successful output packages.
type ExecutionResult struct {
	Patches         []PatchResult
	Files           []FileRecord
	FinalTreeSHA256 string
	Failure         *Failure
	Diagnostics     string
}

type Executor interface {
	Execute(context.Context, ExecuteRequest) (ExecutionResult, error)
}
