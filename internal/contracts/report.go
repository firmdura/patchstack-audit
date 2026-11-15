package contracts

import (
	"fmt"
	"regexp"
)

var modePattern = regexp.MustCompile(`^0[0-7]{3}$`)

// Validate checks the report's structure, required fields and consistency. It
// does not repeat patch application, recalculate hashes or authenticate external
// claims. Report writers and ExitCode use these checks to reject incomplete or
// contradictory results.
func (r Report) Validate() error {
	bad := func() error { return fmt.Errorf("invalid or incomplete version 1 report") }
	if r.SchemaVersion != SchemaVersion || r.DigestDefinition != DigestDefinition || r.Limitations != EvidenceLimitations {
		return bad()
	}
	declarations := make([]Patch, len(r.Patches))
	for i, p := range r.Patches {
		declarations[i] = p.Patch
	}
	if (Manifest{SchemaVersion: SchemaVersion, Source: r.Source, PatchDir: "patches", Patches: declarations}).Validate() != nil {
		return bad()
	}
	if r.Outcome == OutcomeReproduced {
		if r.Stage != StageComplete || r.Reason != ReasonNone || !hashPattern.MatchString(r.FinalTreeSHA256) {
			return bad()
		}
	} else if r.Outcome == OutcomeFailed {
		if !r.Stage.Valid() || r.Stage == StageComplete || !r.Reason.Valid() || r.Reason == ReasonNone || r.FinalTreeSHA256 != "" || len(r.Files) != 0 {
			return bad()
		}
	} else {
		return bad()
	}
	stopped := false
	failed := false
	for _, p := range r.Patches {
		switch p.Status {
		case PatchApplied:
			if stopped || p.Reason != ReasonNone {
				return bad()
			}
		case PatchNotRun:
			if p.Reason != ReasonNone {
				return bad()
			}
			stopped = true
		case PatchFailed:
			if stopped || failed || !p.Reason.Valid() || p.Reason == ReasonNone {
				return bad()
			}
			failed = true
			stopped = true
		default:
			return bad()
		}
		if r.Outcome == OutcomeReproduced && p.Status != PatchApplied {
			return bad()
		}
		if (r.Stage == StageManifest || r.Stage == StageSource || r.Stage == StageInventory || r.Stage == StageTool) && p.Status != PatchNotRun {
			return bad()
		}
	}
	last := ""
	for i, file := range r.Files {
		if ValidateRelativePath(file.Path) != nil || !modePattern.MatchString(file.Mode) || !hashPattern.MatchString(file.SHA256) || (i > 0 && file.Path <= last) {
			return bad()
		}
		last = file.Path
	}
	return nil
}

// Valid reports whether s is a recognized version 1 stage.
func (s Stage) Valid() bool {
	switch s {
	case StageComplete, StageManifest, StageSource, StageInventory, StageTool, StageExecution, StageDigest, StagePublication, StageOutput:
		return true
	}
	return false
}

// Valid reports whether r is a recognized version 1 reason.
func (r Reason) Valid() bool {
	switch r {
	case ReasonNone, ReasonInvalidManifest, ReasonHashMismatch, ReasonInventoryMismatch, ReasonPatchFailed, ReasonUnsafeInput, ReasonLimitExceeded, ReasonIO, ReasonToolUnavailable, ReasonUnsupportedTool, ReasonTimeout, ReasonCancelled, ReasonOutputExists, ReasonUnsupportedPublication, ReasonOutputWrite:
		return true
	}
	return false
}
