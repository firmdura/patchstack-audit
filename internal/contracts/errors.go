package contracts

import (
	"errors"
	"fmt"
)

// RunError describes invalid input, setup or I/O problems, tooling failures,
// timeouts or cancellation. Stage and Reason are stable classifications. Err is
// an optional diagnostic cause; it must never be copied into a Report.
type RunError struct {
	Stage  Stage
	Reason Reason
	Err    error
}

// Error formats the stage, reason and optional diagnostic cause.
func (e *RunError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return string(e.Stage) + ": " + string(e.Reason)
	}
	return fmt.Sprintf("%s: %s: %v", e.Stage, e.Reason, e.Err)
}

// Unwrap exposes the diagnostic cause to errors.Is and errors.As.
func (e *RunError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Expected reports whether the reason is a hash, patch inventory or patch
// application mismatch. Audits return those failures as results with a nil error.
// Other failure reasons identify operational errors.
func (r Reason) Expected() bool {
	return r == ReasonHashMismatch || r == ReasonInventoryMismatch || r == ReasonPatchFailed
}

// ExitCode combines the report and error into a CLI exit status: 0 for complete
// success, 1 for an expected mismatch, or 2 for an operational error or invalid
// report. Always pass the returned error; any non-nil error takes precedence,
// including a report-write failure after complete output has been published.
func (r Report) ExitCode(err error) int {
	if err != nil || r.Validate() != nil {
		return 2
	}
	if r.Outcome == OutcomeFailed && r.Reason.Expected() {
		return 1
	}
	if r.Outcome == OutcomeReproduced && r.Reason == ReasonNone {
		return 0
	}
	return 2
}

// FailureFromError extracts a stage and reason from a typed error. It uses the
// supplied stage unless a RunError provides its own valid failure stage. Unknown
// errors become I/O failures. Diagnostic text is never copied into the result.
func FailureFromError(stage Stage, err error) Failure {
	var run *RunError
	if errors.As(err, &run) && run != nil {
		if run.Stage.Valid() && run.Stage != StageComplete {
			stage = run.Stage
		}
		return Failure{Stage: stage, Reason: run.Reason}
	}
	var input *InputError
	if errors.As(err, &input) && input != nil {
		return Failure{Stage: stage, Reason: input.Reason}
	}
	return Failure{Stage: stage, Reason: ReasonIO}
}

// InputError describes a failed read beneath the retained input directory.
// Input readers use ReasonUnsafeInput, ReasonIO or ReasonCancelled. Source and
// inventory preparation add their own stage while preserving this reason.
type InputError struct {
	Reason Reason
	Err    error
}

func (e *InputError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return string(e.Reason)
	}
	return fmt.Sprintf("%s: %v", e.Reason, e.Err)
}
func (e *InputError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
