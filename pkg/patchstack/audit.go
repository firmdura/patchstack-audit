package patchstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/executor"
	"github.com/firmdura/patchstack-audit/internal/inputfs"
	"github.com/firmdura/patchstack-audit/internal/patchinput"
	"github.com/firmdura/patchstack-audit/internal/publish"
	"github.com/firmdura/patchstack-audit/internal/source"
)

// Audit verifies the declared local inputs and applies every patch in manifest
// order using GNU patch on Linux. On success, it writes source/, report.json and
// report.md together under options.OutputDir. The destination must not exist,
// must be outside options.InputRoot, and must have an existing parent on a
// filesystem that supports atomic rename without replacement. Original inputs
// remain unchanged, and the audit makes no network calls.
//
// An empty PatchExecutable selects "patch" from PATH. Real GNU patch is required
// even for an empty series. The same fixed limits apply as when using the CLI.
//
// A source or patch hash mismatch, patch inventory mismatch, or patch application
// failure returns a failed Report and a nil error. Operational failures also
// return a RunError. An invalid manifest returns an empty Report and an error.
// Use report.ExitCode(err) to classify the report and error together.
//
// Failures before publication remove the private temporary directory; any cleanup
// error is returned. A successful report is returned only after complete output
// is published. If later cleanup or report writing fails, keep that completed
// output and handle the error.
func Audit(ctx context.Context, manifest Manifest, options Options) (report Report, retErr error) {
	if err := manifest.Validate(); err != nil {
		return Report{}, err
	}
	report = Report{SchemaVersion: SchemaVersion, Source: manifest.Source, Patches: make([]PatchResult, len(manifest.Patches)), DigestDefinition: DigestDefinition, Limitations: EvidenceLimitations}
	for i, patch := range manifest.Patches {
		patch.CVEs = append([]string(nil), patch.CVEs...)
		report.Patches[i] = PatchResult{Patch: patch, Status: PatchNotRun, Reason: ReasonNone}
	}
	fail := func(failure Failure, err error) (Report, error) {
		report.Outcome, report.Stage, report.Reason = OutcomeFailed, failure.Stage, failure.Reason
		report.Files, report.FinalTreeSHA256 = nil, ""
		return report, err
	}
	failError := func(stage Stage, err error) (Report, error) {
		failure := contracts.FailureFromError(stage, err)
		return fail(failure, &RunError{Stage: failure.Stage, Reason: failure.Reason, Err: err})
	}
	if ctx == nil {
		return failError(StageManifest, &RunError{Stage: StageManifest, Reason: ReasonInvalidManifest, Err: errors.New("missing context")})
	}
	if err := ctx.Err(); err != nil {
		return failError(StageManifest, &RunError{Stage: StageManifest, Reason: ReasonCancelled, Err: err})
	}
	if options.InputRoot == "" || options.OutputDir == "" {
		return failError(StageManifest, &RunError{Stage: StageManifest, Reason: ReasonInvalidManifest, Err: errors.New("input root and output directory are required")})
	}
	executable, err := executor.ValidateTool(ctx, options.PatchExecutable)
	if err != nil {
		return failError(StageTool, err)
	}
	inputs, err := inputfs.Open(options.InputRoot)
	if err != nil {
		return failError(StageSource, err)
	}
	inputsOpen := true
	defer func() {
		if inputsOpen {
			if err := inputs.Close(); err != nil {
				report, retErr = failError(StageSource, errors.Join(retErr, err))
			}
		}
	}()
	inputInfo, err := inputs.Stat()
	if err != nil {
		return failError(StageSource, err)
	}
	tx, err := publish.Begin(ctx, inputInfo, options.OutputDir)
	if err != nil {
		return failError(StagePublication, err)
	}
	defer func() {
		if err := tx.Cleanup(); err != nil {
			if tx.Published() {
				retErr = &RunError{Stage: StagePublication, Reason: ReasonIO, Err: fmt.Errorf("complete output retained at %q; temporary cleanup: %w", tx.OutputDir(), err)}
			} else {
				report, retErr = failError(StagePublication, errors.Join(retErr, err))
			}
		}
	}()
	workspace, staging := filepath.Join(tx.Dir(), "source"), filepath.Join(tx.Dir(), ".staging")
	for _, name := range []string{workspace, staging} {
		if err := os.Mkdir(name, 0700); err != nil {
			return failError(StagePublication, err)
		}
		if err := os.Chmod(name, 0700); err != nil {
			return failError(StagePublication, err)
		}
	}
	prepared, err := (source.Preparer{}).Prepare(ctx, contracts.SourceRequest{Inputs: inputs, Source: manifest.Source, StagingDir: staging, WorkspaceDir: workspace})
	if err != nil {
		return failError(StageSource, err)
	}
	if prepared.Failure != nil {
		return fail(*prepared.Failure, nil)
	}
	inventory, err := (patchinput.Inventory{}).Prepare(ctx, contracts.PatchRequest{Inputs: inputs, PatchDir: manifest.PatchDir, Patches: manifest.Patches, StagingDir: staging})
	if err != nil {
		return failError(StageInventory, err)
	}
	if inventory.Failure != nil {
		return fail(*inventory.Failure, nil)
	}
	err = inputs.Close()
	inputsOpen = false
	if err != nil {
		return failError(StageSource, err)
	}
	execution, err := (executor.Executor{}).Execute(ctx, contracts.ExecuteRequest{Source: prepared.Source, Patches: inventory.Patches, PatchExecutable: executable})
	report.Patches = execution.Patches
	if err != nil {
		return failError(StageExecution, err)
	}
	if execution.Failure != nil {
		return fail(*execution.Failure, nil)
	}
	report.Outcome, report.Stage, report.Reason = OutcomeReproduced, StageComplete, ReasonNone
	report.Files, report.FinalTreeSHA256 = execution.Files, execution.FinalTreeSHA256
	if err := report.Validate(); err != nil {
		return failError(StagePublication, err)
	}
	if err := os.RemoveAll(staging); err != nil {
		return failError(StagePublication, err)
	}
	for _, output := range []struct {
		name  string
		write func(io.Writer, Report) error
	}{{"report.json", WriteJSON}, {"report.md", WriteMarkdown}} {
		if err := writeAuditReport(filepath.Join(tx.Dir(), output.name), report, output.write); err != nil {
			return failError(StagePublication, err)
		}
	}
	if err := tx.Publish(ctx); err != nil {
		return failError(StagePublication, err)
	}
	return report, nil
}

func writeAuditReport(name string, report Report, write func(io.Writer, Report) error) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	writeErr := write(file, report)
	modeErr := file.Chmod(0644)
	closeErr := file.Close()
	if err := errors.Join(writeErr, modeErr, closeErr); err != nil {
		return fmt.Errorf("write staged evidence: %w", err)
	}
	return nil
}
