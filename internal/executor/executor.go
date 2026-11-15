// Package executor applies a complete verified series to a private prepared
// workspace using real GNU patch on Linux. It never opens original inputs or
// publishes output. The caller owns the surrounding staging/run directory.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/treedigest"
)

// Executor implements the fixed v1 timeout and combined diagnostic byte limit.
// Successful results include the digest and restored final modes. If execution
// begins and fails, workspace contents are removed; preflight failures leave the
// prepared workspace untouched. The caller removes the workspace root/staging.
type Executor struct{}

var _ contracts.Executor = Executor{}

type policy struct {
	timeout  time.Duration
	logBytes int64
}

func fixedPolicy() policy {
	return policy{time.Duration(contracts.PatchTimeoutSeconds) * time.Second, contracts.MaxPatchLogBytes}
}

// ValidateTool resolves a local executable and checks its GNU patch version
// identity without changing a workspace. A normal audit needs real GNU patch;
// diagnostics for GNU patch 2.7.6 are independently tested. Other GNU versions
// must still produce the same conservative clean-application diagnostic grammar.
// No caller environment variables affecting patch behavior are inherited.
func ValidateTool(ctx context.Context, name string) (string, error) {
	return validateTool(ctx, name, fixedPolicy())
}

var versionLine = regexp.MustCompile(`^GNU patch ([0-9]+\.[0-9]+(?:\.[0-9]+)?)$`)

func validateTool(ctx context.Context, name string, limits policy) (string, error) {
	if err := supported(); err != nil {
		return "", runError(contracts.StageTool, contracts.ReasonUnsupportedTool, err)
	}
	if err := ctx.Err(); err != nil {
		return "", runError(contracts.StageTool, contracts.ReasonCancelled, err)
	}
	if name == "" {
		name = "patch"
	}
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", runError(contracts.StageTool, contracts.ReasonToolUnavailable, err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", runError(contracts.StageTool, contracts.ReasonToolUnavailable, err)
	}
	result := process(ctx, executable, []string{"--version"}, "", nil, limits)
	if reason, cause := result.operational(); reason != contracts.ReasonNone {
		if result.startErr != nil {
			reason = contracts.ReasonToolUnavailable
		}
		return "", runError(contracts.StageTool, reason, cause)
	}
	first, _, _ := strings.Cut(string(result.stdout), "\n")
	if result.err != nil || len(result.stderr) != 0 || !versionLine.MatchString(first) {
		return "", runError(contracts.StageTool, contracts.ReasonUnsupportedTool, errors.New("expected GNU patch version identity"))
	}
	return executable, nil
}

// Execute consumes only prepared source and verified staged patches. All stage
// descriptors are opened, rehashed and retained before any application process.
// Patches preserve declaration order. Operational diagnostics are bounded and
// separate from portable evidence; success contains no raw diagnostic logs.
func (Executor) Execute(ctx context.Context, req contracts.ExecuteRequest) (contracts.ExecutionResult, error) {
	return execute(ctx, req, fixedPolicy())
}

func execute(ctx context.Context, req contracts.ExecuteRequest, limits policy) (result contracts.ExecutionResult, retErr error) {
	result.Patches = make([]contracts.PatchResult, len(req.Patches))
	for i, patch := range req.Patches {
		result.Patches[i] = contracts.PatchResult{Patch: patch.Patch, Status: contracts.PatchNotRun, Reason: contracts.ReasonNone}
	}
	fail := func(stage contracts.Stage, reason contracts.Reason, cause error) (contracts.ExecutionResult, error) {
		result.Files, result.FinalTreeSHA256 = nil, ""
		result.Failure = &contracts.Failure{Stage: stage, Reason: reason}
		if reason.Expected() {
			return result, nil
		}
		return result, runError(stage, reason, cause)
	}
	if err := ctx.Err(); err != nil {
		return fail(contracts.StageExecution, contracts.ReasonCancelled, err)
	}
	if err := supported(); err != nil {
		return fail(contracts.StageTool, contracts.ReasonUnsupportedTool, err)
	}
	if err := validateTargets(req.Patches); err != nil {
		return fail(contracts.StageExecution, contracts.ReasonUnsafeInput, err)
	}
	stages, reason, err := openStages(ctx, req.Patches)
	if reason != contracts.ReasonNone {
		return fail(contracts.StageInventory, reason, err)
	}
	defer func() {
		for _, file := range stages {
			file.Close()
		}
	}()
	executable, err := validateTool(ctx, req.PatchExecutable, fixedPolicy())
	if err != nil {
		failure := contracts.FailureFromError(contracts.StageTool, err)
		return fail(failure.Stage, failure.Reason, err)
	}
	workspace, err := filepath.Abs(req.Source.WorkspaceDir)
	if err != nil || req.Source.WorkspaceDir == "" {
		return fail(contracts.StageExecution, contracts.ReasonUnsafeInput, errors.New("missing private workspace"))
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return fail(contracts.StageExecution, contracts.ReasonIO, err)
	}
	defer root.Close()
	modes := make(map[string]uint32, len(req.Source.IntendedModes))
	for name, mode := range req.Source.IntendedModes {
		if contracts.ValidateRelativePath(name) != nil || mode > 0777 {
			return fail(contracts.StageExecution, contracts.ReasonUnsafeInput, errors.New("invalid intended source mode"))
		}
		modes[name] = mode
	}
	files, err := workspaceFiles(ctx, root, false, modes)
	if err != nil {
		failure := contracts.FailureFromError(contracts.StageExecution, err)
		return fail(failure.Stage, failure.Reason, err)
	}
	began, complete := false, false
	defer func() {
		if began && !complete {
			if err := clearWorkspace(root); err != nil {
				result, retErr = fail(contracts.StageExecution, contracts.ReasonIO, errors.Join(retErr, err))
			}
		}
	}()
	for i, patch := range req.Patches {
		if err := ctx.Err(); err != nil {
			return fail(contracts.StageExecution, contracts.ReasonCancelled, err)
		}
		nextFiles, nextModes, err := plannedFiles(files, modes, patch.Targets)
		if err != nil {
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, contracts.ReasonPatchFailed
			return fail(contracts.StageExecution, contracts.ReasonPatchFailed, err)
		}
		began = true // Parent preparation below mutates only the private workspace.
		if err := additionParents(root, patch.Targets); err != nil {
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, contracts.ReasonIO
			return fail(contracts.StageExecution, contracts.ReasonIO, err)
		}
		args := []string{"--batch", "--forward", "--fuzz=0", "--strip=1", "--no-backup-if-mismatch", "--get=0", "--quoting-style=literal", "--directory", workspace}
		applied := process(ctx, executable, args, workspace, stages[i], limits)
		result.Diagnostics = string(applied.combined)
		if reason, cause := applied.operational(); reason != contracts.ReasonNone {
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, reason
			return fail(contracts.StageExecution, reason, cause)
		}
		if applied.err != nil || !cleanDiagnostics(applied.stdout, applied.stderr, patch.Targets) {
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, contracts.ReasonPatchFailed
			return fail(contracts.StageExecution, contracts.ReasonPatchFailed, applied.err)
		}
		actual, err := workspaceFiles(ctx, root, true, nextModes)
		if err != nil {
			failure := contracts.FailureFromError(contracts.StageExecution, err)
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, failure.Reason
			return fail(failure.Stage, failure.Reason, err)
		}
		if !sameFiles(actual, nextFiles) {
			result.Patches[i].Status, result.Patches[i].Reason = contracts.PatchFailed, contracts.ReasonPatchFailed
			return fail(contracts.StageExecution, contracts.ReasonPatchFailed, errors.New("patch changed unexpected file inventory"))
		}
		files, modes = nextFiles, nextModes
		result.Patches[i].Status = contracts.PatchApplied
	}
	records, digest, err := treedigest.ComputeRoot(ctx, root, modes)
	if err != nil {
		failure := contracts.FailureFromError(contracts.StageDigest, err)
		return fail(failure.Stage, failure.Reason, err)
	}
	// Mode restoration is a private mutation, including for an empty patch series.
	began = true
	if err := treedigest.RestoreModes(ctx, workspace, records); err != nil {
		failure := contracts.FailureFromError(contracts.StageDigest, err)
		return fail(failure.Stage, failure.Reason, err)
	}
	if err := ctx.Err(); err != nil {
		return fail(contracts.StageDigest, contracts.ReasonCancelled, err)
	}
	complete = true
	result.Files, result.FinalTreeSHA256 = records, digest
	result.Diagnostics = ""
	return result, nil
}

func cleanDiagnostics(stdout, stderr []byte, targets []contracts.PatchTarget) bool {
	var want strings.Builder
	for _, target := range targets {
		name := target.NewPath
		if name == "" {
			name = target.OldPath
		}
		fmt.Fprintf(&want, "patching file %s\n", name)
	}
	return len(stderr) == 0 && bytes.Equal(stdout, []byte(want.String()))
}

func validateTargets(patches []contracts.StagedPatch) error {
	if len(patches) > contracts.MaxPatches {
		return errors.New("too many staged patches")
	}
	for _, patch := range patches {
		if len(patch.Targets) == 0 {
			return errors.New("missing verified patch targets")
		}
		for _, target := range patch.Targets {
			for _, name := range []string{target.OldPath, target.NewPath} {
				if name == "" {
					continue
				}
				if _, err := contracts.StripPatchPath("a/" + name); err != nil {
					return err
				}
			}
			switch target.Operation {
			case contracts.OperationModify:
				if target.OldPath == "" || target.OldPath != target.NewPath {
					return errors.New("invalid modify target")
				}
			case contracts.OperationAdd:
				if target.OldPath != "" || target.NewPath == "" {
					return errors.New("invalid add target")
				}
			case contracts.OperationDelete:
				if target.NewPath != "" || target.OldPath == "" {
					return errors.New("invalid delete target")
				}
			default:
				return errors.New("unsupported target operation")
			}
		}
	}
	return nil
}

func openStages(ctx context.Context, patches []contracts.StagedPatch) (files []*os.File, reason contracts.Reason, retErr error) {
	success := false
	defer func() {
		if !success {
			for _, file := range files {
				file.Close()
			}
			files = nil
		}
	}()
	for _, patch := range patches {
		if err := ctx.Err(); err != nil {
			return files, contracts.ReasonCancelled, err
		}
		if patch.Input.Size <= 0 || patch.Input.Size > contracts.MaxPatchBytes || patch.Input.SHA256 != patch.Patch.SHA256 {
			return files, contracts.ReasonUnsafeInput, errors.New("invalid verified staged identity")
		}
		file, err := openStage(patch.Input.Path)
		if err != nil {
			return files, contracts.ReasonIO, err
		}
		files = append(files, file)
		hash := sha256.New()
		size, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, contracts.MaxPatchBytes+1))
		if err != nil {
			if ctx.Err() != nil {
				return files, contracts.ReasonCancelled, ctx.Err()
			}
			return files, contracts.ReasonIO, err
		}
		if size > contracts.MaxPatchBytes {
			return files, contracts.ReasonLimitExceeded, errors.New("staged patch exceeds fixed limit")
		}
		if size != patch.Input.Size || hex.EncodeToString(hash.Sum(nil)) != patch.Input.SHA256 {
			return files, contracts.ReasonHashMismatch, errors.New("staged patch bytes changed")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return files, contracts.ReasonIO, err
		}
	}
	success = true
	return files, contracts.ReasonNone, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func plannedFiles(files map[string]bool, modes map[string]uint32, targets []contracts.PatchTarget) (map[string]bool, map[string]uint32, error) {
	nextFiles, nextModes := make(map[string]bool, len(files)), make(map[string]uint32, len(modes))
	for name, exists := range files {
		nextFiles[name] = exists
	}
	for name, mode := range modes {
		nextModes[name] = mode
	}
	for _, target := range targets {
		switch target.Operation {
		case contracts.OperationAdd:
			if nextFiles[target.NewPath] {
				return nil, nil, errors.New("addition target already exists")
			}
			nextFiles[target.NewPath], nextModes[target.NewPath] = true, contracts.NewFileMode
		case contracts.OperationDelete:
			if !nextFiles[target.OldPath] {
				return nil, nil, errors.New("deletion target is absent")
			}
			delete(nextFiles, target.OldPath)
			delete(nextModes, target.OldPath)
		case contracts.OperationModify:
			if !nextFiles[target.OldPath] {
				return nil, nil, errors.New("modification target is absent")
			}
		}
	}
	return nextFiles, nextModes, nil
}

func workspaceFiles(ctx context.Context, root *os.Root, normalize bool, modes map[string]uint32) (map[string]bool, error) {
	files := map[string]bool{}
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return runError(contracts.StageExecution, contracts.ReasonCancelled, err)
		}
		if walkErr != nil {
			return runError(contracts.StageExecution, contracts.ReasonIO, walkErr)
		}
		if name != "." && contracts.ValidateRelativePath(name) != nil {
			return runError(contracts.StageExecution, contracts.ReasonUnsafeInput, errors.New("unsafe workspace path"))
		}
		if entry.IsDir() {
			if normalize {
				return root.Chmod(name, 0700)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return runError(contracts.StageExecution, contracts.ReasonUnsafeInput, errors.New("workspace contains links or special files"))
		}
		files[name] = true
		if normalize {
			return root.Chmod(name, os.FileMode(modes[name]|0600))
		}
		return nil
	})
	return files, err
}

func additionParents(root *os.Root, targets []contracts.PatchTarget) error {
	for _, target := range targets {
		if target.Operation != contracts.OperationAdd {
			continue
		}
		var prefix string
		parent := path.Dir(target.NewPath)
		if parent == "." {
			continue
		}
		for _, part := range strings.Split(parent, "/") {
			prefix = path.Join(prefix, part)
			if err := root.Mkdir(prefix, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err := root.Lstat(prefix)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return errors.New("addition parent is not a directory")
			}
			if err := root.Chmod(prefix, 0700); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameFiles(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for name := range a {
		if !b[name] {
			return false
		}
	}
	return true
}

func clearWorkspace(root *os.Root) error {
	// Restoration may have made files unreadable; removing directory entries
	// needs only directory owner access. Source/output directories are traversable.
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		result = errors.Join(result, root.RemoveAll(entry.Name()))
	}
	return result
}

func runError(stage contracts.Stage, reason contracts.Reason, err error) error {
	return &contracts.RunError{Stage: stage, Reason: reason, Err: err}
}
