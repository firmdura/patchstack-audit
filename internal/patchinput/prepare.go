package patchinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

// Inventory implements the version 1 patch-preparation contract. Callers provide
// a validated declaration, retained confined input view and private staging
// directory. Every returned file belongs to a new private child of StagingDir;
// the owner removes that staging tree after execution or cancellation.
type Inventory struct{}

var _ contracts.PatchInventory = Inventory{}

func (Inventory) Prepare(ctx context.Context, req contracts.PatchRequest) (result contracts.InventoryResult, err error) {
	if err := ctx.Err(); err != nil {
		return operational(contracts.ReasonCancelled, err)
	}
	if err := validateRequest(req); err != nil {
		return operational(contracts.ReasonInvalidManifest, err)
	}
	if req.Inputs == nil {
		return operational(contracts.ReasonIO, errors.New("missing confined input view"))
	}
	if failure, err := inventory(ctx, req); failure != nil || err != nil {
		return contracts.InventoryResult{Failure: failure}, err
	}
	if len(req.Patches) == 0 {
		return contracts.InventoryResult{Patches: []contracts.StagedPatch{}}, nil
	}
	if req.StagingDir == "" {
		return operational(contracts.ReasonIO, errors.New("missing private staging directory"))
	}
	stage, err := os.MkdirTemp(req.StagingDir, "patches-")
	if err != nil {
		return operational(contracts.ReasonIO, err)
	}
	accepted := false
	defer func() {
		if !accepted {
			if cleanupErr := os.RemoveAll(stage); cleanupErr != nil {
				result, err = operational(contracts.ReasonIO, fmt.Errorf("remove failed patch staging: %w", cleanupErr))
			}
		}
	}()
	// Creation permissions are filtered by umask. Restore private owner access
	// explicitly before creating children, even under umask 0777.
	if err := os.Chmod(stage, 0700); err != nil {
		return operational(contracts.ReasonIO, err)
	}
	patches := make([]contracts.StagedPatch, 0, len(req.Patches))
	for i, patch := range req.Patches {
		staged, reason, err := stagePatch(ctx, req, stage, i, patch)
		if reason != contracts.ReasonNone {
			if reason.Expected() {
				return expected(reason), nil
			}
			return operational(reason, err)
		}
		patches = append(patches, staged)
	}
	// Recheck the complete inventory after all reads. A changed entry, a newly
	// introduced directory or an unlisted hidden file cannot be silently accepted.
	if failure, err := inventory(ctx, req); failure != nil || err != nil {
		return contracts.InventoryResult{Failure: failure}, err
	}
	if err := ctx.Err(); err != nil {
		return operational(contracts.ReasonCancelled, err)
	}
	accepted = true
	return contracts.InventoryResult{Patches: patches}, nil
}

func validateRequest(req contracts.PatchRequest) error {
	if err := contracts.ValidateRelativePath(req.PatchDir); err != nil {
		return err
	}
	if len(req.Patches) > contracts.MaxPatches {
		return errors.New("too many patches")
	}
	ids, files, hashes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, patch := range req.Patches {
		if strings.TrimSpace(patch.ID) == "" || ids[patch.ID] || files[patch.File] || hashes[patch.SHA256] {
			return errors.New("missing or duplicate patch identity")
		}
		if err := contracts.ValidateBasename(patch.File); err != nil {
			return err
		}
		decoded, err := hex.DecodeString(patch.SHA256)
		if err != nil || len(decoded) != sha256.Size || strings.ToLower(patch.SHA256) != patch.SHA256 {
			return errors.New("invalid patch SHA-256")
		}
		ids[patch.ID], files[patch.File], hashes[patch.SHA256] = true, true, true
	}
	return nil
}

func inventory(ctx context.Context, req contracts.PatchRequest) (*contracts.Failure, error) {
	if err := ctx.Err(); err != nil {
		result, err := operational(contracts.ReasonCancelled, err)
		return result.Failure, err
	}
	entries, err := req.Inputs.ReadDir(ctx, req.PatchDir)
	if cancelled := ctx.Err(); cancelled != nil {
		result, err := operational(contracts.ReasonCancelled, cancelled)
		return result.Failure, err
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return expected(contracts.ReasonInventoryMismatch).Failure, nil
		}
		result, err := inputFailure(err)
		return result.Failure, err
	}
	expectedNames := make(map[string]bool, len(req.Patches))
	for _, patch := range req.Patches {
		expectedNames[patch.File] = true
	}
	if len(entries) != len(expectedNames) {
		return expected(contracts.ReasonInventoryMismatch).Failure, nil
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Directory || !expectedNames[entry.Name] || seen[entry.Name] {
			return expected(contracts.ReasonInventoryMismatch).Failure, nil
		}
		seen[entry.Name] = true
	}
	return nil, nil
}

func stagePatch(ctx context.Context, req contracts.PatchRequest, stage string, index int, patch contracts.Patch) (contracts.StagedPatch, contracts.Reason, error) {
	var zero contracts.StagedPatch
	if err := ctx.Err(); err != nil {
		return zero, contracts.ReasonCancelled, err
	}
	input, err := req.Inputs.OpenRegular(ctx, req.PatchDir+"/"+patch.File)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return zero, contracts.ReasonInventoryMismatch, nil
		}
		failure := contracts.FailureFromError(contracts.StageInventory, err)
		return zero, failure.Reason, err
	}
	path := filepath.Join(stage, fmt.Sprintf("%03d.patch", index))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = input.Close()
		return zero, contracts.ReasonIO, err
	}
	if err := file.Chmod(0600); err != nil {
		_ = input.Close()
		_ = file.Close()
		return zero, contracts.ReasonIO, err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(contextReader{ctx, input}, contracts.MaxPatchBytes+1))
	inputCloseErr := input.Close()
	fileCloseErr := file.Close()
	if err := ctx.Err(); err != nil {
		return zero, contracts.ReasonCancelled, err
	}
	if count > contracts.MaxPatchBytes {
		return zero, contracts.ReasonLimitExceeded, errors.New("patch exceeds version 1 byte limit")
	}
	for _, err := range []error{copyErr, inputCloseErr, fileCloseErr} {
		if err != nil {
			failure := contracts.FailureFromError(contracts.StageInventory, err)
			return zero, failure.Reason, err
		}
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != patch.SHA256 {
		return zero, contracts.ReasonHashMismatch, nil
	}
	if err := os.Chmod(path, 0400); err != nil {
		return zero, contracts.ReasonIO, err
	}
	// Parsing consumes the same verified private bytes that execution receives.
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, contracts.ReasonIO, err
	}
	targets, err := parse(data)
	if err != nil {
		return zero, contracts.ReasonUnsafeInput, err
	}
	return contracts.StagedPatch{
		Patch:   patch,
		Input:   contracts.StagedFile{Path: path, SHA256: actual, Size: count},
		Targets: targets,
	}, contracts.ReasonNone, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func expected(reason contracts.Reason) contracts.InventoryResult {
	return contracts.InventoryResult{Failure: &contracts.Failure{Stage: contracts.StageInventory, Reason: reason}}
}

func operational(reason contracts.Reason, cause error) (contracts.InventoryResult, error) {
	return expected(reason), &contracts.RunError{Stage: contracts.StageInventory, Reason: reason, Err: cause}
}

func inputFailure(err error) (contracts.InventoryResult, error) {
	failure := contracts.FailureFromError(contracts.StageInventory, err)
	return operational(failure.Reason, err)
}
