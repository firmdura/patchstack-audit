// Package treedigest computes the version 1 canonical source tree inventory and
// restores intended publication modes only after readable content is hashed.
package treedigest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"syscall"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/inputfs"
)

// Compute hashes regular files while they retain temporary owner access. Modes
// come from intendedModes; new files absent from that map use 0644. Removed files
// and empty directories are excluded. It returns sorted records and SHA-256 of
// path NUL four-digit octal mode NUL lowercase file SHA-256 LF for each record.
// The workspace must remain private and unmodified throughout Compute/RestoreModes.
func Compute(ctx context.Context, workspace string, intendedModes map[string]uint32) ([]contracts.FileRecord, string, error) {
	inputs, err := inputfs.Open(workspace)
	if err != nil {
		return nil, "", fromInput(err)
	}
	defer inputs.Close()
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, "", failure(contracts.ReasonIO, err)
	}
	defer root.Close()
	return compute(ctx, root, inputs, intendedModes)
}

// ComputeRoot hashes a trusted private workspace through an already-retained
// directory root. It leaves root open and never resolves its original pathname;
// descendants still use confined reads rejecting symlinks and special files.
func ComputeRoot(ctx context.Context, root *os.Root, intendedModes map[string]uint32) ([]contracts.FileRecord, string, error) {
	if root == nil {
		return nil, "", failure(contracts.ReasonIO, os.ErrInvalid)
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, "", failure(contracts.ReasonIO, err)
	}
	inputs, retainErr := inputfs.FromDirectory(dir)
	closeErr := dir.Close()
	if retainErr != nil {
		return nil, "", fromInput(retainErr)
	}
	defer inputs.Close()
	if closeErr != nil {
		return nil, "", failure(contracts.ReasonIO, closeErr)
	}
	return compute(ctx, root, inputs, intendedModes)
}

func compute(ctx context.Context, root *os.Root, inputs *inputfs.Root, intendedModes map[string]uint32) ([]contracts.FileRecord, string, error) {
	for name, mode := range intendedModes {
		if err := contracts.ValidateRelativePath(name); err != nil || mode > 0777 {
			return nil, "", failure(contracts.ReasonUnsafeInput, errors.New("invalid intended file mode/path"))
		}
	}
	var files []contracts.FileRecord
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return failure(contracts.ReasonCancelled, err)
		}
		if walkErr != nil {
			return failure(contracts.ReasonIO, walkErr)
		}
		if name == "." {
			return nil
		}
		if err := contracts.ValidateRelativePath(name); err != nil {
			return failure(contracts.ReasonUnsafeInput, err)
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type() != 0 {
			return failure(contracts.ReasonUnsafeInput, errors.New("source tree contains a link or special file"))
		}
		f, err := inputs.OpenRegular(ctx, name)
		if err != nil {
			return fromInput(err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, f)
		closeErr := f.Close()
		if copyErr != nil {
			return fromInput(copyErr)
		}
		if closeErr != nil {
			return fromInput(closeErr)
		}
		mode, exists := intendedModes[name]
		if !exists {
			mode = contracts.NewFileMode
		}
		files = append(files, contracts.FileRecord{Path: name, Mode: fmt.Sprintf("%04o", mode), SHA256: hex.EncodeToString(hash.Sum(nil))})
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	hash := sha256.New()
	for _, file := range files {
		fmt.Fprintf(hash, "%s\x00%s\x00%s\n", file.Path, file.Mode, file.SHA256)
	}
	return files, hex.EncodeToString(hash.Sum(nil)), nil
}

// RestoreModes applies the final file modes from a successful Compute result and
// 0755 directory modes. Call it only after the entire patch series and digest
// succeed, immediately before publication. A final 0000 file needs no later read.
func RestoreModes(ctx context.Context, workspace string, files []contracts.FileRecord) error {
	if err := ctx.Err(); err != nil {
		return failure(contracts.ReasonCancelled, err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return failure(contracts.ReasonIO, err)
	}
	defer root.Close()
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return failure(contracts.ReasonCancelled, err)
		}
		mode, err := strconv.ParseUint(file.Mode, 8, 32)
		if err != nil || len(file.Mode) != 4 || file.Mode[0] != '0' || mode > 0777 || seen[file.Path] {
			return failure(contracts.ReasonUnsafeInput, errors.New("invalid or duplicate final file mode"))
		}
		if err := contracts.ValidateRelativePath(file.Path); err != nil {
			return failure(contracts.ReasonUnsafeInput, err)
		}
		seen[file.Path] = true
		if err := chmod(root, file.Path, os.FileMode(mode), false); err != nil {
			return err
		}
	}
	// Directories are traversable during the walk and all receive the same final
	// mode, including empty directories and the source root itself.
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return failure(contracts.ReasonCancelled, err)
		}
		if walkErr != nil {
			return failure(contracts.ReasonIO, walkErr)
		}
		if entry.IsDir() {
			return chmod(root, name, os.FileMode(contracts.DirectoryMode), true)
		}
		if entry.Type() != 0 || !seen[name] {
			return failure(contracts.ReasonUnsafeInput, errors.New("source tree differs from computed inventory"))
		}
		return nil
	})
}

func chmod(root *os.Root, name string, mode os.FileMode, directory bool) error {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	f, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return failure(contracts.ReasonIO, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return failure(contracts.ReasonIO, err)
	}
	if (!directory && !info.Mode().IsRegular()) || (directory && !info.IsDir()) {
		return failure(contracts.ReasonUnsafeInput, errors.New("source entry changed type"))
	}
	if err := f.Chmod(mode); err != nil {
		return failure(contracts.ReasonIO, err)
	}
	return nil
}

func fromInput(err error) error {
	f := contracts.FailureFromError(contracts.StageDigest, err)
	return failure(f.Reason, err)
}

func failure(reason contracts.Reason, err error) error {
	return &contracts.RunError{Stage: contracts.StageDigest, Reason: reason, Err: err}
}
