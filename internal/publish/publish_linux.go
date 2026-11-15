//go:build linux

// Package publish keeps a completed output package private until one Linux
// atomic no-replace rename makes it visible at the requested destination.
package publish

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

const directoryFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
const pathFlags = 0x200000 | syscall.O_NOFOLLOW | syscall.O_CLOEXEC // Linux O_PATH

// Transaction owns a private temporary sibling and retained directory identities.
// Dir is an operational path, valid until Cleanup, including for child processes.
// Callers finish the package and remove all staging material before Publish.
type Transaction struct {
	mu        sync.Mutex
	parent    *os.File
	outer     *os.File
	inputInfo os.FileInfo
	tempName  string
	destName  string
	dir       string
	output    string
	published bool
	closed    bool
}

// Begin validates an absent output with an existing, symlink-free parent outside
// the actual retained input directory. inputInfo must come from the open input
// root, not a new Stat of its pathname. No directories are created on validation
// failure. The private outer directory stays 0700 even when its package is ready
// for publication with mode 0755.
func Begin(ctx context.Context, inputInfo os.FileInfo, outputDir string) (_ *Transaction, retErr error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if inputInfo == nil || !inputInfo.IsDir() || outputDir == "" {
		return nil, failure(contracts.ReasonUnsafeInput, errors.New("input directory identity and output path are required"))
	}
	output, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, failure(contracts.ReasonIO, err)
	}
	name := filepath.Base(output)
	if name == "." || name == string(filepath.Separator) {
		return nil, failure(contracts.ReasonOutputExists, errors.New("output already exists"))
	}
	parent, err := openDirectory(filepath.Dir(output))
	if err != nil {
		return nil, classify(err)
	}
	tx := &Transaction{parent: parent, inputInfo: inputInfo, destName: name, output: output}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, tx.Cleanup())
		}
	}()
	if err := outsideInput(ctx, parent, inputInfo); err != nil {
		return nil, err
	}
	if err := absent(parent, name); err != nil {
		return nil, err
	}
	for range 100 {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, failure(contracts.ReasonIO, err)
		}
		temp := ".patchstack-" + hex.EncodeToString(random[:])
		if err := syscall.Mkdirat(int(parent.Fd()), temp, 0700); errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return nil, classify(err)
		}
		tx.tempName = temp
		// O_PATH permits opening our newly created directory even under umask
		// 0777. Chmod through the retained descriptor, never a reopened name.
		fd, err := syscall.Openat(int(parent.Fd()), temp, pathFlags|syscall.O_DIRECTORY, 0)
		if err != nil {
			return nil, classify(err)
		}
		pathDir := os.NewFile(uintptr(fd), temp)
		info, statErr := pathDir.Stat()
		if statErr == nil && info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			statErr = errors.New("temporary directory changed ownership")
		}
		if statErr == nil {
			statErr = os.Chmod(fdPath(pathDir), 0700)
		}
		if statErr == nil {
			tx.outer, statErr = os.Open(fdPath(pathDir))
		}
		pathDir.Close()
		if statErr != nil {
			return nil, classify(statErr)
		}
		tx.dir = filepath.Join(fdPath(tx.outer), "package")
		if err := syscall.Mkdirat(int(tx.outer.Fd()), "package", 0700); err != nil {
			return nil, classify(err)
		}
		if err := os.Chmod(tx.dir, 0700); err != nil {
			return nil, classify(err)
		}
		return tx, nil
	}
	return nil, failure(contracts.ReasonIO, errors.New("could not allocate a unique temporary sibling"))
}

// Dir returns the private package directory. It deliberately uses a retained
// descriptor path so moving/replacing an output ancestor cannot redirect writes.
func (t *Transaction) Dir() string { return t.dir }

// OutputDir returns the requested absolute output path for operational diagnostics.
func (t *Transaction) OutputDir() string { return t.output }

// Published reports whether the final no-replace rename completed. Cleanup
// errors after this point must retain the complete successful report and output.
func (t *Transaction) Published() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.published
}

// Publish atomically installs a complete package without replacing any competing
// destination. It performs no fallible cleanup after a successful rename; call
// Cleanup separately. Unsupported kernels/filesystems fail explicitly.
func (t *Transaction) Publish(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if t.closed || t.published {
		return failure(contracts.ReasonIO, errors.New("publication transaction is no longer pending"))
	}
	currentParent, err := openDirectory(filepath.Dir(t.output))
	if err != nil {
		return classify(err)
	}
	currentInfo, statErr := currentParent.Stat()
	parentInfo, parentErr := t.parent.Stat()
	closeErr := currentParent.Close()
	if statErr != nil || parentErr != nil || closeErr != nil {
		return classify(errors.Join(statErr, parentErr, closeErr))
	}
	if !os.SameFile(currentInfo, parentInfo) {
		return failure(contracts.ReasonUnsafeInput, errors.New("output parent path changed during the run"))
	}
	if err := outsideInput(ctx, t.parent, t.inputInfo); err != nil {
		return err
	}
	// The package is still shielded by its private 0700 outer directory.
	if err := os.Chmod(t.dir, os.FileMode(contracts.DirectoryMode)); err != nil {
		return classify(err)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := renameNoReplace(int(t.outer.Fd()), "package", int(t.parent.Fd()), t.destName); err != nil {
		return classify(err)
	}
	t.published = true
	return nil
}

// Cleanup removes unpublished contents and the temporary outer directory. It is
// idempotent and never removes the published output. A caller must propagate any
// cleanup failure, preserving publication state when Published is true.
func (t *Transaction) Cleanup() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	var result error
	if t.outer != nil {
		root, err := os.OpenRoot(fdPath(t.outer))
		if err == nil {
			err = removeTree(root, ".")
			result = errors.Join(result, root.Close())
		}
		result = errors.Join(result, err)
		result = errors.Join(result, t.outer.Close())
	}
	if t.tempName != "" {
		result = errors.Join(result, removeDirectoryAt(int(t.parent.Fd()), t.tempName))
	}
	result = errors.Join(result, t.parent.Close())
	t.closed = true
	if result != nil {
		return failure(contracts.ReasonIO, result)
	}
	return nil
}

func removeTree(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := root.Chmod(name, 0700); err != nil {
			return err
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := f.ReadDir(-1)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, entry := range entries {
			if err := removeTree(root, filepath.Join(name, entry.Name())); err != nil {
				return err
			}
		}
	}
	if name == "." {
		return nil
	}
	return root.Remove(name)
}

func openDirectory(name string) (*os.File, error) {
	fd, err := syscall.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := syscall.Openat(int(dir.Fd()), part, directoryFlags, 0)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = os.NewFile(uintptr(next), part)
	}
	return dir, nil
}

func outsideInput(ctx context.Context, parent *os.File, input os.FileInfo) error {
	fd, err := syscall.Openat(int(parent.Fd()), ".", directoryFlags, 0)
	if err != nil {
		return classify(err)
	}
	dir := os.NewFile(uintptr(fd), ".")
	defer func() { dir.Close() }()
	for {
		if err := contextError(ctx); err != nil {
			return err
		}
		info, err := dir.Stat()
		if err != nil {
			return classify(err)
		}
		if os.SameFile(info, input) {
			return failure(contracts.ReasonUnsafeInput, errors.New("output must be outside the retained input root"))
		}
		nextFD, err := syscall.Openat(int(dir.Fd()), "..", directoryFlags, 0)
		if err != nil {
			return classify(err)
		}
		next := os.NewFile(uintptr(nextFD), "..")
		nextInfo, err := next.Stat()
		if err != nil {
			next.Close()
			return classify(err)
		}
		if os.SameFile(info, nextInfo) {
			next.Close()
			return nil
		}
		dir.Close()
		dir = next
	}
}

func absent(parent *os.File, name string) error {
	fd, err := syscall.Openat(int(parent.Fd()), name, pathFlags, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return classify(err)
	}
	syscall.Close(fd)
	return failure(contracts.ReasonOutputExists, errors.New("output already exists"))
}

func fdPath(file *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return failure(contracts.ReasonIO, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return failure(contracts.ReasonCancelled, err)
	}
	return nil
}

func classify(err error) error {
	switch {
	case errors.Is(err, syscall.EEXIST), errors.Is(err, syscall.ENOTEMPTY):
		return failure(contracts.ReasonOutputExists, err)
	case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.EINVAL):
		return failure(contracts.ReasonUnsupportedPublication, err)
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
		return failure(contracts.ReasonUnsafeInput, err)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		return failure(contracts.ReasonIO, err)
	default:
		return failure(contracts.ReasonIO, err)
	}
}

func failure(reason contracts.Reason, err error) error {
	return &contracts.RunError{Stage: contracts.StagePublication, Reason: reason, Err: err}
}
