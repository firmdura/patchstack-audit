//go:build linux

// Package inputfs provides the retained, read-only input root used during preparation.
// Version 1 supports Linux; every path component is opened relative to a retained
// descriptor with O_NOFOLLOW, including symlinks whose targets remain in the root.
package inputfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

// Root retains the identity of one input directory until Close. Its methods are
// safe for concurrent use; callers must keep it open throughout preparation.
type Root struct{ dir *os.File }

var _ contracts.ConfinedInputs = (*Root)(nil)

// FromDirectory retains its own duplicate of a trusted, already-open directory.
// The caller retains ownership of file. Descendant reads retain Open's confined
// no-symlink semantics; this constructor does not resolve a pathname.
func FromDirectory(file *os.File) (*Root, error) {
	if file == nil {
		return nil, inputError(os.ErrInvalid)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, inputError(err)
	}
	var fd uintptr
	var duplicateErr syscall.Errno
	err = raw.Control(func(source uintptr) {
		fd, _, duplicateErr = syscall.Syscall(syscall.SYS_FCNTL, source, syscall.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil {
		return nil, inputError(err)
	}
	if duplicateErr != 0 {
		return nil, inputError(duplicateErr)
	}
	dir := os.NewFile(fd, "retained input directory")
	info, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, inputError(err)
	}
	if !info.IsDir() {
		dir.Close()
		return nil, unsafe("input is not a directory")
	}
	return &Root{dir: dir}, nil
}

// Stat returns the retained directory identity, even if its pathname has moved.
// Publication uses this identity to keep output outside the actual input root.
func (r *Root) Stat() (os.FileInfo, error) {
	if r == nil || r.dir == nil {
		return nil, inputError(os.ErrClosed)
	}
	info, err := r.dir.Stat()
	if err != nil {
		return nil, inputError(err)
	}
	return info, nil
}

// Open retains an existing directory without following any symlink component.
// Renaming or replacing the original root pathname does not redirect reads.
func Open(name string) (*Root, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, inputError(err)
	}
	fd, err := syscall.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, inputError(err)
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, component := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := openAt(dir, component, directoryFlags)
		dir.Close()
		if err != nil {
			return nil, inputError(err)
		}
		dir = next
	}
	return &Root{dir: dir}, nil
}

// Close releases the retained root. It must be called after its readers finish.
func (r *Root) Close() error {
	if r == nil || r.dir == nil {
		return nil
	}
	if err := r.dir.Close(); err != nil {
		return inputError(err)
	}
	return nil
}

const directoryFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK

// OpenRegular opens only a regular file, rejecting all symlink components and
// special files. Reads preserve InputError classification and check cancellation.
func (r *Root) OpenRegular(ctx context.Context, name string) (io.ReadCloser, error) {
	f, err := r.open(ctx, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOCTTY)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, inputError(err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, unsafe("input is not a regular file")
	}
	return &reader{ctx: ctx, file: f}, nil
}

// ReadDir returns every entry, including hidden names, in byte-sorted order.
// It rejects symlinks and special entries instead of silently filtering them.
func (r *Root) ReadDir(ctx context.Context, name string) ([]contracts.InputEntry, error) {
	dir, err := r.open(ctx, name, directoryFlags)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, inputError(err)
	}
	result := make([]contracts.InputEntry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, inputError(err)
		}
		if err := contracts.ValidateBasename(entry.Name()); err != nil {
			return nil, unsafe("invalid directory entry name")
		}
		// O_PATH never opens a device or waits on a FIFO. O_NOFOLLOW returns a
		// descriptor for a symlink itself, which the subsequent fstat rejects.
		const oPath = 0x200000
		f, err := openAt(dir, entry.Name(), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
		if err != nil {
			return nil, inputError(err)
		}
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil {
			return nil, inputError(statErr)
		}
		if closeErr != nil {
			return nil, inputError(closeErr)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, unsafe("directory contains a symlink or special entry")
		}
		result = append(result, contracts.InputEntry{Name: entry.Name(), Directory: info.IsDir()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (r *Root) open(ctx context.Context, name string, flags int) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, inputError(err)
	}
	if err := contracts.ValidateRelativePath(name); err != nil {
		return nil, unsafe("invalid relative input path")
	}
	if r == nil || r.dir == nil {
		return nil, inputError(os.ErrClosed)
	}
	parts := strings.Split(name, "/")
	parent := r.dir
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			if parent != r.dir {
				parent.Close()
			}
			return nil, inputError(err)
		}
		componentFlags := directoryFlags
		if i == len(parts)-1 {
			componentFlags = flags
		}
		next, err := openAt(parent, part, componentFlags)
		if parent != r.dir {
			parent.Close()
		}
		if err != nil {
			return nil, inputError(err)
		}
		parent = next
	}
	return parent, nil
}

// RawConn.Control holds the descriptor open through openat, including if a
// concurrent caller closes the Root; an integer fd cannot be recycled mid-open.
func openAt(parent *os.File, name string, flags int) (*os.File, error) {
	raw, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var openErr error
	if err := raw.Control(func(parentFD uintptr) {
		fd, openErr = syscall.Openat(int(parentFD), name, flags, 0)
	}); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, openErr
	}
	return os.NewFile(uintptr(fd), name), nil
}

type reader struct {
	ctx  context.Context
	file *os.File
}

func (r *reader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, inputError(err)
	}
	n, err := r.file.Read(p)
	if err != nil && err != io.EOF {
		err = inputError(err)
	}
	return n, err
}

func (r *reader) Close() error {
	if err := r.file.Close(); err != nil {
		return inputError(err)
	}
	return nil
}

func unsafe(message string) error {
	return &contracts.InputError{Reason: contracts.ReasonUnsafeInput, Err: errors.New(message)}
}

func inputError(err error) error {
	reason := contracts.ReasonIO
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		reason = contracts.ReasonCancelled
	} else if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENXIO) {
		reason = contracts.ReasonUnsafeInput
	}
	return &contracts.InputError{Reason: reason, Err: fmt.Errorf("input read: %w", err)}
}
