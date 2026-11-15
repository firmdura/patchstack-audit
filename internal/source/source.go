// Package source freezes and verifies a declared source archive before extracting
// regular files and directories into a caller-owned private empty workspace.
// It never executes patches or publishes output.
package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

// Preparer implements the fixed version 1 source preparation limits.
type Preparer struct{}

var _ contracts.SourcePreparer = Preparer{}

type limits struct {
	archive, extracted int64
	entries            int
}

var errLimit = errors.New("source preparation limit exceeded")

// Prepare hashes while copying to a private staged file, compares the declared
// hash, then extracts only those staged bytes. WorkspaceDir must be an existing
// empty private directory; StagingDir must be an existing private directory.
// On failure, created staging and workspace contents are removed. File modes in
// IntendedModes are final 0777 bits; extracted files retain temporary owner access.
func (Preparer) Prepare(ctx context.Context, req contracts.SourceRequest) (contracts.SourceResult, error) {
	return prepare(ctx, req, limits{contracts.MaxArchiveBytes, contracts.MaxExtractedBytes, contracts.MaxArchiveEntries})
}

func prepare(ctx context.Context, req contracts.SourceRequest, lim limits) (result contracts.SourceResult, retErr error) {
	if err := ctx.Err(); err != nil {
		return failed(contracts.ReasonCancelled, err)
	}
	if req.Inputs == nil {
		return failed(contracts.ReasonIO, errors.New("missing confined inputs"))
	}
	if err := contracts.ValidateRelativePath(req.Source.Path); err != nil {
		return failed(contracts.ReasonUnsafeInput, err)
	}
	if err := contracts.ValidateBasename(req.Source.RootDir); err != nil {
		return failed(contracts.ReasonUnsafeInput, err)
	}
	workspace, err := os.OpenRoot(req.WorkspaceDir)
	if err != nil {
		return failed(contracts.ReasonIO, err)
	}
	defer workspace.Close()
	dir, err := workspace.Open(".")
	if err != nil {
		return failed(contracts.ReasonIO, err)
	}
	entries, readErr := dir.ReadDir(1)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF {
		return failed(contracts.ReasonIO, readErr)
	}
	if closeErr != nil {
		return failed(contracts.ReasonIO, closeErr)
	}
	if len(entries) != 0 {
		return failed(contracts.ReasonUnsafeInput, errors.New("source workspace is not empty"))
	}
	// This directory is caller-owned private preparation space, never an input.
	if err := workspace.Chmod(".", 0700); err != nil {
		return failed(contracts.ReasonIO, err)
	}
	var staged string
	success := false
	defer func() {
		if success {
			return
		}
		var cleanupErr error
		if staged != "" {
			cleanupErr = os.Remove(staged)
		}
		cleanupDir, err := workspace.Open(".")
		if err == nil {
			var remaining []os.DirEntry
			remaining, err = cleanupDir.ReadDir(-1)
			cleanupDir.Close()
			for _, entry := range remaining {
				err = errors.Join(err, workspace.RemoveAll(entry.Name()))
			}
		}
		cleanupErr = errors.Join(cleanupErr, err)
		if cleanupErr != nil {
			result, retErr = failed(contracts.ReasonIO, errors.Join(retErr, cleanupErr))
		}
	}()
	input, err := req.Inputs.OpenRegular(ctx, req.Source.Path)
	if err != nil {
		return failedInput(err)
	}
	stage, err := os.CreateTemp(req.StagingDir, "source-*.tar.gz")
	if err != nil {
		input.Close()
		return failed(contracts.ReasonIO, err)
	}
	staged = stage.Name()
	if err := stage.Chmod(0600); err != nil {
		stage.Close()
		input.Close()
		return failed(contracts.ReasonIO, err)
	}
	hash := sha256.New()
	size, copyErr := copyBounded(ctx, io.MultiWriter(stage, hash), input, lim.archive)
	inputCloseErr := input.Close()
	stageCloseErr := stage.Close()
	if copyErr != nil {
		if errors.Is(copyErr, errLimit) {
			return failed(contracts.ReasonLimitExceeded, copyErr)
		}
		return failedInput(copyErr)
	}
	if inputCloseErr != nil {
		return failedInput(inputCloseErr)
	}
	if stageCloseErr != nil {
		return failed(contracts.ReasonIO, stageCloseErr)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if actualHash != req.Source.SHA256 {
		return contracts.SourceResult{Failure: &contracts.Failure{Stage: contracts.StageSource, Reason: contracts.ReasonHashMismatch}}, nil
	}
	if err := os.Chmod(staged, 0400); err != nil {
		return failed(contracts.ReasonIO, err)
	}
	archive, err := os.Open(staged)
	if err != nil {
		return failed(contracts.ReasonIO, err)
	}
	modes, extractErr := extract(ctx, workspace, archive, req.Source.RootDir, lim)
	archiveCloseErr := archive.Close()
	if extractErr != nil {
		var run *contracts.RunError
		if errors.As(extractErr, &run) {
			return failed(run.Reason, run.Err)
		}
		return failed(contracts.ReasonIO, extractErr)
	}
	if archiveCloseErr != nil {
		return failed(contracts.ReasonIO, archiveCloseErr)
	}
	success = true
	return contracts.SourceResult{Source: contracts.PreparedSource{
		Archive:       contracts.StagedFile{Path: staged, SHA256: actualHash, Size: size},
		WorkspaceDir:  req.WorkspaceDir,
		IntendedModes: modes,
	}}, nil
}

func extract(ctx context.Context, workspace *os.Root, archive io.Reader, root string, lim limits) (map[string]uint32, error) {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return nil, decodeError(err)
	}
	defer gz.Close()
	// Bound the entire decompressed stream as well as file bytes. The allowance
	// covers headers, padding and extended metadata; it prevents tar.Next from
	// consuming an unbounded metadata or trailing-padding decompression bomb.
	stream := &tarStream{ctx: ctx, reader: gz, remaining: lim.extracted + int64(lim.entries)*1024 + 1024, headers: headerCounter{limit: lim.entries}}
	tr := tar.NewReader(stream)
	modes := make(map[string]uint32)
	seen := make(map[string]byte)
	requiredDirs := make(map[string]bool)
	var total int64
	count := 0
	for {
		before := stream.read
		stream.headers.next(before)
		h, err := tr.Next()
		if err == io.EOF {
			if stream.read-before < 1024 || !stream.zeroTail() {
				return nil, decodeError(errors.New("tar end markers are missing"))
			}
			if count == 0 {
				return nil, decodeError(errors.New("archive does not contain the declared root"))
			}
			break
		}
		if err != nil {
			return nil, decodeError(err)
		}
		count++
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return nil, decodeError(errors.New("archive contains links or special entries"))
		}
		name, err := memberPath(h.Name, root, h.Typeflag == tar.TypeDir)
		if err != nil {
			return nil, decodeError(err)
		}
		if _, exists := seen[name]; exists {
			return nil, decodeError(errors.New("duplicate archive path"))
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if seen[parent] == tar.TypeReg {
				return nil, decodeError(errors.New("archive file/directory collision"))
			}
			requiredDirs[parent] = true
		}
		if h.Typeflag == tar.TypeReg && requiredDirs[name] {
			return nil, decodeError(errors.New("archive file/directory collision"))
		}
		seen[name] = h.Typeflag
		if h.Typeflag == tar.TypeDir {
			if h.Size != 0 {
				return nil, decodeError(errors.New("directory has a body"))
			}
			if name != "" {
				if err := makeDirectories(workspace, name); err != nil {
					return nil, err
				}
			}
			continue
		}
		if h.Size < 0 || h.Size > lim.extracted-total {
			return nil, decodeError(errLimit)
		}
		if parent := path.Dir(name); parent != "." {
			if err := makeDirectories(workspace, parent); err != nil {
				return nil, err
			}
		}
		mode := uint32(h.Mode & 0777)
		f, err := workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(mode|0600))
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(os.FileMode(mode | 0600)); err != nil {
			f.Close()
			return nil, err
		}
		n, copyErr := io.Copy(f, tr)
		closeErr := f.Close()
		total += n
		if copyErr != nil {
			return nil, decodeError(copyErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if n != h.Size || total > lim.extracted {
			return nil, decodeError(errors.New("archive file body does not match its size"))
		}
		modes[name] = mode
	}
	// Complete gzip checksum validation and reject nonzero data after tar's end.
	buf := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buf)
		for _, value := range buf[:n] {
			if value != 0 {
				return nil, decodeError(errors.New("nonzero data after tar end"))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, decodeError(err)
		}
	}
	return modes, nil
}

// Explicit chmod after each creation preserves temporary owner access even if
// the caller's umask removes every permission bit. All names originate from
// validated archive paths inside the initially empty private workspace.
func makeDirectories(workspace *os.Root, name string) error {
	var prefix string
	for _, component := range strings.Split(name, "/") {
		prefix = path.Join(prefix, component)
		if err := workspace.Mkdir(prefix, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := workspace.Lstat(prefix)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("archive directory collides with a non-directory")
		}
		if err := workspace.Chmod(prefix, 0700); err != nil {
			return err
		}
	}
	return nil
}

func memberPath(name, root string, directory bool) (string, error) {
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if err := contracts.ValidateRelativePath(name); err != nil {
		return "", err
	}
	if name == root && directory {
		return "", nil
	}
	rel, ok := strings.CutPrefix(name, root+"/")
	if !ok {
		return "", errors.New("archive member is outside declared root")
	}
	if err := contracts.ValidateRelativePath(rel); err != nil {
		return "", err
	}
	return rel, nil
}

func copyBounded(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	var total int64
	buf := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		readBuf := buf
		if int64(len(readBuf)) > limit-total+1 {
			readBuf = readBuf[:limit-total+1]
		}
		n, err := src.Read(readBuf)
		if int64(n) > limit-total {
			return total, errLimit
		}
		if n != 0 {
			written, writeErr := dst.Write(readBuf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

type tarStream struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
	read      int64
	tail      [1024]byte
	headers   headerCounter
}

func (s *tarStream) Read(p []byte) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > s.remaining+1 {
		p = p[:s.remaining+1]
	}
	n, err := s.reader.Read(p)
	if int64(n) > s.remaining {
		return 0, errLimit
	}
	if headerErr := s.headers.observe(p[:n]); headerErr != nil {
		return 0, headerErr
	}
	s.remaining -= int64(n)
	s.read += int64(n)
	if n >= len(s.tail) {
		copy(s.tail[:], p[n-len(s.tail):n])
	} else {
		copy(s.tail[:], s.tail[n:])
		copy(s.tail[len(s.tail)-n:], p[:n])
	}
	return n, err
}

func (s *tarStream) zeroTail() bool {
	for _, value := range s.tail {
		if value != 0 {
			return false
		}
	}
	return true
}

func decodeError(err error) error {
	reason := contracts.ReasonUnsafeInput
	var pathErr *os.PathError
	if errors.Is(err, errLimit) {
		reason = contracts.ReasonLimitExceeded
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		reason = contracts.ReasonCancelled
	} else if errors.As(err, &pathErr) {
		reason = contracts.ReasonIO
	}
	return &contracts.RunError{Stage: contracts.StageSource, Reason: reason, Err: err}
}

func failedInput(err error) (contracts.SourceResult, error) {
	failure := contracts.FailureFromError(contracts.StageSource, err)
	return failed(failure.Reason, err)
}

func failed(reason contracts.Reason, err error) (contracts.SourceResult, error) {
	failure := &contracts.Failure{Stage: contracts.StageSource, Reason: reason}
	return contracts.SourceResult{Failure: failure}, &contracts.RunError{Stage: contracts.StageSource, Reason: reason, Err: fmt.Errorf("prepare source: %w", err)}
}
