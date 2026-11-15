package patchinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

type memoryInputs struct {
	files           map[string][]byte
	entries         []contracts.InputEntry
	dirErr, openErr error
	reader          func([]byte) io.ReadCloser
	readDir         func(int) ([]contracts.InputEntry, error)
	dirReads, opens int
}

func (m *memoryInputs) OpenRegular(_ context.Context, path string) (io.ReadCloser, error) {
	m.opens++
	if m.openErr != nil {
		return nil, m.openErr
	}
	data, exists := m.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	if m.reader != nil {
		return m.reader(data), nil
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memoryInputs) ReadDir(_ context.Context, _ string) ([]contracts.InputEntry, error) {
	m.dirReads++
	if m.readDir != nil {
		return m.readDir(m.dirReads)
	}
	return m.entries, m.dirErr
}

func declaration(id, name, data string) contracts.Patch {
	hash := sha256.Sum256([]byte(data))
	return contracts.Patch{ID: id, File: name, SHA256: hex.EncodeToString(hash[:]), Upstream: "local:demonstration"}
}

func request(t *testing.T, data ...string) (contracts.PatchRequest, *memoryInputs) {
	t.Helper()
	inputs := &memoryInputs{files: map[string][]byte{}}
	req := contracts.PatchRequest{Inputs: inputs, PatchDir: "patches", StagingDir: t.TempDir()}
	for i, text := range data {
		name := string(rune('z'-i)) + ".patch"
		req.Patches = append(req.Patches, declaration(name, name, text))
		inputs.files["patches/"+name] = []byte(text)
		inputs.entries = append(inputs.entries, contracts.InputEntry{Name: name})
	}
	return req, inputs
}

func assertFailure(t *testing.T, result contracts.InventoryResult, err error, reason contracts.Reason) {
	t.Helper()
	if result.Failure == nil || result.Failure.Stage != contracts.StageInventory || result.Failure.Reason != reason || len(result.Patches) != 0 {
		t.Fatalf("result=%#v, err=%v; want no series and inventory/%s", result, err, reason)
	}
	if reason.Expected() {
		if err != nil {
			t.Fatalf("expected failure returned error: %v", err)
		}
	} else {
		var run *contracts.RunError
		if !errors.As(err, &run) || run.Stage != contracts.StageInventory || run.Reason != reason {
			t.Fatalf("operational failure missing typed error: %v", err)
		}
	}
}

func assertEmptyStage(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed preparation left stage entries %v, err=%v", entries, err)
	}
}

func TestPrepareVerifiedStagedOrderAndIdentity(t *testing.T) {
	req, inputs := request(t, modifyPatch, addPatch, deletePatch)
	before := make(map[string][]byte, len(inputs.files))
	for path, data := range inputs.files {
		before[path] = bytes.Clone(data)
	}
	result, err := (Inventory{}).Prepare(context.Background(), req)
	if err != nil || result.Failure != nil || len(result.Patches) != 3 || inputs.dirReads != 2 {
		t.Fatalf("result=%#v, err=%v, directory checks=%d", result, err, inputs.dirReads)
	}
	for i, staged := range result.Patches {
		want := req.Patches[i]
		if !reflect.DeepEqual(staged.Patch, want) || staged.Input.SHA256 != want.SHA256 || staged.Input.Size != int64(len(before["patches/"+want.File])) {
			t.Fatalf("staged identity/order differs: %#v", staged)
		}
		data, err := os.ReadFile(staged.Input.Path)
		if err != nil || !bytes.Equal(data, before["patches/"+want.File]) {
			t.Fatalf("staged bytes differ: %v", err)
		}
		fileInfo, err := os.Stat(staged.Input.Path)
		if err != nil || fileInfo.Mode().Perm() != 0400 {
			t.Fatalf("staged file is not private read-only: %v, %v", fileInfo, err)
		}
		dirInfo, err := os.Stat(filepath.Dir(staged.Input.Path))
		if err != nil || dirInfo.Mode().Perm() != 0700 {
			t.Fatalf("staging child is not private: %v, %v", dirInfo, err)
		}
		if len(staged.Targets) != 1 {
			t.Fatalf("missing parsed targets: %#v", staged.Targets)
		}
	}
	if !reflect.DeepEqual(inputs.files, before) {
		t.Fatal("original inputs changed")
	}
	inputs.files["patches/"+req.Patches[0].File][0] = '!'
	data, err := os.ReadFile(result.Patches[0].Input.Path)
	if err != nil || !bytes.Equal(data, before["patches/"+req.Patches[0].File]) {
		t.Fatal("later input mutation changed verified staged bytes")
	}
}

func TestPrepareEmptyInventory(t *testing.T) {
	req, inputs := request(t)
	result, err := (Inventory{}).Prepare(context.Background(), req)
	if err != nil || result.Failure != nil || len(result.Patches) != 0 || inputs.opens != 0 {
		t.Fatalf("empty inventory failed: %#v, %v", result, err)
	}
	assertEmptyStage(t, req.StagingDir)
}

func TestPrepareInventoryMismatch(t *testing.T) {
	for _, name := range []string{"missing", "extra", "hidden", "nested", "duplicate entry", "missing directory", "changed during read", "disappeared file"} {
		t.Run(name, func(t *testing.T) {
			req, inputs := request(t, modifyPatch)
			switch name {
			case "missing":
				inputs.entries = nil
			case "extra":
				inputs.entries = append(inputs.entries, contracts.InputEntry{Name: "extra.patch"})
			case "hidden":
				inputs.entries = append(inputs.entries, contracts.InputEntry{Name: ".hidden"})
			case "nested":
				inputs.entries[0].Directory = true
			case "duplicate entry":
				inputs.entries = []contracts.InputEntry{{Name: "duplicate"}}
			case "missing directory":
				inputs.dirErr = os.ErrNotExist
			case "changed during read":
				inputs.readDir = func(count int) ([]contracts.InputEntry, error) {
					if count == 1 {
						return inputs.entries, nil
					}
					return append(inputs.entries, contracts.InputEntry{Name: "unexpected"}), nil
				}
			case "disappeared file":
				inputs.openErr = os.ErrNotExist
			}
			result, err := (Inventory{}).Prepare(context.Background(), req)
			assertFailure(t, result, err, contracts.ReasonInventoryMismatch)
			assertEmptyStage(t, req.StagingDir)
		})
	}
}

func TestPrepareDuplicateAndInvalidDeclarations(t *testing.T) {
	for _, name := range []string{"id", "file", "hash", "hash syntax", "file traversal", "directory traversal", "too many", "empty id"} {
		t.Run(name, func(t *testing.T) {
			req, inputs := request(t, modifyPatch, addPatch)
			switch name {
			case "id":
				req.Patches[1].ID = req.Patches[0].ID
			case "file":
				req.Patches[1].File = req.Patches[0].File
			case "hash":
				req.Patches[1].SHA256 = req.Patches[0].SHA256
			case "hash syntax":
				req.Patches[0].SHA256 = "BAD"
			case "file traversal":
				req.Patches[0].File = "../file.patch"
			case "directory traversal":
				req.PatchDir = "../patches"
			case "too many":
				req.Patches = make([]contracts.Patch, contracts.MaxPatches+1)
			case "empty id":
				req.Patches[0].ID = " "
			}
			result, err := (Inventory{}).Prepare(context.Background(), req)
			assertFailure(t, result, err, contracts.ReasonInvalidManifest)
			if inputs.opens != 0 || inputs.dirReads != 0 {
				t.Fatal("invalid declarations opened inputs")
			}
			assertEmptyStage(t, req.StagingDir)
		})
	}
}

func TestPrepareHashMismatchAndLimit(t *testing.T) {
	t.Run("wrong declared hash", func(t *testing.T) {
		req, _ := request(t, modifyPatch)
		req.Patches[0].SHA256 = strings.Repeat("0", 64)
		result, err := (Inventory{}).Prepare(context.Background(), req)
		assertFailure(t, result, err, contracts.ReasonHashMismatch)
		assertEmptyStage(t, req.StagingDir)
	})
	t.Run("over byte limit", func(t *testing.T) {
		data := strings.Repeat("x", int(contracts.MaxPatchBytes)+1)
		req, _ := request(t, data)
		result, err := (Inventory{}).Prepare(context.Background(), req)
		assertFailure(t, result, err, contracts.ReasonLimitExceeded)
		assertEmptyStage(t, req.StagingDir)
	})
	t.Run("exact byte limit", func(t *testing.T) {
		prefix := "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+"
		data := prefix + strings.Repeat("x", int(contracts.MaxPatchBytes)-len(prefix)-1) + "\n"
		req, _ := request(t, data)
		result, err := (Inventory{}).Prepare(context.Background(), req)
		if err != nil || result.Failure != nil || len(result.Patches) != 1 || result.Patches[0].Input.Size != contracts.MaxPatchBytes {
			t.Fatalf("exact byte limit rejected: %#v, %v", result, err)
		}
	})
}

type failedReader struct{ closeErr error }

func (r failedReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (r failedReader) Close() error             { return r.closeErr }

type closeFailReader struct{ io.Reader }

func (closeFailReader) Close() error { return errors.New("close failed") }

type cancelReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r cancelReader) Read(b []byte) (int, error) { r.cancel(); return r.Reader.Read(b) }
func (cancelReader) Close() error                 { return nil }

func TestPrepareOperationalErrorsAndCancellation(t *testing.T) {
	for _, name := range []string{"nil input", "missing staging", "directory io", "open io", "unsafe reader", "read io", "close io", "cancelled", "cancel during read", "cancel during empty directory read", "final inventory unsafe"} {
		t.Run(name, func(t *testing.T) {
			req, inputs := request(t, modifyPatch)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := contracts.ReasonIO
			switch name {
			case "nil input":
				req.Inputs = nil
			case "missing staging":
				req.StagingDir = filepath.Join(req.StagingDir, "absent")
			case "directory io":
				inputs.dirErr = errors.New("directory read failed")
			case "open io":
				inputs.openErr = errors.New("open failed")
			case "unsafe reader":
				inputs.openErr = &contracts.InputError{Reason: contracts.ReasonUnsafeInput, Err: errors.New("symlink")}
				want = contracts.ReasonUnsafeInput
			case "read io":
				inputs.reader = func([]byte) io.ReadCloser { return failedReader{} }
			case "close io":
				inputs.reader = func(data []byte) io.ReadCloser { return closeFailReader{bytes.NewReader(data)} }
			case "cancelled":
				cancel()
				want = contracts.ReasonCancelled
			case "cancel during read":
				inputs.reader = func(data []byte) io.ReadCloser { return cancelReader{bytes.NewReader(data), cancel} }
				want = contracts.ReasonCancelled
			case "cancel during empty directory read":
				req.Patches = nil
				inputs.readDir = func(int) ([]contracts.InputEntry, error) { cancel(); return nil, nil }
				want = contracts.ReasonCancelled
			case "final inventory unsafe":
				inputs.readDir = func(count int) ([]contracts.InputEntry, error) {
					if count == 1 {
						return inputs.entries, nil
					}
					return nil, &contracts.InputError{Reason: contracts.ReasonUnsafeInput, Err: errors.New("introduced symlink")}
				}
				want = contracts.ReasonUnsafeInput
			}
			result, err := (Inventory{}).Prepare(ctx, req)
			assertFailure(t, result, err, want)
			if name != "missing staging" {
				assertEmptyStage(t, req.StagingDir)
			}
		})
	}
}

func TestPrepareRejectedSeriesCannotReachExecutor(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(modifyPatch, "b/file", "b/../../escape", 1),
		"old mode 100644\nnew mode 100755\n" + modifyPatch,
		modifyPatch + "unaccounted data\n",
	} {
		req, _ := request(t, addPatch, bad)
		called := false
		result, err := (Inventory{}).Prepare(context.Background(), req)
		if err == nil && result.Failure == nil {
			called = true // An executor is permitted only after complete preparation.
		}
		assertFailure(t, result, err, contracts.ReasonUnsafeInput)
		if called {
			t.Fatal("rejected series was accepted for execution")
		}
		assertEmptyStage(t, req.StagingDir)
	}
}
