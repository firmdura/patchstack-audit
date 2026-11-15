//go:build linux

package patchinput

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/inputfs"
)

func filesystemRequest(t *testing.T) (contracts.PatchRequest, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "patches"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "patches", "fix.patch"), []byte(modifyPatch), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := inputfs.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inputs.Close() })
	return contracts.PatchRequest{
		Inputs: inputs, PatchDir: "patches", StagingDir: t.TempDir(),
		Patches: []contracts.Patch{declaration("fix", "fix.patch", modifyPatch)},
	}, root
}

func TestPrepareFilesystemIdentityAndImmutableInputs(t *testing.T) {
	req, root := filesystemRequest(t)
	path := filepath.Join(root, "patches", "fix.patch")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Read-only input directories are sufficient; staging is elsewhere.
	if err := os.Chmod(filepath.Join(root, "patches"), 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "patches"), 0700) })
	result, err := (Inventory{}).Prepare(context.Background(), req)
	if err != nil || result.Failure != nil || len(result.Patches) != 1 {
		t.Fatalf("real confined preparation failed: %#v, %v", result, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, []byte(modifyPatch)) {
		t.Fatalf("input bytes changed: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
		t.Fatalf("input identity/mode/mtime changed: %v", err)
	}
	stage, err := os.ReadFile(result.Patches[0].Input.Path)
	if err != nil || !bytes.Equal(stage, data) {
		t.Fatalf("staged bytes differ: %v", err)
	}
}

func TestPrepareFilesystemRejectsUnsafeAndIncompleteInventory(t *testing.T) {
	for _, name := range []string{"symlink file", "symlink parent", "symlink within root", "extra file", "hidden extra", "nested directory", "fifo", "missing file", "hash mismatch", "oversized file"} {
		t.Run(name, func(t *testing.T) {
			req, root := filesystemRequest(t)
			path := filepath.Join(root, "patches", "fix.patch")
			want := contracts.ReasonInventoryMismatch
			switch name {
			case "symlink file":
				outside := filepath.Join(t.TempDir(), "outside.patch")
				if err := os.WriteFile(outside, []byte(modifyPatch), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
				want = contracts.ReasonUnsafeInput
			case "symlink within root":
				target := filepath.Join(root, "original.patch")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../original.patch", path); err != nil {
					t.Fatal(err)
				}
				want = contracts.ReasonUnsafeInput
			case "symlink parent":
				if err := os.Symlink("patches", filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				req.PatchDir = "alias"
				want = contracts.ReasonUnsafeInput
			case "extra file", "hidden extra":
				extra := "extra.patch"
				if name == "hidden extra" {
					extra = ".hidden"
				}
				if err := os.WriteFile(filepath.Join(root, "patches", extra), []byte("unlisted"), 0600); err != nil {
					t.Fatal(err)
				}
			case "nested directory":
				if err := os.Mkdir(filepath.Join(root, "patches", "nested"), 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(root, "patches", "fifo"), 0600); err != nil {
					t.Fatal(err)
				}
				want = contracts.ReasonUnsafeInput
			case "missing file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "hash mismatch":
				if err := os.WriteFile(path, []byte("different bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				want = contracts.ReasonHashMismatch
			case "oversized file":
				if err := os.Truncate(path, contracts.MaxPatchBytes+1); err != nil {
					t.Fatal(err)
				}
				want = contracts.ReasonLimitExceeded
			}
			result, err := (Inventory{}).Prepare(context.Background(), req)
			assertFailure(t, result, err, want)
			assertEmptyStage(t, req.StagingDir)
		})
	}
}

func TestPrepareHostileUmask(t *testing.T) {
	const marker = "PATCHSTACK_PATCHINPUT_UMASK_CHILD"
	if os.Getenv(marker) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestPrepareHostileUmask$")
		cmd.Env = append(os.Environ(), marker+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated umask check failed: %v\n%s", err, output)
		}
		return
	}
	req, _ := filesystemRequest(t)
	previous := syscall.Umask(0777)
	defer syscall.Umask(previous)
	result, err := (Inventory{}).Prepare(context.Background(), req)
	if err != nil || result.Failure != nil || len(result.Patches) != 1 {
		t.Fatalf("umask 0777 blocked private owner access: %#v, %v", result, err)
	}
	path := result.Patches[0].Input.Path
	for path, mode := range map[string]os.FileMode{path: 0400, filepath.Dir(path): 0700} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("wrong private staging mode at %s: %v %v", path, info, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, []byte(modifyPatch)) {
		t.Fatalf("staged bytes unreadable under hostile umask: %v", err)
	}
}
