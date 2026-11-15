//go:build linux

package treedigest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

func TestCanonicalDigestIndependentRecomputation(t *testing.T) {
	root := t.TempDir()
	write(t, root, "z", "last", 0600)
	write(t, root, "a", "first", 0600)
	write(t, root, "é/file", "unicode", 0700)
	write(t, root, "new", "patch-created", 0777)
	must(t, os.Mkdir(filepath.Join(root, "empty"), 0700))
	modes := map[string]uint32{"a": 0000, "z": 0751, "é/file": 0400, "removed": 0644}
	files, digest, err := Compute(context.Background(), root, modes)
	must(t, err)
	wantFiles := []contracts.FileRecord{
		{Path: "a", Mode: "0000", SHA256: hash("first")},
		{Path: "new", Mode: "0644", SHA256: hash("patch-created")},
		{Path: "z", Mode: "0751", SHA256: hash("last")},
		{Path: "é/file", Mode: "0400", SHA256: hash("unicode")},
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Fatalf("files = %#v, want %#v", files, wantFiles)
	}
	// This deliberately constructs the documented bytes without calling any
	// production manifest/digest helper or using the returned record order.
	wantManifest := "a\x000000\x00" + hash("first") + "\n" +
		"new\x000644\x00" + hash("patch-created") + "\n" +
		"z\x000751\x00" + hash("last") + "\n" +
		"é/file\x000400\x00" + hash("unicode") + "\n"
	if digest != hash(wantManifest) {
		t.Fatalf("digest=%s, independent=%s", digest, hash(wantManifest))
	}
	// Compute must not restore final modes while files still need to be read.
	assertMode(t, filepath.Join(root, "a"), 0600)
	must(t, RestoreModes(context.Background(), root, files))
	for _, file := range files {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(file.Path)))
		must(t, err)
		if fmt.Sprintf("%04o", info.Mode().Perm()) != file.Mode {
			t.Fatalf("final mode %s = %o, want %s", file.Path, info.Mode().Perm(), file.Mode)
		}
	}
	assertMode(t, root, 0755)
	assertMode(t, filepath.Join(root, "empty"), 0755)
	assertMode(t, filepath.Join(root, "é"), 0755)
}

func TestDigestSensitivityAndMetadataExclusion(t *testing.T) {
	root := t.TempDir()
	write(t, root, "file", "content", 0600)
	compute := func(modes map[string]uint32) string {
		t.Helper()
		_, digest, err := Compute(context.Background(), root, modes)
		must(t, err)
		return digest
	}
	baseline := compute(map[string]uint32{"file": 0644})
	must(t, os.Mkdir(filepath.Join(root, "empty"), 0700))
	must(t, os.Chmod(filepath.Join(root, "file"), 0700))
	if got := compute(map[string]uint32{"file": 0644}); got != baseline {
		t.Fatal("temporary filesystem mode/empty directory entered digest")
	}
	if got := compute(map[string]uint32{"file": 0640}); got == baseline {
		t.Fatal("intended mode did not enter digest")
	}
	write(t, root, "file", "changed", 0600)
	if got := compute(map[string]uint32{"file": 0644}); got == baseline {
		t.Fatal("content did not enter digest")
	}
	write(t, root, "file", "content", 0600)
	must(t, os.Rename(filepath.Join(root, "file"), filepath.Join(root, "renamed")))
	if got := compute(nil); got == baseline {
		t.Fatal("path did not enter digest")
	}
}

func TestEmptyTreeDigest(t *testing.T) {
	root := t.TempDir()
	must(t, os.Mkdir(filepath.Join(root, "empty"), 0700))
	files, digest, err := Compute(context.Background(), root, nil)
	must(t, err)
	if len(files) != 0 || digest != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty inventory = %#v, %s", files, digest)
	}
}

func TestDigestRejectsUnsafeTreeAndModes(t *testing.T) {
	for _, kind := range []string{"file-link", "dir-link", "fifo", "invalid-path"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			write(t, outside, "file", "outside", 0600)
			switch kind {
			case "file-link":
				must(t, os.Symlink(filepath.Join(outside, "file"), filepath.Join(root, "link")))
			case "dir-link":
				must(t, os.Symlink(outside, filepath.Join(root, "link")))
			case "fifo":
				must(t, syscall.Mkfifo(filepath.Join(root, "fifo"), 0600))
			case "invalid-path":
				write(t, root, "bad\nname", "content", 0600)
			}
			files, digest, err := Compute(context.Background(), root, nil)
			assertReason(t, err, contracts.ReasonUnsafeInput)
			if files != nil || digest != "" {
				t.Fatal("unsafe tree exposed partial digest")
			}
		})
	}
	for name, modes := range map[string]map[string]uint32{
		"path": {"../outside": 0644},
		"mode": {"file": 04755},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Compute(context.Background(), t.TempDir(), modes)
			assertReason(t, err, contracts.ReasonUnsafeInput)
		})
	}
}

func TestDigestCancellationAndRestorationValidation(t *testing.T) {
	root := t.TempDir()
	write(t, root, "file", "content", 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Compute(ctx, root, nil)
	assertReason(t, err, contracts.ReasonCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel cause lost")
	}
	assertReason(t, RestoreModes(ctx, root, nil), contracts.ReasonCancelled)
	for _, files := range [][]contracts.FileRecord{
		{{Path: "../outside", Mode: "0644"}},
		{{Path: "file", Mode: "4755"}},
		{{Path: "file", Mode: "644"}},
		{{Path: "file", Mode: "0008"}},
		{{Path: "file", Mode: "0600"}, {Path: "file", Mode: "0600"}},
		nil,
	} {
		assertReason(t, RestoreModes(context.Background(), root, files), contracts.ReasonUnsafeInput)
	}
	_, _, err = Compute(context.Background(), filepath.Join(root, "missing"), nil)
	assertReason(t, err, contracts.ReasonIO)
}

func write(t *testing.T, root, name, body string, mode os.FileMode) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	must(t, os.MkdirAll(filepath.Dir(filename), 0700))
	must(t, os.WriteFile(filename, []byte(body), mode))
	// Existing writes must also update mode for the metadata sensitivity test.
	must(t, os.Chmod(filename, mode))
}

func hash(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func assertReason(t *testing.T, err error, reason contracts.Reason) {
	t.Helper()
	var run *contracts.RunError
	if !errors.As(err, &run) || run.Stage != contracts.StageDigest || run.Reason != reason {
		t.Fatalf("error = %v, want digest %s", err, reason)
	}
	if err != nil && strings.Contains(err.Error(), "<nil>") {
		t.Fatal("nil diagnostic cause")
	}
}

func assertMode(t *testing.T, name string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(name)
	must(t, err)
	if info.Mode().Perm() != want {
		t.Fatalf("mode %s = %04o, want %04o", name, info.Mode().Perm(), want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
