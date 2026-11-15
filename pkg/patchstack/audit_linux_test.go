//go:build linux

package patchstack_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func auditHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func auditPatch(old, next string) string {
	return "--- a/file.c\n+++ b/file.c\n@@ -1 +1 @@\n-" + old + "\n+" + next + "\n"
}

type auditFixture struct {
	base, input string
	manifest    patchstack.Manifest
}

func newAuditFixture(t *testing.T, mode int64) auditFixture {
	t.Helper()
	f := auditFixture{base: t.TempDir()}
	f.input = filepath.Join(f.base, "inputs")
	auditMkdir(t, filepath.Join(f.input, "patches"), 0700)
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "demo/file.c", Mode: mode, Size: int64(len("old\n")), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("old\n")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	auditWrite(t, filepath.Join(f.input, "source.tar.gz"), data.Bytes(), 0600)
	f.manifest = patchstack.Manifest{SchemaVersion: 1, Source: patchstack.Source{Path: "source.tar.gz", SHA256: auditHash(data.Bytes()), RootDir: "demo"}, PatchDir: "patches", Patches: []patchstack.Patch{}}
	for i, p := range []string{auditPatch("old", "middle"), auditPatch("middle", "new")} {
		name := fmt.Sprintf("%04d.patch", i+1)
		auditWrite(t, filepath.Join(f.input, "patches", name), []byte(p), 0600)
		f.manifest.Patches = append(f.manifest.Patches, patchstack.Patch{ID: name, File: name, SHA256: auditHash([]byte(p)), Upstream: "local:demonstration"})
	}
	return f
}
func auditMkdir(t *testing.T, name string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(name, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}
func auditWrite(t *testing.T, name string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, data, mode); err != nil {
		t.Fatal(err)
	}
}
func (f auditFixture) options(output string) patchstack.Options {
	return patchstack.Options{InputRoot: f.input, OutputDir: filepath.Join(f.base, output), PatchExecutable: "patch"}
}
func (f auditFixture) saveManifest(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	fmt.Fprintf(&out, "schema_version: 1\nsource:\n  path: %q\n  sha256: %q\n  root_dir: %q\npatch_dir: %q\npatches:", f.manifest.Source.Path, f.manifest.Source.SHA256, f.manifest.Source.RootDir, f.manifest.PatchDir)
	if len(f.manifest.Patches) == 0 {
		out.WriteString(" []\n")
	} else {
		out.WriteByte('\n')
	}
	for _, p := range f.manifest.Patches {
		fmt.Fprintf(&out, "  - id: %q\n    file: %q\n    sha256: %q\n    upstream: %q\n", p.ID, p.File, p.SHA256, p.Upstream)
	}
	name := filepath.Join(f.input, "stack.yaml")
	auditWrite(t, name, []byte(out.String()), 0600)
	return name
}
func auditSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(dir, func(name string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.Type().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, name)
			result[rel] = auditHash(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func auditNoTemp(t *testing.T, base string) {
	t.Helper()
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".patchstack-") {
			t.Fatalf("temporary output remains: %s", e.Name())
		}
	}
}
func auditFailure(t *testing.T, r patchstack.Report, err error, reason patchstack.Reason) {
	t.Helper()
	if r.Validate() != nil || r.Outcome != patchstack.OutcomeFailed || r.Reason != reason || r.FinalTreeSHA256 != "" || len(r.Files) != 0 {
		t.Fatalf("invalid failure report: %#v; %v", r, err)
	}
	if reason.Expected() {
		if err != nil || r.ExitCode(err) != 1 {
			t.Fatalf("expected failure: %v", err)
		}
	} else {
		var run *patchstack.RunError
		if !errors.As(err, &run) || run.Reason != reason || r.ExitCode(err) != 2 {
			t.Fatalf("operational failure: %v", err)
		}
	}
}

func TestAuditRealRepeatableAndImmutable(t *testing.T) {
	f := newAuditFixture(t, 0640)
	before := auditSnapshot(t, f.input)
	var previous patchstack.Report
	for i, name := range []string{"out1", "out2"} {
		o := f.options(name)
		r, err := patchstack.Audit(context.Background(), f.manifest, o)
		if err != nil || r.ExitCode(err) != 0 {
			t.Fatalf("audit: %#v %v", r, err)
		}
		fileHash := auditHash([]byte("new\n"))
		want := auditHash([]byte("file.c\x000640\x00" + fileHash + "\n"))
		if r.FinalTreeSHA256 != want || len(r.Files) != 1 || r.Files[0].Mode != "0640" {
			t.Fatalf("digest: %#v", r)
		}
		data, err := os.ReadFile(filepath.Join(o.OutputDir, "source/file.c"))
		if err != nil || string(data) != "new\n" {
			t.Fatalf("source: %q %v", data, err)
		}
		var jsonReport, mdReport bytes.Buffer
		if err := patchstack.WriteJSON(&jsonReport, r); err != nil {
			t.Fatal(err)
		}
		if err := patchstack.WriteMarkdown(&mdReport, r); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string][]byte{"report.json": jsonReport.Bytes(), "report.md": mdReport.Bytes()} {
			data, err := os.ReadFile(filepath.Join(o.OutputDir, name))
			if err != nil || !bytes.Equal(data, want) {
				t.Fatalf("published report %s differs: %v", name, err)
			}
		}
		entries, _ := os.ReadDir(o.OutputDir)
		if len(entries) != 3 {
			t.Fatalf("unexpected published files: %v", entries)
		}
		if i > 0 && !reflect.DeepEqual(previous, r) {
			t.Fatal("reports differ")
		}
		previous = r
	}
	if !reflect.DeepEqual(before, auditSnapshot(t, f.input)) {
		t.Fatal("inputs changed")
	}
	auditNoTemp(t, f.base)
}

func TestAuditFailureAtomicity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason patchstack.Reason
		change func(*testing.T, *auditFixture, *patchstack.Options)
	}{
		{"hash", patchstack.ReasonHashMismatch, func(_ *testing.T, f *auditFixture, _ *patchstack.Options) {
			f.manifest.Source.SHA256 = strings.Repeat("a", 64)
		}},
		{"extra", patchstack.ReasonInventoryMismatch, func(t *testing.T, f *auditFixture, _ *patchstack.Options) {
			auditWrite(t, filepath.Join(f.input, "patches/extra.patch"), []byte("extra"), 0600)
		}},
		{"second", patchstack.ReasonPatchFailed, func(t *testing.T, f *auditFixture, _ *patchstack.Options) {
			data := []byte(auditPatch("wrong", "new"))
			auditWrite(t, filepath.Join(f.input, "patches/0002.patch"), data, 0600)
			f.manifest.Patches[1].SHA256 = auditHash(data)
		}},
		{"offset", patchstack.ReasonPatchFailed, func(t *testing.T, f *auditFixture, _ *patchstack.Options) {
			data := []byte(strings.Replace(auditPatch("old", "middle"), "@@ -1 +1 @@", "@@ -2 +2 @@", 1))
			auditWrite(t, filepath.Join(f.input, "patches/0001.patch"), data, 0600)
			f.manifest.Patches[0].SHA256 = auditHash(data)
		}},
		{"unsafe-diff", patchstack.ReasonUnsafeInput, func(t *testing.T, f *auditFixture, _ *patchstack.Options) {
			data := []byte(strings.ReplaceAll(auditPatch("old", "middle"), "file.c", "../../escape"))
			auditWrite(t, filepath.Join(f.input, "patches/0001.patch"), data, 0600)
			f.manifest.Patches[0].SHA256 = auditHash(data)
		}},
		{"existing", patchstack.ReasonOutputExists, func(t *testing.T, _ *auditFixture, o *patchstack.Options) {
			auditMkdir(t, o.OutputDir, 0755)
			auditWrite(t, filepath.Join(o.OutputDir, "keep"), []byte("untouched"), 0644)
		}},
		{"missing-parent", patchstack.ReasonIO, func(_ *testing.T, _ *auditFixture, o *patchstack.Options) {
			o.OutputDir = filepath.Join(o.OutputDir, "missing/out")
		}},
		{"inside-input", patchstack.ReasonUnsafeInput, func(_ *testing.T, f *auditFixture, o *patchstack.Options) {
			o.OutputDir = filepath.Join(f.input, "out")
		}},
		{"unavailable", patchstack.ReasonToolUnavailable, func(_ *testing.T, f *auditFixture, o *patchstack.Options) {
			o.PatchExecutable = filepath.Join(f.base, "missing-tool")
		}},
		{"readonly-parent", patchstack.ReasonIO, func(t *testing.T, f *auditFixture, o *patchstack.Options) {
			if os.Geteuid() == 0 {
				t.Fatal("unprivileged Linux acceptance required")
			}
			parent := filepath.Join(f.base, "readonly")
			auditMkdir(t, parent, 0555)
			t.Cleanup(func() { os.Chmod(parent, 0700) })
			o.OutputDir = filepath.Join(parent, "out")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t, 0644)
			o := f.options("out")
			tc.change(t, &f, &o)
			before := auditSnapshot(t, f.input)
			r, err := patchstack.Audit(context.Background(), f.manifest, o)
			auditFailure(t, r, err, tc.reason)
			if tc.name == "second" && (r.Patches[0].Status != patchstack.PatchApplied || r.Patches[1].Status != patchstack.PatchFailed) {
				t.Fatalf("statuses: %#v", r.Patches)
			}
			if tc.name == "existing" {
				data, err := os.ReadFile(filepath.Join(o.OutputDir, "keep"))
				if err != nil || string(data) != "untouched" {
					t.Fatal("existing output changed")
				}
			} else {
				if _, err := os.Lstat(o.OutputDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("partial output: %v", err)
				}
			}
			if !reflect.DeepEqual(before, auditSnapshot(t, f.input)) {
				t.Fatal("inputs changed")
			}
			auditNoTemp(t, f.base)
		})
	}
}

func TestAuditRevalidatesManifest(t *testing.T) {
	f := newAuditFixture(t, 0644)
	f.manifest.Patches[0].File = "../escape"
	r, err := patchstack.Audit(context.Background(), f.manifest, f.options("out"))
	var run *patchstack.RunError
	if !errors.As(err, &run) || run.Reason != patchstack.ReasonInvalidManifest || r.SchemaVersion != 0 {
		t.Fatalf("report=%#v err=%v", r, err)
	}
	auditNoTemp(t, f.base)
}

func TestAuditEmptySeriesAndUnsafeArchive(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(fmt.Sprint(unsafe), func(t *testing.T) {
			f := newAuditFixture(t, 0644)
			if unsafe {
				var data bytes.Buffer
				gz := gzip.NewWriter(&data)
				tw := tar.NewWriter(gz)
				if err := tw.WriteHeader(&tar.Header{Name: "demo/../../escape", Mode: 0644, Typeflag: tar.TypeReg, Size: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				if err := tw.Close(); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				auditWrite(t, filepath.Join(f.input, "source.tar.gz"), data.Bytes(), 0600)
				f.manifest.Source.SHA256 = auditHash(data.Bytes())
			} else {
				for _, p := range f.manifest.Patches {
					if err := os.Remove(filepath.Join(f.input, "patches", p.File)); err != nil {
						t.Fatal(err)
					}
				}
				f.manifest.Patches = nil
			}
			o := f.options("out")
			r, err := patchstack.Audit(context.Background(), f.manifest, o)
			if unsafe {
				auditFailure(t, r, err, patchstack.ReasonUnsafeInput)
				if _, err := os.Stat(filepath.Join(f.base, "escape")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("archive escaped")
				}
			} else {
				if r.ExitCode(err) != 0 || len(r.Patches) != 0 || r.Files[0].SHA256 != auditHash([]byte("old\n")) {
					t.Fatalf("empty series: %#v %v", r, err)
				}
			}
			auditNoTemp(t, f.base)
		})
	}
}

func TestAuditUnprivilegedFinal0000(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("real unprivileged Linux acceptance required")
	}
	f := newAuditFixture(t, 0)
	o := f.options("out")
	r, err := patchstack.Audit(context.Background(), f.manifest, o)
	if err != nil || r.ExitCode(err) != 0 {
		t.Fatalf("%#v %v", r, err)
	}
	name := filepath.Join(o.OutputDir, "source/file.c")
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if _, err := os.ReadFile(name); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("0000 readable: %v", err)
	}
	want := auditHash([]byte("file.c\x000000\x00" + auditHash([]byte("new\n")) + "\n"))
	if r.FinalTreeSHA256 != want || r.Files[0].Mode != "0000" {
		t.Fatalf("digest: %#v", r)
	}
}

func blockingAuditTool(t *testing.T, f auditFixture) (string, string) {
	t.Helper()
	tool, marker := filepath.Join(f.base, "slow-patch"), filepath.Join(f.base, "started")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'GNU patch 2.7.6\\n'; exit 0; fi\nprintf started > %q\nsleep 60\n", marker)
	auditWrite(t, tool, []byte(script), 0700)
	return tool, marker
}
func awaitAuditMarker(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("patch did not start")
}
func TestAuditCancellation(t *testing.T) {
	f := newAuditFixture(t, 0644)
	o := f.options("out")
	o.PatchExecutable, _ = blockingAuditTool(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		r patchstack.Report
		e error
	}
	done := make(chan result, 1)
	go func() { r, e := patchstack.Audit(ctx, f.manifest, o); done <- result{r, e} }()
	awaitAuditMarker(t, filepath.Join(f.base, "started"))
	cancel()
	select {
	case got := <-done:
		auditFailure(t, got.r, got.e, patchstack.ReasonCancelled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not stop execution")
	}
	if _, err := os.Lstat(o.OutputDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial output")
	}
	auditNoTemp(t, f.base)
}

func TestAuditCLISubprocess(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "patchstack")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "../../cmd/patchstack")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, data)
	}
	for _, tc := range []struct {
		name   string
		want   int
		reason patchstack.Reason
	}{{"success", 0, patchstack.ReasonNone}, {"hash", 1, patchstack.ReasonHashMismatch}, {"second", 1, patchstack.ReasonPatchFailed}, {"existing", 2, patchstack.ReasonOutputExists}, {"missing-parent", 2, patchstack.ReasonIO}, {"inside-input", 2, patchstack.ReasonUnsafeInput}, {"readonly-parent", 2, patchstack.ReasonIO}, {"invalid", 2, ""}, {"usage", 2, ""}, {"stdout", 2, ""}, {"interrupt", 2, patchstack.ReasonCancelled}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t, 0644)
			o := f.options("out")
			if tc.name == "hash" {
				f.manifest.Source.SHA256 = strings.Repeat("a", 64)
			}
			if tc.name == "second" {
				data := []byte(auditPatch("wrong", "new"))
				auditWrite(t, filepath.Join(f.input, "patches/0002.patch"), data, 0600)
				f.manifest.Patches[1].SHA256 = auditHash(data)
			}
			manifest := f.saveManifest(t)
			if tc.name == "invalid" {
				auditWrite(t, manifest, []byte("unknown: true\n"), 0600)
			}
			if tc.name == "existing" {
				auditMkdir(t, o.OutputDir, 0700)
				auditWrite(t, filepath.Join(o.OutputDir, "keep"), []byte("untouched"), 0600)
			}
			if tc.name == "missing-parent" {
				o.OutputDir = filepath.Join(f.base, "missing/out")
			}
			if tc.name == "inside-input" {
				o.OutputDir = filepath.Join(f.input, "out")
			}
			if tc.name == "readonly-parent" {
				parent := filepath.Join(f.base, "readonly")
				auditMkdir(t, parent, 0555)
				t.Cleanup(func() { os.Chmod(parent, 0700) })
				o.OutputDir = filepath.Join(parent, "out")
			}
			args := []string{"audit", "--manifest", manifest, "--input-root", f.input, "--output", o.OutputDir}
			var marker string
			if tc.name == "interrupt" {
				o.PatchExecutable, marker = blockingAuditTool(t, f)
				args = append(args, "--patch-executable", o.PatchExecutable)
			}
			if tc.name == "usage" {
				args = append(args, "--format", "bad")
			}
			cmd := exec.Command(bin, args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if tc.name == "stdout" {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				reader.Close()
				defer writer.Close()
				cmd.Stdout = writer
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if tc.name == "interrupt" {
				awaitAuditMarker(t, marker)
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			err := cmd.Wait()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.want {
				t.Fatalf("code=%d want%d stdout=%s stderr=%s", code, tc.want, stdout.String(), stderr.String())
			}
			if tc.reason != "" {
				var r patchstack.Report
				if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
					t.Fatalf("stdout report: %v %s", err, stdout.String())
				}
				if r.Validate() != nil || r.Reason != tc.reason {
					t.Fatalf("report=%#v", r)
				}
			} else if tc.name != "stdout" && stdout.Len() != 0 {
				t.Fatalf("invalid/usage emitted report: %s", stdout.String())
			}
			if tc.name == "stdout" {
				if !strings.Contains(stderr.String(), "complete output retained at") || !strings.Contains(stderr.String(), o.OutputDir) {
					t.Fatalf("retention diagnostic: %s", stderr.String())
				}
				for _, name := range []string{"source/file.c", "report.json", "report.md"} {
					if _, err := os.Stat(filepath.Join(o.OutputDir, name)); err != nil {
						t.Fatal(err)
					}
				}
			} else if tc.name != "success" && tc.name != "existing" {
				if _, err := os.Lstat(o.OutputDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("partial output: %v", err)
				}
			}
			if tc.name == "existing" {
				data, err := os.ReadFile(filepath.Join(o.OutputDir, "keep"))
				if err != nil || string(data) != "untouched" {
					t.Fatal("existing output changed")
				}
			}
			auditNoTemp(t, f.base)
		})
	}
}
