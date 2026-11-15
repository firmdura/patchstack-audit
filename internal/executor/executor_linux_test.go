//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/patchinput"
)

type fixtureInputs map[string][]byte

func (m fixtureInputs) OpenRegular(_ context.Context, name string) (io.ReadCloser, error) {
	data, ok := m[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (m fixtureInputs) ReadDir(context.Context, string) ([]contracts.InputEntry, error) {
	var result []contracts.InputEntry
	for name := range m {
		result = append(result, contracts.InputEntry{Name: strings.TrimPrefix(name, "patches/")})
	}
	return result, nil
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func realGNU(t *testing.T) string {
	t.Helper()
	name, err := exec.LookPath("patch")
	if err != nil {
		t.Fatalf("real GNU patch is required: %v", err)
	}
	resolved, err := ValidateTool(context.Background(), name)
	if err != nil {
		t.Fatalf("real GNU patch is required: %v", err)
	}
	return resolved
}

func fixture(t *testing.T, files map[string]string, patches ...string) (contracts.ExecuteRequest, fixtureInputs) {
	t.Helper()
	workspace := t.TempDir()
	modes := map[string]uint32{}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(workspace, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		modes[name] = 0644
	}
	inputs := fixtureInputs{}
	declarations := []contracts.Patch{}
	for i, data := range patches {
		name := fmt.Sprintf("%03d.patch", i)
		inputs["patches/"+name] = []byte(data)
		declarations = append(declarations, contracts.Patch{ID: name, File: name, SHA256: hashText(data), Upstream: "local:demonstration"})
	}
	prepared, err := (patchinput.Inventory{}).Prepare(context.Background(), contracts.PatchRequest{Inputs: inputs, PatchDir: "patches", Patches: declarations, StagingDir: t.TempDir()})
	if err != nil || prepared.Failure != nil {
		t.Fatalf("fixture patch preparation: %#v, %v", prepared, err)
	}
	return contracts.ExecuteRequest{Source: contracts.PreparedSource{WorkspaceDir: workspace, IntendedModes: modes}, Patches: prepared.Patches, PatchExecutable: realGNU(t)}, inputs
}

func modify(name, old, new string) string {
	return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-%s\n+%s\n", name, name, old, new)
}
func add(name, text string) string {
	return fmt.Sprintf("--- /dev/null\n+++ b/%s\n@@ -0,0 +1 @@\n+%s\n", name, text)
}
func remove(name, text string) string {
	return fmt.Sprintf("--- a/%s\n+++ /dev/null\n@@ -1 +0,0 @@\n-%s\n", name, text)
}

func assertFailure(t *testing.T, result contracts.ExecutionResult, err error, stage contracts.Stage, reason contracts.Reason, statuses ...contracts.PatchStatus) {
	t.Helper()
	if result.Failure == nil || *result.Failure != (contracts.Failure{Stage: stage, Reason: reason}) || result.FinalTreeSHA256 != "" || len(result.Files) != 0 {
		t.Fatalf("result=%#v err=%v; want %s/%s and no final evidence", result, err, stage, reason)
	}
	if len(result.Patches) != len(statuses) {
		t.Fatalf("patch statuses: %#v", result.Patches)
	}
	for i, want := range statuses {
		if result.Patches[i].Status != want {
			t.Fatalf("patch %d status=%s want %s", i, result.Patches[i].Status, want)
		}
	}
	if reason.Expected() {
		if err != nil {
			t.Fatalf("expected failure returned operational error: %v", err)
		}
	} else {
		var run *contracts.RunError
		if !errors.As(err, &run) || run.Stage != stage || run.Reason != reason {
			t.Fatalf("missing typed %s/%s: %v", stage, reason, err)
		}
	}
}
func emptyWorkspace(t *testing.T, workspace string) {
	t.Helper()
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed execution left partial contents %v, err %v", entries, err)
	}
}

func TestExecuteRealTwoPatchesRepeatable(t *testing.T) {
	var previous contracts.ExecutionResult
	for run := 0; run < 2; run++ {
		req, inputs := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "middle"), modify("file", "middle", "new"))
		before := map[string]string{}
		for name, data := range inputs {
			before[name] = hashText(string(data))
		}
		// Inherited variables must not change quoting, backups, POSIX behavior or
		// invoke a checkout helper. Production uses its own explicit environment.
		t.Setenv("POSIXLY_CORRECT", "1")
		t.Setenv("PATCH_GET", "1")
		t.Setenv("VERSION_CONTROL", "numbered")
		t.Setenv("QUOTING_STYLE", "shell-always")
		result, err := (Executor{}).Execute(context.Background(), req)
		if err != nil || result.Failure != nil || len(result.Files) != 1 || result.Diagnostics != "" {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		for _, patch := range result.Patches {
			if patch.Status != contracts.PatchApplied || patch.Reason != contracts.ReasonNone {
				t.Fatalf("patch %#v", patch)
			}
		}
		file := contracts.FileRecord{Path: "file", Mode: "0644", SHA256: hashText("new\n")}
		if result.Files[0] != file || result.FinalTreeSHA256 != hashText("file\x000644\x00"+file.SHA256+"\n") {
			t.Fatalf("incorrect canonical evidence: %#v", result)
		}
		actual, err := os.ReadFile(filepath.Join(req.Source.WorkspaceDir, "file"))
		if err != nil || string(actual) != "new\n" {
			t.Fatalf("patched content %q, %v", actual, err)
		}
		for name, data := range inputs {
			if before[name] != hashText(string(data)) {
				t.Fatal("original input changed")
			}
		}
		for _, patch := range req.Patches {
			data, err := os.ReadFile(patch.Input.Path)
			if err != nil || hashText(string(data)) != patch.Input.SHA256 {
				t.Fatal("verified staging changed")
			}
		}
		if run != 0 && !reflect.DeepEqual(previous, result) {
			t.Fatalf("reports differ across workspaces: %#v / %#v", previous, result)
		}
		previous = result
	}
}

func TestExecuteRealStrictFailures(t *testing.T) {
	for _, tc := range []struct{ name, initial, patch string }{
		{"offset", "padding\nold\n", modify("file", "old", "new")},
		{"fuzz only", "wrong-before\nold\nwrong-after\n", "--- a/file\n+++ b/file\n@@ -1,3 +1,3 @@\n before\n-old\n+new\n after\n"},
		{"already applied", "new\n", modify("file", "old", "new")},
		{"reversed", "old\n", modify("file", "new", "old")},
		{"partial hunk", "old\nline2\nline3\nlast\n", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n@@ -4 +4 @@\n-missing\n+LAST\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := fixture(t, map[string]string{"file": tc.initial}, tc.patch, add("must-not-run", "later"))
			outside := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := (Executor{}).Execute(context.Background(), req)
			assertFailure(t, result, err, contracts.StageExecution, contracts.ReasonPatchFailed, contracts.PatchFailed, contracts.PatchNotRun)
			if tc.name == "offset" && !strings.Contains(result.Diagnostics, "offset") {
				t.Fatalf("did not exercise real zero-exit offset: %q", result.Diagnostics)
			}
			emptyWorkspace(t, req.Source.WorkspaceDir)
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "untouched" {
				t.Fatal("outside file changed")
			}
		})
	}
}

func TestExecuteRealFirstPassSecondFailure(t *testing.T) {
	req, _ := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "middle"), modify("file", "absent", "new"), add("later", "should not run"))
	result, err := (Executor{}).Execute(context.Background(), req)
	assertFailure(t, result, err, contracts.StageExecution, contracts.ReasonPatchFailed, contracts.PatchApplied, contracts.PatchFailed, contracts.PatchNotRun)
	emptyWorkspace(t, req.Source.WorkspaceDir)
}

func TestExecuteRealAddDeleteAndModes(t *testing.T) {
	gitAdd := "diff --git a/nested/new b/nested/new\nnew file mode 100755\nindex 0000000..2222222\n" + add("nested/new", "created")
	req, _ := fixture(t, map[string]string{"file": "old\n", "unreadable": "known bytes\n"}, remove("file", "old"), gitAdd+add("file", "replacement"))
	req.Source.IntendedModes["file"] = 0755
	req.Source.IntendedModes["unreadable"] = 0000
	result, err := (Executor{}).Execute(context.Background(), req)
	if err != nil || result.Failure != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	want := []contracts.FileRecord{{Path: "file", Mode: "0644", SHA256: hashText("replacement\n")}, {Path: "nested/new", Mode: "0644", SHA256: hashText("created\n")}, {Path: "unreadable", Mode: "0000", SHA256: hashText("known bytes\n")}}
	if !reflect.DeepEqual(result.Files, want) {
		t.Fatalf("mode/content evidence=%#v want %#v", result.Files, want)
	}
	for _, file := range want {
		info, err := os.Stat(filepath.Join(req.Source.WorkspaceDir, file.Path))
		mode, _ := strconv.ParseUint(file.Mode, 8, 32)
		if err != nil || info.Mode().Perm() != os.FileMode(mode) {
			t.Fatalf("final file mode for %s: %v %v", file.Path, info, err)
		}
	}
	for _, name := range []string{".", "nested"} {
		info, err := os.Stat(filepath.Join(req.Source.WorkspaceDir, name))
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("directory mode: %v %v", info, err)
		}
	}
	if os.Geteuid() != 0 {
		if _, err := os.ReadFile(filepath.Join(req.Source.WorkspaceDir, "unreadable")); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("mode 0000 was not genuinely unreadable: %v", err)
		}
	}
	if req.Source.IntendedModes["file"] != 0755 {
		t.Fatal("caller mode map changed")
	}
}

func TestExecuteRealLiteralNamesAndNoNewline(t *testing.T) {
	name := "shell;dollar$paren()`tick`&.txt"
	patch := modify(name, "old", "new")
	patch = strings.ReplaceAll(patch, "-old\n+new\n", "-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n")
	req, _ := fixture(t, map[string]string{name: "old"}, patch)
	result, err := (Executor{}).Execute(context.Background(), req)
	if err != nil || result.Failure != nil || result.Files[0].SHA256 != hashText("new") {
		t.Fatalf("literal target: %#v %v", result, err)
	}
}

func TestExecuteEmptySeriesAndPreflight(t *testing.T) {
	t.Run("empty series", func(t *testing.T) {
		req, _ := fixture(t, map[string]string{"file": "bytes\n"})
		result, err := (Executor{}).Execute(context.Background(), req)
		if err != nil || result.Failure != nil || len(result.Patches) != 0 || result.FinalTreeSHA256 == "" {
			t.Fatalf("%#v %v", result, err)
		}
	})
	for _, name := range []string{"missing tool", "non GNU tool", "altered later stage", "unsafe target", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			req, _ := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "middle"), modify("file", "middle", "new"))
			ctx := context.Background()
			stage, reason := contracts.StageTool, contracts.ReasonToolUnavailable
			switch name {
			case "missing tool":
				req.PatchExecutable = filepath.Join(t.TempDir(), "missing")
			case "non GNU tool":
				req.PatchExecutable = fakeTool(t, "printf 'BSD patch 1.0\\n'\n", "")
				reason = contracts.ReasonUnsupportedTool
			case "altered later stage":
				if err := os.Chmod(req.Patches[1].Input.Path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(req.Patches[1].Input.Path, []byte("different bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				stage, reason = contracts.StageInventory, contracts.ReasonHashMismatch
			case "unsafe target":
				req.Patches[1].Targets[0].NewPath = "../outside"
				stage, reason = contracts.StageExecution, contracts.ReasonUnsafeInput
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				stage, reason = contracts.StageExecution, contracts.ReasonCancelled
			}
			result, err := (Executor{}).Execute(ctx, req)
			assertFailure(t, result, err, stage, reason, contracts.PatchNotRun, contracts.PatchNotRun)
			data, readErr := os.ReadFile(filepath.Join(req.Source.WorkspaceDir, "file"))
			if readErr != nil || string(data) != "old\n" {
				t.Fatal("preflight failure changed workspace")
			}
		})
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func fakeTool(t *testing.T, version, application string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "GNU patch ; literal $tool")
	text := "#!/bin/sh\nif [ \"$1\" = --version ]; then\n" + version + "exit 0\nfi\n" + application
	if err := os.WriteFile(name, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	return name
}

const fakeVersion = "printf 'GNU patch 2.7.6\\n'\n"

func TestExecuteTimeoutAndCombinedCaptureLimit(t *testing.T) {
	for _, name := range []string{"timeout", "combined output cap", "unexpected stdout", "unexpected stderr"} {
		t.Run(name, func(t *testing.T) {
			req, _ := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "new"), add("later", "no"))
			application := "sleep 60\n"
			reason := contracts.ReasonTimeout
			limits := policy{timeout: 100 * time.Millisecond, logBytes: 1024}
			switch name {
			case "combined output cap":
				application = "head -c 600 /dev/zero\nhead -c 600 /dev/zero >&2\nsleep 60\n"
				reason = contracts.ReasonLimitExceeded
				limits.timeout = 2 * time.Second
			case "unexpected stdout":
				application = "printf 'patching file file\\nHunk #1 succeeded at 1 (offset 1 line).\\n'\n"
				reason = contracts.ReasonPatchFailed
			case "unexpected stderr":
				application = "printf 'patching file file\\n'\nprintf 'unrecognized warning\\n' >&2\n"
				reason = contracts.ReasonPatchFailed
			}
			req.PatchExecutable = fakeTool(t, fakeVersion, application)
			started := time.Now()
			result, err := execute(context.Background(), req, limits)
			assertFailure(t, result, err, contracts.StageExecution, reason, contracts.PatchFailed, contracts.PatchNotRun)
			if time.Since(started) > 3*time.Second {
				t.Fatal("resource-limit failure did not terminate promptly")
			}
			if len(result.Diagnostics) > int(limits.logBytes) {
				t.Fatal("capture exceeded combined limit")
			}
			if name == "combined output cap" && len(result.Diagnostics) != int(limits.logBytes) {
				t.Fatalf("capture length=%d", len(result.Diagnostics))
			}
			emptyWorkspace(t, req.Source.WorkspaceDir)
		})
	}
}

func TestExecuteCancellationKillsProcessGroup(t *testing.T) {
	req, _ := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "new"), add("later", "no"))
	control := t.TempDir()
	childPath := filepath.Join(control, "child")
	parentPath := filepath.Join(control, "parent")
	application := "printf '%s\\n' \"$$\" > " + shellQuote(parentPath) + "\nsleep 60 &\nprintf '%s\\n' \"$!\" > " + shellQuote(childPath) + "\nwait\n"
	req.PatchExecutable = fakeTool(t, fakeVersion, application)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result contracts.ExecutionResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := (Executor{}).Execute(ctx, req); done <- outcome{result, err} }()
	child := waitPID(t, childPath)
	parent := waitPID(t, parentPath)
	cancel()
	select {
	case result := <-done:
		assertFailure(t, result.result, result.err, contracts.StageExecution, contracts.ReasonCancelled, contracts.PatchFailed, contracts.PatchNotRun)
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("cancel cause lost: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not return promptly")
	}
	for _, pid := range []int{child, parent} {
		assertNotRunning(t, pid)
	}
	emptyWorkspace(t, req.Source.WorkspaceDir)
}

func waitPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			value, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil && value > 1 {
				return value
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process fixture did not become ready: %s", path)
	return 0
}
func assertNotRunning(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		// A killed orphan may remain a zombie until the container's PID1 reaps
		// it; it cannot execute or hold workspace files/pipes. The direct child
		// is reaped by exec.Cmd.Wait before Execute returns.
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if bytes.Contains(data, []byte("State:\tZ")) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process %d remains alive after group cancellation", pid)
}

func TestExecuteLiteralArgvAndStopAfterFailure(t *testing.T) {
	req, _ := fixture(t, map[string]string{"file": "old\n"}, modify("file", "old", "new"), add("later", "no"))
	workspace := filepath.Join(t.TempDir(), "workspace ; dollar$() `literal`")
	if err := os.Rename(req.Source.WorkspaceDir, workspace); err != nil {
		t.Fatal(err)
	}
	req.Source.WorkspaceDir = workspace
	argsPath := filepath.Join(t.TempDir(), "argv")
	application := "printf '%s\\n' \"$@\" >> " + shellQuote(argsPath) + "\nprintf 'patching file file\\n'\nexit 1\n"
	req.PatchExecutable = fakeTool(t, fakeVersion, application)
	result, err := (Executor{}).Execute(context.Background(), req)
	assertFailure(t, result, err, contracts.StageExecution, contracts.ReasonPatchFailed, contracts.PatchFailed, contracts.PatchNotRun)
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"--batch", "--forward", "--fuzz=0", "--strip=1", "--no-backup-if-mismatch", "--get=0", "--quoting-style=literal", "--directory", workspace, ""}, "\n")
	if string(args) != want {
		t.Fatalf("argv was split, interpolated or repeated:\n%q\nwant%q", args, want)
	}
}

func TestExecuteHostileUmask(t *testing.T) {
	if os.Getenv("PATCHSTACK_EXECUTOR_UMASK_CHILD") == "1" {
		t.Fatal("parent test entered in child")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestExecuteHostileUmaskWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PATCHSTACK_EXECUTOR_UMASK_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated hostile umask: %v\n%s", err, output)
	}
}
func TestExecuteHostileUmaskWorker(t *testing.T) {
	if os.Getenv("PATCHSTACK_EXECUTOR_UMASK_CHILD") != "1" {
		return
	}
	req, _ := fixture(t, map[string]string{"file": "old\n"}, add("new/deep/file", "first"), modify("new/deep/file", "first", "second")+modify("file", "old", "new"))
	previous := syscall.Umask(0777)
	defer syscall.Umask(previous)
	result, err := (Executor{}).Execute(context.Background(), req)
	if err != nil || result.Failure != nil || len(result.Files) != 2 {
		t.Fatalf("hostile umask execution=%#v err=%v", result, err)
	}
	for _, name := range []string{"file", "new/deep/file"} {
		data, err := os.ReadFile(filepath.Join(req.Source.WorkspaceDir, name))
		if err != nil || len(data) == 0 {
			t.Fatalf("private access lost for %s: %v", name, err)
		}
	}
}

func TestCleanDiagnosticGrammar(t *testing.T) {
	targets := []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}, {NewPath: "new", Operation: contracts.OperationAdd}}
	good := []byte("patching file file\npatching file new\n")
	if !cleanDiagnostics(good, nil, targets) {
		t.Fatal("clean transcript rejected")
	}
	for _, bad := range []string{"", string(good) + "Hunk #1 succeeded at 1 (offset 1 line).\n", string(good) + "Hunk #1 succeeded at 1 with fuzz 1.\n", "patching file new\npatching file file\n", string(good) + "warning\n", strings.TrimSuffix(string(good), "\n")} {
		if cleanDiagnostics([]byte(bad), nil, targets) {
			t.Fatalf("unexpected transcript accepted: %q", bad)
		}
	}
	if cleanDiagnostics(good, []byte("warning"), targets) {
		t.Fatal("stderr accepted")
	}
}
