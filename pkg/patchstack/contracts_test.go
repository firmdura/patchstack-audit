package patchstack_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func completeReport(t *testing.T) patchstack.Report {
	t.Helper()
	m, err := patchstack.LoadManifest(strings.NewReader(validYAML(t)))
	if err != nil {
		t.Fatal(err)
	}
	r := patchstack.Report{SchemaVersion: patchstack.SchemaVersion, Outcome: patchstack.OutcomeReproduced, Stage: patchstack.StageComplete, Reason: patchstack.ReasonNone, Source: m.Source, DigestDefinition: patchstack.DigestDefinition, Limitations: patchstack.EvidenceLimitations, FinalTreeSHA256: strings.Repeat("d", 64)}
	for _, p := range m.Patches {
		r.Patches = append(r.Patches, patchstack.PatchResult{Patch: p, Status: patchstack.PatchApplied, Reason: patchstack.ReasonNone})
	}
	r.Files = []patchstack.FileRecord{{Path: "file.c", Mode: "0000", SHA256: strings.Repeat("e", 64)}}
	return r
}

func TestContractExitPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason patchstack.Reason
		stage  patchstack.Stage
		want   int
	}{
		{"integrity", patchstack.ReasonHashMismatch, patchstack.StageSource, 1},
		{"inventory", patchstack.ReasonInventoryMismatch, patchstack.StageInventory, 1},
		{"application", patchstack.ReasonPatchFailed, patchstack.StageExecution, 1},
		{"unsafe", patchstack.ReasonUnsafeInput, patchstack.StageSource, 2},
		{"limit", patchstack.ReasonLimitExceeded, patchstack.StageSource, 2},
		{"tool", patchstack.ReasonToolUnavailable, patchstack.StageTool, 2},
		{"timeout", patchstack.ReasonTimeout, patchstack.StageExecution, 2},
		{"cancel", patchstack.ReasonCancelled, patchstack.StageExecution, 2},
		{"io", patchstack.ReasonIO, patchstack.StagePublication, 2},
		{"output", patchstack.ReasonOutputExists, patchstack.StagePublication, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := completeReport(t)
			r.Outcome = patchstack.OutcomeFailed
			r.Stage = tc.stage
			r.Reason = tc.reason
			r.FinalTreeSHA256 = ""
			r.Files = nil
			for i := range r.Patches {
				r.Patches[i].Status = patchstack.PatchNotRun
			}
			if got := r.ExitCode(nil); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
			if got := r.ExitCode(errors.New("operational failure after earlier work")); got != 2 {
				t.Fatalf("operational failure lost: %d", got)
			}
		})
	}
	r := completeReport(t)
	if r.ExitCode(nil) != 0 {
		t.Fatal("complete report not successful")
	}
	if r.ExitCode(&patchstack.RunError{Stage: patchstack.StageOutput, Reason: patchstack.ReasonOutputWrite}) != 2 {
		t.Fatal("stdout failure lost after publication")
	}
	if (patchstack.Report{}).ExitCode(nil) != 2 || (patchstack.Report{Outcome: patchstack.OutcomeReproduced, Reason: patchstack.ReasonNone}).ExitCode(nil) != 2 {
		t.Fatal("incomplete report treated as success")
	}
}

func TestContractReportInvariants(t *testing.T) {
	mutations := map[string]func(*patchstack.Report){
		"schema":     func(r *patchstack.Report) { r.SchemaVersion = 0 },
		"no-digest":  func(r *patchstack.Report) { r.FinalTreeSHA256 = "" },
		"bad-digest": func(r *patchstack.Report) { r.FinalTreeSHA256 = "ABC" },
		"failure-digest": func(r *patchstack.Report) {
			r.Outcome = patchstack.OutcomeFailed
			r.Stage = patchstack.StageExecution
			r.Reason = patchstack.ReasonPatchFailed
		},
		"success-reason":  func(r *patchstack.Report) { r.Reason = patchstack.ReasonPatchFailed },
		"partial-success": func(r *patchstack.Report) { r.Patches[1].Status = patchstack.PatchNotRun },
		"failed-success": func(r *patchstack.Report) {
			r.Patches[1].Status = patchstack.PatchFailed
			r.Patches[1].Reason = patchstack.ReasonPatchFailed
		},
		"unknown-outcome":   func(r *patchstack.Report) { r.Outcome = "fixed" },
		"unknown-stage":     func(r *patchstack.Report) { r.Stage = "other" },
		"unknown-status":    func(r *patchstack.Report) { r.Patches[0].Status = "fixed" },
		"unknown-reason":    func(r *patchstack.Report) { r.Patches[0].Reason = "other" },
		"wrong-digest-spec": func(r *patchstack.Report) { r.DigestDefinition = "other algorithm" },
		"wrong-limitations": func(r *patchstack.Report) { r.Limitations = "verified compliant" },
		"absolute-file":     func(r *patchstack.Report) { r.Files[0].Path = "/private/file.c" },
		"privileged-mode":   func(r *patchstack.Report) { r.Files[0].Mode = "4000" },
		"short-mode":        func(r *patchstack.Report) { r.Files[0].Mode = "644" },
		"bad-file-hash":     func(r *patchstack.Report) { r.Files[0].SHA256 = "abc" },
		"duplicate-file":    func(r *patchstack.Report) { r.Files = append(r.Files, r.Files[0]) },
		"unsorted": func(r *patchstack.Report) {
			r.Files = append(r.Files, patchstack.FileRecord{Path: "a.c", Mode: "0644", SHA256: strings.Repeat("a", 64)})
		},
	}
	mutations["failed-after-not-run"] = func(r *patchstack.Report) {
		r.Outcome = patchstack.OutcomeFailed
		r.Stage = patchstack.StageExecution
		r.Reason = patchstack.ReasonPatchFailed
		r.FinalTreeSHA256 = ""
		r.Files = nil
		r.Patches[0].Status = patchstack.PatchNotRun
		r.Patches[1].Status = patchstack.PatchFailed
		r.Patches[1].Reason = patchstack.ReasonPatchFailed
	}
	mutations["all-privileged-bits"] = func(r *patchstack.Report) { r.Files[0].Mode = "7777" }
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := completeReport(t)
			mutate(&r)
			if r.Validate() == nil || r.ExitCode(nil) != 2 {
				t.Fatal("accepted contradictory report")
			}
		})
	}
	r := completeReport(t)
	r.Patches = nil
	r.Files = nil
	if r.Validate() != nil {
		t.Fatal("empty patch list/file inventory is permitted")
	}
	r = completeReport(t)
	r.Outcome = patchstack.OutcomeFailed
	r.Stage = patchstack.StageExecution
	r.Reason = patchstack.ReasonPatchFailed
	r.FinalTreeSHA256 = ""
	r.Files = nil
	r.Patches[1].Status = patchstack.PatchFailed
	r.Patches[1].Reason = patchstack.ReasonPatchFailed
	if r.Validate() != nil || r.ExitCode(nil) != 1 {
		t.Fatal("valid first-pass second-failure result rejected")
	}
}

func TestContractPublicAliases(t *testing.T) {
	// This package imports only the public facade. Public field composites and
	// methods compile without naming the internal canonical package.
	m := patchstack.Manifest{SchemaVersion: 1, Source: patchstack.Source{Path: "x.tar.gz", SHA256: strings.Repeat("0", 64), RootDir: "x"}, PatchDir: "patches"}
	if m.Validate() != nil {
		t.Fatal("public manifest method unavailable")
	}
	var err error = &patchstack.RunError{Stage: patchstack.StageSource, Reason: patchstack.ReasonIO, Err: errors.New("diagnostic")}
	var typed *patchstack.RunError
	if !errors.As(err, &typed) || typed.Unwrap() == nil {
		t.Fatal("public typed error unavailable")
	}
	if reflect.TypeOf(m).PkgPath() != "github.com/firmdura/patchstack-audit/internal/contracts" {
		t.Fatal("public models are copies, not aliases")
	}
	_ = patchstack.Options{InputRoot: "inputs", OutputDir: "out", PatchExecutable: "patch"}
}
