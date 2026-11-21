package patchstack_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func renderReport() patchstack.Report {
	return patchstack.Report{
		SchemaVersion: patchstack.SchemaVersion,
		Outcome:       patchstack.OutcomeReproduced,
		Stage:         patchstack.StageComplete,
		Reason:        patchstack.ReasonNone,
		Source:        patchstack.Source{Path: "demo.tar.gz", SHA256: strings.Repeat("a", 64), RootDir: "demo-1.0"},
		Patches: []patchstack.PatchResult{
			{Patch: patchstack.Patch{ID: "z-first", File: "0001-first.patch", SHA256: strings.Repeat("b", 64), Upstream: "local:demonstration", CVEs: []string{"CVE-2025-0001", "CVE-2024-10000"}}, Status: patchstack.PatchApplied, Reason: patchstack.ReasonNone},
			{Patch: patchstack.Patch{ID: "a-second", File: "0002-second.patch", SHA256: strings.Repeat("c", 64), Upstream: "https://example.org/commit/demo"}, Status: patchstack.PatchApplied, Reason: patchstack.ReasonNone},
		},
		FinalTreeSHA256: strings.Repeat("d", 64),
		Files: []patchstack.FileRecord{
			{Path: "main.c", Mode: "0000", SHA256: strings.Repeat("e", 64)},
			{Path: "nested/empty.txt", Mode: "0755", SHA256: strings.Repeat("f", 64)},
		},
		DigestDefinition: patchstack.DigestDefinition,
		Limitations:      patchstack.EvidenceLimitations,
	}
}

func failedRenderReport(stage patchstack.Stage, reason patchstack.Reason) patchstack.Report {
	r := renderReport()
	r.Outcome, r.Stage, r.Reason = patchstack.OutcomeFailed, stage, reason
	r.FinalTreeSHA256, r.Files = "", nil
	for i := range r.Patches {
		r.Patches[i].Status = patchstack.PatchNotRun
	}
	if stage == patchstack.StageExecution {
		r.Patches[0].Status = patchstack.PatchApplied
		r.Patches[1].Status, r.Patches[1].Reason = patchstack.PatchFailed, reason
	}
	return r
}

func renderCases() []struct {
	name   string
	report patchstack.Report
} {
	return []struct {
		name   string
		report patchstack.Report
	}{
		{"success", renderReport()},
		{"integrity-failure", failedRenderReport(patchstack.StageSource, patchstack.ReasonHashMismatch)},
		{"second-patch-failure", failedRenderReport(patchstack.StageExecution, patchstack.ReasonPatchFailed)},
		{"unsafe-input", failedRenderReport(patchstack.StageSource, patchstack.ReasonUnsafeInput)},
		{"timeout", failedRenderReport(patchstack.StageExecution, patchstack.ReasonTimeout)},
	}
}

func TestWriteGolden(t *testing.T) {
	for _, tc := range renderCases() {
		for _, format := range []struct {
			ext   string
			write func(io.Writer, patchstack.Report) error
		}{{"json", patchstack.WriteJSON}, {"md", patchstack.WriteMarkdown}} {
			t.Run(tc.name+"/"+format.ext, func(t *testing.T) {
				var got bytes.Buffer
				if err := format.write(&got, tc.report); err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "reports", tc.name+"."+format.ext))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("report differs from golden:\n%s", got.Bytes())
				}
				if !bytes.HasSuffix(got.Bytes(), []byte("\n")) || bytes.Contains(got.Bytes(), []byte("\r")) {
					t.Fatal("report is not LF-terminated text")
				}
				for _, forbidden := range []string{"/work/", "/Users/", "\"created_at\":", "\"timestamp\":", "verified secure", "CVE fixed", "is compliant"} {
					if strings.Contains(got.String(), forbidden) {
						t.Fatalf("unexpected report material %q", forbidden)
					}
				}
				if tc.report.Outcome == patchstack.OutcomeFailed {
					for _, forbidden := range []string{"final_tree_sha256", "Final source tree", strings.Repeat("d", 64), "\"files\""} {
						if strings.Contains(got.String(), forbidden) {
							t.Fatalf("failure contains final evidence %q", forbidden)
						}
					}
				}
			})
		}
	}
}

func TestWriteJSONIndependentDecoder(t *testing.T) {
	for _, tc := range renderCases() {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := patchstack.WriteJSON(&out, tc.report); err != nil {
				t.Fatal(err)
			}
			// Decode into a consumer-owned shape, without relying on the public
			// report type or its validation to interpret the evidence.
			var decoded struct {
				Schema int    `json:"schema_version"`
				State  string `json:"outcome"`
				Stage  string `json:"stage"`
				Reason string `json:"reason"`
				Source struct {
					Path   string `json:"path"`
					SHA256 string `json:"sha256"`
				} `json:"source"`
				Patches []struct {
					ID       string   `json:"id"`
					SHA256   string   `json:"sha256"`
					Upstream string   `json:"upstream"`
					CVEs     []string `json:"cves"`
					Status   string   `json:"status"`
					Reason   string   `json:"reason"`
				} `json:"patches"`
				Digest *string `json:"final_tree_sha256"`
			}
			decoder := json.NewDecoder(&out)
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if decoder.Decode(new(any)) != io.EOF {
				t.Fatal("more than one JSON value")
			}
			if decoded.Schema != 1 || decoded.State != string(tc.report.Outcome) || decoded.Stage != string(tc.report.Stage) || decoded.Reason != string(tc.report.Reason) || decoded.Source.SHA256 != tc.report.Source.SHA256 || decoded.Source.Path != tc.report.Source.Path || len(decoded.Patches) != len(tc.report.Patches) {
				t.Fatalf("lost report evidence: %+v", decoded)
			}
			for i, want := range tc.report.Patches {
				got := decoded.Patches[i]
				if got.ID != want.ID || got.SHA256 != want.SHA256 || got.Upstream != want.Upstream || !reflect.DeepEqual(got.CVEs, want.CVEs) || got.Status != string(want.Status) || got.Reason != string(want.Reason) {
					t.Fatalf("patch %d lost order, identity or outcome: %+v", i, got)
				}
			}
			if tc.report.Outcome == patchstack.OutcomeFailed && decoded.Digest != nil {
				t.Fatal("failure exposes a final digest")
			}
		})
	}
}

func TestWriteInvalidReportsWriteNothing(t *testing.T) {
	for name, mutate := range map[string]func(*patchstack.Report){
		"missing-schema":  func(r *patchstack.Report) { r.SchemaVersion = 0 },
		"false-verdict":   func(r *patchstack.Report) { r.Limitations = "This source is secure and compliant." },
		"false-outcome":   func(r *patchstack.Report) { r.Outcome = "fixed" },
		"partial-success": func(r *patchstack.Report) { r.Patches[1].Status = patchstack.PatchNotRun },
		"absolute-path":   func(r *patchstack.Report) { r.Files[0].Path = "/tmp/machine/source.c" },
		"unsorted-files":  func(r *patchstack.Report) { r.Files[0], r.Files[1] = r.Files[1], r.Files[0] },
		"failed-with-digest": func(r *patchstack.Report) {
			r.Outcome, r.Stage, r.Reason = patchstack.OutcomeFailed, patchstack.StageExecution, patchstack.ReasonPatchFailed
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, write := range []func(io.Writer, patchstack.Report) error{patchstack.WriteJSON, patchstack.WriteMarkdown} {
				r := renderReport()
				mutate(&r)
				var out bytes.Buffer
				if err := write(&out, r); err == nil || out.Len() != 0 {
					t.Fatalf("invalid report produced evidence: error=%v output=%q", err, &out)
				}
			}
		})
	}
}

type reportErrorWriter struct {
	err error
}

func (w reportErrorWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

func TestWriteErrors(t *testing.T) {
	sentinel := errors.New("downstream closed")
	for _, write := range []func(io.Writer, patchstack.Report) error{patchstack.WriteJSON, patchstack.WriteMarkdown} {
		for _, tc := range []struct {
			writer io.Writer
			want   error
		}{{reportErrorWriter{err: sentinel}, sentinel}, {reportErrorWriter{}, io.ErrShortWrite}, {nil, nil}} {
			err := write(tc.writer, renderReport())
			var run *patchstack.RunError
			if err == nil || !errors.As(err, &run) || run.Stage != patchstack.StageOutput || run.Reason != patchstack.ReasonOutputWrite || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("write error lost: %v", err)
			}
		}
	}
}

func TestWriteMarkdownEscape(t *testing.T) {
	r := renderReport()
	r.Source.Path, r.Source.RootDir = "源[1]&.tar.gz", "源<root>"
	r.Patches[0].ID = "修正<script>alert(1)</script>\n# forged | [click](https://bad.invalid) &lt; &#124; `code` \\ \x1b[2J"
	r.Patches[0].File = "[first]&.patch"
	r.Patches[0].Upstream = "local:<img src=x onerror=alert(1)>\r\n| forged |\t\u2028\u202e"
	r.Files[0].Path = "[main]&.c"
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := patchstack.WriteMarkdown(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"<script>", "<img", "\n# forged", "| forged |", "[click]", "https://bad.invalid", "&lt;", "`code`", "\x1b", "\r", "\t", "\u2028", "\u202e"} {
		if strings.Contains(out.String(), raw) {
			t.Fatalf("unescaped supplied Markdown text %q", raw)
		}
	}
	for _, escaped := range []string{"修正&#60;script&#62;", "&#10;&#35; forged &#124;", "&#38;lt&#59;", "&#38;&#35;124&#59;", "&#27;&#91;2J", "&#13;&#10;&#124; forged &#124;&#9;&#8232;&#8238;", "源&#91;1&#93;&#38;&#46;tar&#46;gz", "&#91;main&#93;&#38;&#46;c"} {
		if !strings.Contains(out.String(), escaped) {
			t.Fatalf("missing escaped text %q", escaped)
		}
	}
	if strings.Count(out.String(), "\n| 1 | ") != 1 || strings.Count(out.String(), "\n| 2 | ") != 1 {
		t.Fatal("supplied text changed table structure")
	}
	// JSON independently retains the exact supplied text, including controls.
	var encoded bytes.Buffer
	if err := patchstack.WriteJSON(&encoded, r); err != nil {
		t.Fatal(err)
	}
	var recovered patchstack.Report
	if err := json.Unmarshal(encoded.Bytes(), &recovered); err != nil || !reflect.DeepEqual(recovered, r) {
		t.Fatalf("JSON changed supplied evidence: %v", err)
	}
}

func TestWriteDeterministicAndUnchanged(t *testing.T) {
	for _, tc := range renderCases() {
		before, err := json.Marshal(tc.report)
		if err != nil {
			t.Fatal(err)
		}
		for _, write := range []func(io.Writer, patchstack.Report) error{patchstack.WriteJSON, patchstack.WriteMarkdown} {
			var first bytes.Buffer
			if err := write(&first, tc.report); err != nil {
				t.Fatal(err)
			}
			for range 4 {
				var again bytes.Buffer
				if err := write(&again, tc.report); err != nil || !bytes.Equal(first.Bytes(), again.Bytes()) {
					t.Fatalf("nondeterministic report: %v", err)
				}
			}
		}
		after, err := json.Marshal(tc.report)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rendering modified caller-owned report")
		}
	}
}

func TestWriteEmptyCollections(t *testing.T) {
	r := renderReport()
	r.Patches, r.Files = nil, nil
	var out bytes.Buffer
	if err := patchstack.WriteMarkdown(&out, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No patches declared.") || !strings.Contains(out.String(), "No regular files.") || !strings.Contains(out.String(), r.FinalTreeSHA256) {
		t.Fatal("empty series lost its complete source evidence")
	}
}

func TestWriteMarkdownCountsUnrunPatchesAfterFailure(t *testing.T) {
	r := failedRenderReport(patchstack.StageExecution, patchstack.ReasonPatchFailed)
	r.Patches = append(r.Patches, patchstack.PatchResult{
		Patch:  patchstack.Patch{ID: "third", File: "third.patch", SHA256: strings.Repeat("d", 64), Upstream: "local:demo"},
		Status: patchstack.PatchNotRun,
		Reason: patchstack.ReasonNone,
	})
	var out bytes.Buffer
	if err := patchstack.WriteMarkdown(&out, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 applied, 1 failed, 1 not run.") {
		t.Fatalf("missing patch counts:\n%s", &out)
	}
}
