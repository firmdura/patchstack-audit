package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

func TestRunDispatchAndOutputFailure(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "stack.yaml")
	if err := os.WriteFile(manifest, []byte("manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	r := contracts.Report{SchemaVersion: 1, Outcome: contracts.OutcomeReproduced, Stage: contracts.StageComplete, Reason: contracts.ReasonNone, Source: contracts.Source{Path: "source.tar.gz", SHA256: strings.Repeat("a", 64), RootDir: "demo"}, Patches: []contracts.PatchResult{}, FinalTreeSHA256: strings.Repeat("b", 64), DigestDefinition: contracts.DigestDefinition, Limitations: contracts.EvidenceLimitations}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "markdown"} {
		t.Run(format, func(t *testing.T) {
			called := false
			api := API{LoadManifest: func(io.Reader) (contracts.Manifest, error) { return contracts.Manifest{}, nil }, Audit: func(_ context.Context, _ contracts.Manifest, o contracts.Options) (contracts.Report, error) {
				called = true
				if o.InputRoot != "inputs" || o.OutputDir != "out" || o.PatchExecutable != "custom-patch" {
					t.Fatalf("options=%#v", o)
				}
				return r, nil
			}, WriteJSON: func(w io.Writer, _ contracts.Report) error { _, err := io.WriteString(w, "json"); return err }, WriteMarkdown: func(w io.Writer, _ contracts.Report) error { _, err := io.WriteString(w, "markdown"); return err }}
			args := []string{"audit", "--manifest", manifest, "--input-root", "inputs", "--output", "out", "--format", format, "--patch-executable", "custom-patch"}
			var out, diagnostics bytes.Buffer
			if code := Run(context.Background(), args, &out, &diagnostics, api); code != 0 || !called || out.String() != format || diagnostics.Len() != 0 {
				t.Fatalf("code=%d out=%s err=%s", code, out.String(), diagnostics.String())
			}
			if code := Run(context.Background(), args, errorWriter{}, &diagnostics, api); code != 2 || !strings.Contains(diagnostics.String(), "complete output retained at") {
				t.Fatalf("code=%d stderr=%s", code, diagnostics.String())
			}
		})
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("downstream write failed") }

func TestRunMalformedManifestAndUsageDoNotAudit(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "stack.yaml")
	if err := os.WriteFile(manifest, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	api := API{LoadManifest: func(io.Reader) (contracts.Manifest, error) {
		return contracts.Manifest{}, errors.New("invalid manifest")
	}, Audit: func(context.Context, contracts.Manifest, contracts.Options) (contracts.Report, error) {
		t.Fatal("audit called")
		return contracts.Report{}, nil
	}, WriteJSON: func(io.Writer, contracts.Report) error { t.Fatal("writer called"); return nil }, WriteMarkdown: func(io.Writer, contracts.Report) error { t.Fatal("writer called"); return nil }}
	for _, args := range [][]string{nil, {"audit", "--format", "unsupported"}, {"audit", "--manifest", manifest, "--input-root", "inputs", "--output", "out"}} {
		var out, diagnostics bytes.Buffer
		if code := Run(context.Background(), args, &out, &diagnostics, api); code != 2 || out.Len() != 0 || diagnostics.Len() == 0 {
			t.Fatalf("code=%d out=%s diagnostics=%s", code, out.String(), diagnostics.String())
		}
	}
}
