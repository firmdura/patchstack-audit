package patchstack_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func validYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/contracts/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestManifestValid(t *testing.T) {
	m, err := patchstack.LoadManifest(strings.NewReader(validYAML(t)))
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != 1 || m.Source.RootDir != "demo-1.0" || len(m.Patches) != 2 || m.Patches[0].Upstream != "local:demonstration" || m.Patches[1].ID != "second" {
		t.Fatalf("lost fields or ordering: %#v", m)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestStrictYAML(t *testing.T) {
	base := validYAML(t)
	cases := map[string]string{
		"empty": "", "not-map": "[1,2]", "null": "null", "syntax": "{",
		"unknown-root":          base + "surprise: true\n",
		"duplicate-root":        base + "patch_dir: other\n",
		"unknown-source":        strings.Replace(base, "  root_dir:", "  extra: value\n  root_dir:", 1),
		"duplicate-source":      strings.Replace(base, "  root_dir:", "  path: other.tar.gz\n  root_dir:", 1),
		"unknown-patch":         strings.Replace(base, "    file: first.patch", "    unknown: true\n    file: first.patch", 1),
		"duplicate-patch":       strings.Replace(base, "    file: first.patch", "    id: other\n    file: first.patch", 1),
		"source-alias":          strings.Replace(base, "source:\n", "source: &source\n", 1),
		"scalar-alias":          strings.Replace(base, "path: source.tar.gz", "path: &p source.tar.gz", 1),
		"actual-alias":          strings.Replace(base, "root_dir: demo-1.0", "root_dir: *missing", 1),
		"merge-key":             strings.Replace(base, "  root_dir:", "  <<: {path: other.tar.gz}\n  root_dir:", 1),
		"custom-tag":            strings.Replace(base, "patch_dir: patches", "patch_dir: !custom patches", 1),
		"multi-document":        base + "---\n{}\n",
		"empty-second-document": base + "---\n",
		"missing-source":        strings.Replace(base, "source:\n", "other:\n", 1),
		"missing-patches":       base[:strings.Index(base, "patches:\n")],
		"null-patches":          base[:strings.Index(base, "patches:\n")] + "patches: null\n",
		"null-cves":             strings.Replace(base, "cves: [CVE-2024-0001]", "cves: null", 1),
		"schema-string":         strings.Replace(base, "schema_version: 1", "schema_version: '1'", 1),
		"schema-float":          strings.Replace(base, "schema_version: 1", "schema_version: 1.0", 1),
		"schema-octal":          strings.Replace(base, "schema_version: 1", "schema_version: 01", 1),
		"numeric-id":            strings.Replace(base, "id: first", "id: 42", 1),
		"numeric-path":          strings.Replace(base, "path: source.tar.gz", "path: 42", 1),
		"numeric-cve":           strings.Replace(base, "CVE-2024-0001", "20240001", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := patchstack.LoadManifest(strings.NewReader(input))
			var run *patchstack.RunError
			if !errors.As(err, &run) || run.Reason != patchstack.ReasonInvalidManifest || m.SchemaVersion != 0 {
				t.Fatalf("expected zero manifest and typed invalid manifest, got %#v, %v", m, err)
			}
		})
	}
}

func TestManifestValidation(t *testing.T) {
	base := validYAML(t)
	cases := map[string]string{
		"unsupported-version": strings.Replace(base, "schema_version: 1", "schema_version: 2", 1),
		"uppercase-hash":      strings.Replace(base, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"short-hash":          strings.Replace(base, strings.Repeat("a", 64), "abc", 1),
		"invalid-hash":        strings.Replace(base, strings.Repeat("a", 64), strings.Repeat("g", 64), 1),
		"extension":           strings.Replace(base, "source.tar.gz", "source.tgz", 1),
		"cve-lowercase":       strings.Replace(base, "CVE-2024-0001", "cve-2024-0001", 1),
		"cve-short":           strings.Replace(base, "CVE-2024-0001", "CVE-2024-001", 1),
		"duplicate-id":        strings.Replace(base, "id: second", "id: first", 1),
		"duplicate-file":      strings.Replace(base, "file: second.patch", "file: first.patch", 1),
		"duplicate-hash":      strings.Replace(base, strings.Repeat("c", 64), strings.Repeat("b", 64), 1),
		"empty-id":            strings.Replace(base, "id: first", "id: ''", 1),
		"local-empty":         strings.Replace(base, "local:demonstration", "local:", 1),
		"local-whitespace":    strings.Replace(base, "local:demonstration", "'local:  '", 1),
		"http":                strings.Replace(base, "https://example.org", "http://example.org", 1),
		"https-no-host":       strings.Replace(base, "https://example.org/project/commit/abc", "https:///project", 1),
		"https-space":         strings.Replace(base, "https://example.org/project/commit/abc", "https://example.org/has space", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := patchstack.LoadManifest(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	for _, bad := range []string{"../x.tar.gz", "/x.tar.gz", "C:/x.tar.gz", "x/../s.tar.gz", "x//s.tar.gz", "./s.tar.gz", `x\s.tar.gz`, ""} {
		t.Run("source-path-"+bad, func(t *testing.T) {
			input := strings.Replace(base, "source.tar.gz", fmt.Sprintf("'%s'", bad), 1)
			if _, err := patchstack.LoadManifest(strings.NewReader(input)); err == nil {
				t.Fatal("accepted unsafe source path")
			}
		})
	}
	for _, field := range []string{"root_dir: demo-1.0", "file: first.patch"} {
		for _, bad := range []string{"..", ".", "a/b", "/absolute", `a\b`} {
			t.Run(field+bad, func(t *testing.T) {
				key, _, _ := strings.Cut(field, ":")
				input := strings.Replace(base, field, key+": '"+bad+"'", 1)
				if _, err := patchstack.LoadManifest(strings.NewReader(input)); err == nil {
					t.Fatal("accepted unsafe basename")
				}
			})
		}
	}
}

func TestManifestDirectValidationAndCounts(t *testing.T) {
	m, err := patchstack.LoadManifest(strings.NewReader(validYAML(t)))
	if err != nil {
		t.Fatal(err)
	}
	m.Patches = make([]patchstack.Patch, patchstack.MaxPatches)
	for i := range m.Patches {
		m.Patches[i] = patchstack.Patch{ID: fmt.Sprint(i), File: fmt.Sprintf("%d.patch", i), SHA256: fmt.Sprintf("%064x", i), Upstream: "local:test"}
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("maximum patch count: %v", err)
	}
	m.Patches = append(m.Patches, patchstack.Patch{})
	if m.Validate() == nil {
		t.Fatal("accepted excessive patch count")
	}
	m.Patches = nil
	if m.Validate() != nil {
		t.Fatal("zero patches are allowed")
	}
	m.Source.Path = "../mutated.tar.gz"
	if m.Validate() == nil {
		t.Fatal("direct/mutated manifest bypassed validation")
	}
}

func TestManifestLimitsAndReadErrors(t *testing.T) {
	base := validYAML(t)
	atLimit := base + "#" + strings.Repeat("x", int(patchstack.MaxManifestBytes)-len(base)-1)
	if _, err := patchstack.LoadManifest(strings.NewReader(atLimit)); err != nil {
		t.Fatalf("limit should be inclusive: %v", err)
	}
	reader := &countingReader{remaining: int(patchstack.MaxManifestBytes) * 2}
	if _, err := patchstack.LoadManifest(reader); err == nil {
		t.Fatal("accepted oversized manifest")
	}
	if reader.read != int(patchstack.MaxManifestBytes)+1 {
		t.Fatalf("unbounded read: %d", reader.read)
	}
	failure := errors.New("reader failed")
	_, err := patchstack.LoadManifest(errorReader{failure})
	var run *patchstack.RunError
	if !errors.As(err, &run) || run.Reason != patchstack.ReasonIO || !errors.Is(err, failure) {
		t.Fatalf("read error lost: %v", err)
	}
	if _, err := patchstack.LoadManifest(nil); err == nil {
		t.Fatal("accepted nil reader")
	}
}

type countingReader struct{ remaining, read int }

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestManifestNoFilesystemSideEffects(t *testing.T) {
	base := validYAML(t)
	dir := t.TempDir()
	t.Chdir(dir)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(base, "source.tar.gz", "missing/source.tar.gz", 1)
	m, err := patchstack.LoadManifest(bytes.NewBufferString(input))
	if err != nil {
		t.Fatal(err)
	}
	if m.Source.Path != "missing/source.tar.gz" {
		t.Fatal("path changed")
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("manifest loading created files")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatal("unexpected input access")
	}
}

func TestManifestYAMLPatchCount(t *testing.T) {
	base := validYAML(t)
	base = base[:strings.Index(base, "patches:\n")] + "patches:\n"
	var patches strings.Builder
	for i := 0; i <= patchstack.MaxPatches; i++ {
		fmt.Fprintf(&patches, "  - id: p%d\n    file: p%d.patch\n    sha256: '%064x'\n    upstream: local:count-test\n", i, i, i)
		if i == patchstack.MaxPatches-1 {
			if _, err := patchstack.LoadManifest(strings.NewReader(base + patches.String())); err != nil {
				t.Fatalf("maximum count rejected: %v", err)
			}
		}
	}
	if _, err := patchstack.LoadManifest(strings.NewReader(base + patches.String())); err == nil {
		t.Fatal("excessive YAML patch count accepted")
	}
}
