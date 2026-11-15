// Package fixtures generates repeatable inputs for the local two-patch example.
// The C source and two patches are Apache-2.0 examples, not security repairs.
package fixtures

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed source/demo-1.0/main.c patches/*.patch
var files embed.FS

// Generate creates output as a new directory containing stack.yaml, source.tar.gz
// and patches/. Its parent must already exist, and output must not exist.
// Archive entry names, order, permissions, ownership and timestamps are fixed,
// so the same embedded fixtures produce identical archive and manifest bytes.
func Generate(output string) (retErr error) {
	if output == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.Mkdir(output, 0755); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("generate example inputs: %w", retErr)
			if err := os.RemoveAll(output); err != nil {
				retErr = fmt.Errorf("%w; could not remove generated files: %v", retErr, err)
			}
		}
	}()
	if err := os.Mkdir(filepath.Join(output, "patches"), 0755); err != nil {
		return err
	}
	source, err := files.ReadFile("source/demo-1.0/main.c")
	if err != nil {
		return err
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, header := range []*tar.Header{
		{Name: "demo-1.0/", Typeflag: tar.TypeDir, Mode: 0755, Format: tar.FormatUSTAR},
		{Name: "demo-1.0/main.c", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(source)), Format: tar.FormatUSTAR},
	} {
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write(source); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "source.tar.gz"), archive.Bytes(), 0644); err != nil {
		return err
	}
	names := []string{"0001-add.patch", "0002-label.patch"}
	patches := make([][]byte, len(names))
	for i, name := range names {
		patches[i], err = files.ReadFile("patches/" + name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, "patches", name), patches[i], 0644); err != nil {
			return err
		}
	}
	manifest := fmt.Sprintf("schema_version: 1\nsource:\n  path: source.tar.gz\n  sha256: '%x'\n  root_dir: demo-1.0\npatch_dir: patches\npatches:\n  - id: add\n    file: %s\n    sha256: '%x'\n    upstream: local:demonstration\n  - id: label\n    file: %s\n    sha256: '%x'\n    upstream: local:demonstration\n", sha256.Sum256(archive.Bytes()), names[0], sha256.Sum256(patches[0]), names[1], sha256.Sum256(patches[1]))
	return os.WriteFile(filepath.Join(output, "stack.yaml"), []byte(manifest), 0644)
}
