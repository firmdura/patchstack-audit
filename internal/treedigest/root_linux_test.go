//go:build linux

package treedigest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeRootRetainsWorkspaceIdentity(t *testing.T) {
	base := t.TempDir()
	name := filepath.Join(base, "workspace")
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "file"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	wantFiles, wantDigest, err := Compute(context.Background(), name, map[string]uint32{"file": 0000})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(name, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "replacement"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	files, digest, err := ComputeRoot(context.Background(), root, map[string]uint32{"file": 0000})
	if err != nil || digest != wantDigest || len(files) != len(wantFiles) || files[0] != wantFiles[0] {
		t.Fatalf("retained digest=%s files=%v err=%v", digest, files, err)
	}
	if _, err := root.Stat("file"); err != nil {
		t.Fatalf("caller root closed: %v", err)
	}
	link := filepath.Join(base, "alias")
	if err := os.Symlink(filepath.Join(base, "moved"), link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Compute(context.Background(), link, nil); err == nil {
		t.Fatal("pathname Compute followed symlink")
	}
	if _, _, err := ComputeRoot(context.Background(), nil, nil); err == nil {
		t.Fatal("nil root accepted")
	}
	root.Close()
	if _, _, err := ComputeRoot(context.Background(), root, nil); err == nil {
		t.Fatal("closed root accepted")
	}
}
