//go:build linux

package inputfs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFromDirectoryRetainsIdentityAndOwnership(t *testing.T) {
	base := t.TempDir()
	name := filepath.Join(base, "root")
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "file"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	want, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := FromDirectory(file)
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
	if err := os.WriteFile(filepath.Join(name, "file"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := root.Stat()
	if err != nil || !os.SameFile(info, want) {
		t.Fatalf("identity: %v %v", info, err)
	}
	reader, err := root.OpenRegular(context.Background(), "file")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || string(data) != "original" {
		t.Fatalf("retained content %q %v", data, err)
	}
	second, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	duplicate, err := FromDirectory(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Stat(); err != nil {
		t.Fatalf("caller descriptor closed: %v", err)
	}
}

func TestFromDirectoryInvalidAndConcurrentClose(t *testing.T) {
	if _, err := FromDirectory(nil); err == nil {
		t.Fatal("nil accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromDirectory(file); err == nil {
		t.Fatal("regular file accepted")
	}
	file.Close()
	if _, err := FromDirectory(file); err == nil {
		t.Fatal("closed accepted")
	}
	if _, err := (*Root)(nil).Stat(); err == nil {
		t.Fatal("nil stat accepted")
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want, err := dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			root, err := FromDirectory(dir)
			if err != nil {
				return
			}
			defer root.Close()
			info, err := root.Stat()
			if err != nil || !os.SameFile(info, want) {
				t.Errorf("concurrent duplicate wrong identity: %v", err)
			}
		}()
	}
	dir.Close()
	workers.Wait()
}
