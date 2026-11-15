//go:build linux

package publish

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

func setup(t *testing.T) (string, os.FileInfo, string) {
	t.Helper()
	base := t.TempDir()
	input := filepath.Join(base, "inputs")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return input, info, filepath.Join(base, "out")
}

func begin(t *testing.T, info os.FileInfo, output string) *Transaction {
	t.Helper()
	tx, err := Begin(context.Background(), info, output)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tx.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return tx
}

func reason(t *testing.T, err error, want contracts.Reason) {
	t.Helper()
	var run *contracts.RunError
	if !errors.As(err, &run) || run.Stage != contracts.StagePublication || run.Reason != want {
		t.Fatalf("error = %v, want publication/%s", err, want)
	}
}

func noTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".patchstack-") {
			t.Fatalf("temporary sibling retained: %s", entry.Name())
		}
	}
}

func TestPublishPrivatePackageAndRetainedCleanup(t *testing.T) {
	_, info, output := setup(t)
	tx := begin(t, info, output)
	if tx.OutputDir() != output || tx.Published() {
		t.Fatal("unexpected transaction state")
	}
	outerInfo, err := tx.outer.Stat()
	if err != nil || outerInfo.Mode().Perm() != 0700 {
		t.Fatalf("outer mode: %v %v", outerInfo, err)
	}
	if err := os.WriteFile(filepath.Join(tx.Dir(), "report.json"), []byte("complete\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tx.Dir(), "source"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination visible before publish: %v", err)
	}
	if err := tx.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tx.Published() {
		t.Fatal("successful publication state missing")
	}
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(output, "report.json"))
	if err != nil || string(got) != "complete\n" {
		t.Fatalf("published bytes: %q %v", got, err)
	}
	info, err = os.Stat(output)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("package mode: %v %v", info, err)
	}
	noTemps(t, filepath.Dir(output))
}

func TestPublishExistingDestinationNeverChanges(t *testing.T) {
	for _, kind := range []string{"directory", "file", "symlink", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			_, info, output := setup(t)
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(output, 0755)
			case "file":
				err = os.WriteFile(output, []byte("unchanged"), 0644)
			case "symlink":
				err = os.Symlink(filepath.Dir(output), output)
			case "dangling-symlink":
				err = os.Symlink("missing", output)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(output)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Begin(context.Background(), info, output)
			reason(t, err, contracts.ReasonOutputExists)
			after, err := os.Lstat(output)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("existing output changed: %v", err)
			}
			if kind == "file" {
				got, err := os.ReadFile(output)
				if err != nil || string(got) != "unchanged" {
					t.Fatalf("preexisting bytes changed: %q %v", got, err)
				}
			}
			noTemps(t, filepath.Dir(output))
		})
	}
}

func TestPublishCompetingTransactionsNoReplace(t *testing.T) {
	_, info, output := setup(t)
	first := begin(t, info, output)
	second := begin(t, info, output)
	for i, tx := range []*Transaction{first, second} {
		if err := os.WriteFile(filepath.Join(tx.Dir(), "winner"), []byte{byte('a' + i)}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i, tx := range []*Transaction{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = tx.Publish(context.Background())
		}()
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range results {
		if err == nil {
			if winner != -1 {
				t.Fatal("both competing publishers succeeded")
			}
			winner = i
		} else {
			reason(t, err, contracts.ReasonOutputExists)
		}
	}
	if winner == -1 {
		t.Fatalf("no winner: %v", results)
	}
	for _, tx := range []*Transaction{first, second} {
		if err := tx.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.Join(output, "winner"))
	if err != nil || string(got) != string(rune('a'+winner)) {
		t.Fatalf("winner overwritten: %q %v", got, err)
	}
	noTemps(t, filepath.Dir(output))
}

func TestPublishValidationDoesNotCreateTemporarySibling(t *testing.T) {
	input, info, output := setup(t)
	_, err := Begin(context.Background(), info, filepath.Join(filepath.Dir(output), "missing", "out"))
	reason(t, err, contracts.ReasonIO)
	_, err = Begin(context.Background(), info, filepath.Join(input, "out"))
	reason(t, err, contracts.ReasonUnsafeInput)
	// The retained input identity still applies after its pathname changes.
	moved := input + "-moved"
	if err := os.Rename(input, moved); err != nil {
		t.Fatal(err)
	}
	_, err = Begin(context.Background(), info, filepath.Join(moved, "out"))
	reason(t, err, contracts.ReasonUnsafeInput)
	alias := filepath.Join(filepath.Dir(output), "alias")
	if err := os.Symlink(moved, alias); err != nil {
		t.Fatal(err)
	}
	_, err = Begin(context.Background(), info, filepath.Join(alias, "out"))
	reason(t, err, contracts.ReasonUnsafeInput)
	noTemps(t, filepath.Dir(output))
	noTemps(t, moved)
}

func TestPublishReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("required read-only-parent check must run as an unprivileged user")
	}
	_, info, output := setup(t)
	parent := filepath.Join(filepath.Dir(output), "readonly")
	if err := os.Mkdir(parent, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0700) })
	_, err := Begin(context.Background(), info, filepath.Join(parent, "out"))
	reason(t, err, contracts.ReasonIO)
	noTemps(t, parent)
}

func TestPublishCancelAndInaccessibleCleanup(t *testing.T) {
	_, info, output := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Begin(ctx, info, output)
	reason(t, err, contracts.ReasonCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not wrapped: %v", err)
	}
	noTemps(t, filepath.Dir(output))
	tx := begin(t, info, output)
	dir := filepath.Join(tx.Dir(), "source")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("private"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	err = tx.Publish(ctx)
	reason(t, err, contracts.ReasonCancelled)
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled output exists: %v", err)
	}
	noTemps(t, filepath.Dir(output))
}

func TestPublishParentSwapRefusedAndWritesStayAnchored(t *testing.T) {
	input, info, output := setup(t)
	parent := filepath.Join(filepath.Dir(output), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	tx := begin(t, info, filepath.Join(parent, "out"))
	moved := parent + "-moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input, parent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.Dir(), "private"), []byte("anchored"), 0600); err != nil {
		t.Fatal(err)
	}
	err := tx.Publish(context.Background())
	reason(t, err, contracts.ReasonUnsafeInput)
	if tx.Published() {
		t.Fatal("parent swap published")
	}
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(input)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement redirected writes into inputs: %v %v", entries, err)
	}
	noTemps(t, moved)
	if _, err := os.Lstat(filepath.Join(moved, "out")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published in moved parent: %v", err)
	}
}

func TestPublishDirectoryReplacementRefused(t *testing.T) {
	_, info, output := setup(t)
	parent := filepath.Join(filepath.Dir(output), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	tx := begin(t, info, filepath.Join(parent, "out"))
	moved := parent + "-moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	reason(t, tx.Publish(context.Background()), contracts.ReasonUnsafeInput)
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	noTemps(t, moved)
	noTemps(t, parent)
}

func TestPublishHostileUmask(t *testing.T) {
	_, info, output := setup(t)
	previous := syscall.Umask(0777)
	defer syscall.Umask(previous)
	tx := begin(t, info, output)
	if err := os.WriteFile(filepath.Join(tx.Dir(), "file"), []byte("complete"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("published root mode under umask0777: %v %v", info, err)
	}
	noTemps(t, filepath.Dir(output))
}

func TestPublicationUnsupportedErrorsAreExplicit(t *testing.T) {
	for _, err := range []error{syscall.ENOSYS, syscall.EOPNOTSUPP, syscall.EINVAL} {
		reason(t, classify(err), contracts.ReasonUnsupportedPublication)
	}
}
