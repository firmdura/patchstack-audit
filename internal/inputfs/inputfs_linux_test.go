//go:build linux

package inputfs

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"
	unsafeptr "unsafe"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

func TestRetainedRootAndCompleteInventory(t *testing.T) {
	base := t.TempDir()
	rootPath := filepath.Join(base, "inputs")
	must(t, os.MkdirAll(filepath.Join(rootPath, "patches", "nested"), 0700))
	must(t, os.WriteFile(filepath.Join(rootPath, "patches", ".hidden"), []byte("frozen"), 0400))
	r, err := Open(rootPath)
	must(t, err)
	defer r.Close()
	must(t, os.Rename(rootPath, rootPath+"-original"))
	must(t, os.MkdirAll(filepath.Join(rootPath, "patches"), 0700))
	must(t, os.WriteFile(filepath.Join(rootPath, "patches", ".hidden"), []byte("replacement"), 0600))
	entries, err := r.ReadDir(context.Background(), "patches")
	must(t, err)
	want := []contracts.InputEntry{{Name: ".hidden"}, {Name: "nested", Directory: true}}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("inventory = %#v, want %#v", entries, want)
	}
	f, err := r.OpenRegular(context.Background(), "patches/.hidden")
	must(t, err)
	data, err := io.ReadAll(f)
	must(t, err)
	must(t, f.Close())
	if string(data) != "frozen" {
		t.Fatalf("root was redirected: %q", data)
	}
}

func TestUnsafeInputs(t *testing.T) {
	rootPath := t.TempDir()
	must(t, os.Mkdir(filepath.Join(rootPath, "dir"), 0700))
	must(t, os.WriteFile(filepath.Join(rootPath, "dir", "regular"), []byte("safe"), 0600))
	must(t, os.Symlink("dir", filepath.Join(rootPath, "linkdir")))
	must(t, os.Symlink("dir/regular", filepath.Join(rootPath, "linkfile")))
	must(t, syscall.Mkfifo(filepath.Join(rootPath, "fifo"), 0600))
	listener, err := net.Listen("unix", filepath.Join(rootPath, "socket"))
	must(t, err)
	defer listener.Close()
	r, err := Open(rootPath)
	must(t, err)
	defer r.Close()
	for _, name := range []string{"linkdir/regular", "linkfile", "dir", "fifo", "socket", "../outside", "/etc/passwd", "dir//regular", "dir/./regular", "dir\\regular"} {
		t.Run(name, func(t *testing.T) {
			f, err := r.OpenRegular(context.Background(), name)
			if f != nil {
				f.Close()
			}
			assertReason(t, err, contracts.ReasonUnsafeInput)
		})
	}
	_, err = r.ReadDir(context.Background(), "linkdir")
	assertReason(t, err, contracts.ReasonUnsafeInput)
	// Every disallowed entry must fail inventory, even if it is hidden.
	for _, kind := range []string{"symlink", "fifo", "socket"} {
		t.Run("inventory-"+kind, func(t *testing.T) {
			dir := filepath.Join(rootPath, "inventory-"+kind)
			must(t, os.Mkdir(dir, 0700))
			name := filepath.Join(dir, ".entry")
			switch kind {
			case "symlink":
				must(t, os.Symlink("../dir/regular", name))
			case "fifo":
				must(t, syscall.Mkfifo(name, 0600))
			case "socket":
				l, err := net.Listen("unix", name)
				must(t, err)
				defer l.Close()
			}
			_, err := r.ReadDir(context.Background(), "inventory-"+kind)
			assertReason(t, err, contracts.ReasonUnsafeInput)
		})
	}
	_, err = Open(filepath.Join(rootPath, "linkdir"))
	assertReason(t, err, contracts.ReasonUnsafeInput)
	_, err = Open(filepath.Join(rootPath, "linkdir", "child"))
	assertReason(t, err, contracts.ReasonUnsafeInput)
}

func TestCancellationAndIOClassification(t *testing.T) {
	rootPath := t.TempDir()
	must(t, os.WriteFile(filepath.Join(rootPath, "file"), []byte("safe"), 0600))
	must(t, os.Mkdir(filepath.Join(rootPath, "dir"), 0700))
	r, err := Open(rootPath)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	f, err := r.OpenRegular(ctx, "file")
	must(t, err)
	cancel()
	_, err = f.Read(make([]byte, 4))
	assertReason(t, err, contracts.ReasonCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel cause was lost")
	}
	must(t, f.Close())
	_, err = r.OpenRegular(ctx, "file")
	assertReason(t, err, contracts.ReasonCancelled)
	_, err = r.ReadDir(ctx, "dir")
	assertReason(t, err, contracts.ReasonCancelled)
	_, err = r.OpenRegular(context.Background(), "missing")
	assertReason(t, err, contracts.ReasonIO)
	must(t, r.Close())
	_, err = r.OpenRegular(context.Background(), "file")
	assertReason(t, err, contracts.ReasonIO)
}

func TestConcurrentSymlinkReplacementNeverReadsOutside(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	must(t, os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0600))
	must(t, os.Mkdir(filepath.Join(rootPath, "dir"), 0700))
	must(t, os.WriteFile(filepath.Join(rootPath, "dir", "file"), []byte("inside"), 0600))
	r, err := Open(rootPath)
	must(t, err)
	defer r.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(filepath.Join(rootPath, "dir"), filepath.Join(rootPath, "held")) == nil {
				os.Symlink(outside, filepath.Join(rootPath, "dir"))
				os.Remove(filepath.Join(rootPath, "dir"))
				os.Rename(filepath.Join(rootPath, "held"), filepath.Join(rootPath, "dir"))
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	for i := 0; i < 1000; i++ {
		f, err := r.OpenRegular(context.Background(), "dir/file")
		if err != nil {
			var input *contracts.InputError
			if !errors.As(err, &input) {
				t.Fatalf("unclassified race error: %v", err)
			}
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		must(t, err)
		if string(data) != "inside" {
			t.Fatalf("read outside retained root: %q", data)
		}
	}
}

func TestRejectTerminalDoesNotAcquireControllingTTY(t *testing.T) {
	const marker = "PATCHSTACK_INPUTFS_TTY_TEST"
	if os.Getenv(marker) != "child" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRejectTerminalDoesNotAcquireControllingTTY$")
		cmd.Env = append(os.Environ(), marker+"=child")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("terminal rejection child: %v\n%s", err, out)
		}
		return
	}
	assertNoTTY := func() {
		t.Helper()
		fd, err := syscall.Open("/dev/tty", syscall.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err == nil {
			syscall.Close(fd)
			t.Fatal("process acquired a controlling terminal")
		}
		if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("unexpected controlling terminal check: %v", err)
		}
	}
	assertNoTTY()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	must(t, err)
	defer syscall.Close(fd)
	var unlocked int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSPTLCK, uintptr(unsafeptr.Pointer(&unlocked)))
	if errno != 0 {
		t.Fatal(errno)
	}
	var number uint32
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGPTN, uintptr(unsafeptr.Pointer(&number)))
	if errno != 0 {
		t.Fatal(errno)
	}
	r, err := Open("/dev/pts")
	must(t, err)
	defer r.Close()
	_, err = r.OpenRegular(context.Background(), strconv.FormatUint(uint64(number), 10))
	assertReason(t, err, contracts.ReasonUnsafeInput)
	assertNoTTY()
}

func assertReason(t *testing.T, err error, want contracts.Reason) {
	t.Helper()
	var input *contracts.InputError
	if !errors.As(err, &input) || input.Reason != want {
		t.Fatalf("error = %v, want InputError(%s)", err, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
