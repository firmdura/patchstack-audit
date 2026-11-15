//go:build linux

package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/patchstack-audit/internal/contracts"
	"github.com/firmdura/patchstack-audit/internal/inputfs"
	"github.com/firmdura/patchstack-audit/internal/treedigest"
)

// Every archive/fixture in this package is original, generated test data.
type member struct {
	name, body string
	mode       int64
	kind       byte
	uid        int
	mtime      time.Time
}

func TestPrepareModesAndFinalZeroModeUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("required final-0000 test must run as an unprivileged user")
	}
	archive := makeArchive(t, []member{
		{name: "demo/", kind: tar.TypeDir, mode: 07777},
		{name: "demo/bin/tool", body: "executable\n", mode: 04755},
		{name: "demo/locked", body: "read before publication\n", mode: 0000},
		{name: "demo/empty/", kind: tar.TypeDir, mode: 0000},
	})
	req := request(t, archive)
	result, err := (Preparer{}).Prepare(context.Background(), req)
	must(t, err)
	if result.Failure != nil {
		t.Fatalf("unexpected failure: %+v", result.Failure)
	}
	wantModes := map[string]uint32{"bin/tool": 0755, "locked": 0000}
	if !reflect.DeepEqual(result.Source.IntendedModes, wantModes) {
		t.Fatalf("intended modes = %#v", result.Source.IntendedModes)
	}
	staged, err := os.ReadFile(result.Source.Archive.Path)
	must(t, err)
	if !bytes.Equal(staged, archive) || result.Source.Archive.SHA256 != hash(archive) || result.Source.Archive.Size != int64(len(archive)) {
		t.Fatal("staged byte identity differs")
	}
	assertMode(t, result.Source.Archive.Path, 0400)
	assertMode(t, filepath.Join(req.WorkspaceDir, "locked"), 0600)
	assertMode(t, filepath.Join(req.WorkspaceDir, "bin/tool"), 0755)
	files, digest, err := treedigest.Compute(context.Background(), req.WorkspaceDir, result.Source.IntendedModes)
	must(t, err)
	if len(files) != 2 || files[1].Path != "locked" || files[1].Mode != "0000" || len(digest) != 64 {
		t.Fatalf("unexpected inventory: %#v, digest=%q", files, digest)
	}
	must(t, treedigest.RestoreModes(context.Background(), req.WorkspaceDir, files))
	assertMode(t, filepath.Join(req.WorkspaceDir, "locked"), 0000)
	assertMode(t, filepath.Join(req.WorkspaceDir, "bin/tool"), 0755)
	for _, dir := range []string{"", "bin", "empty"} {
		assertMode(t, filepath.Join(req.WorkspaceDir, dir), 0755)
	}
	if _, err := os.ReadFile(filepath.Join(req.WorkspaceDir, "locked")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("final 0000 file remained readable to unprivileged user: %v", err)
	}
	assertInput(t, req, archive)
}

func TestPrepareHashMismatchPrecedesExtraction(t *testing.T) {
	archive := []byte("not even a gzip archive")
	req := request(t, archive)
	req.Source.SHA256 = hash([]byte("different"))
	result, err := (Preparer{}).Prepare(context.Background(), req)
	if err != nil || result.Failure == nil || result.Failure.Reason != contracts.ReasonHashMismatch {
		t.Fatalf("hash mismatch = %#v, %v", result, err)
	}
	assertEmpty(t, req.WorkspaceDir)
	assertEmpty(t, req.StagingDir)
	assertInput(t, req, archive)
}

func TestPrepareRejectsUnsafeArchiveMembersAndCleans(t *testing.T) {
	cases := map[string][]member{
		"wrong-root":      {{name: "other/file", body: "bad"}},
		"root-regular":    {{name: "demo", body: "bad"}},
		"traversal":       {{name: "demo/../outside", body: "bad"}},
		"absolute":        {{name: "/outside", body: "bad"}},
		"dot-component":   {{name: "demo/./file", body: "bad"}},
		"empty-component": {{name: "demo//file", body: "bad"}},
		"windows":         {{name: "demo/C:/file", body: "bad"}},
		"backslash":       {{name: "demo/a\\b", body: "bad"}},
		"control":         {{name: "demo/a\nb", body: "bad"}},
		"invalid-utf8":    {{name: "demo/\xff", body: "bad"}},
		"duplicate-file":  {{name: "demo/a", body: "one"}, {name: "demo/a", body: "two"}},
		"duplicate-root":  {{name: "demo", kind: tar.TypeDir}, {name: "demo/", kind: tar.TypeDir}},
		"file-then-child": {{name: "demo/a", body: "one"}, {name: "demo/a/b", body: "two"}},
		"child-then-file": {{name: "demo/a/b", body: "one"}, {name: "demo/a", body: "two"}},
		"dir-then-file":   {{name: "demo/a/", kind: tar.TypeDir}, {name: "demo/a", body: "two"}},
		"file-then-dir":   {{name: "demo/a", body: "one"}, {name: "demo/a/", kind: tar.TypeDir}},
		"symlink":         {{name: "demo/link", kind: tar.TypeSymlink}},
		"hardlink":        {{name: "demo/link", kind: tar.TypeLink}},
		"device":          {{name: "demo/dev", kind: tar.TypeChar}},
		"block":           {{name: "demo/dev", kind: tar.TypeBlock}},
		"fifo":            {{name: "demo/pipe", kind: tar.TypeFifo}},
	}
	for name, members := range cases {
		t.Run(name, func(t *testing.T) {
			// A prior successful extraction proves cleanup of partial workspace.
			members = append([]member{{name: "demo/prior", body: "private"}}, members...)
			archive := makeArchive(t, members)
			req := request(t, archive)
			sentinel := filepath.Join(filepath.Dir(req.WorkspaceDir), "outside")
			must(t, os.WriteFile(sentinel, []byte("unchanged"), 0600))
			result, err := (Preparer{}).Prepare(context.Background(), req)
			assertFailure(t, result, err, contracts.ReasonUnsafeInput)
			assertEmpty(t, req.WorkspaceDir)
			assertEmpty(t, req.StagingDir)
			assertInput(t, req, archive)
			data, err := os.ReadFile(sentinel)
			must(t, err)
			if string(data) != "unchanged" {
				t.Fatal("archive changed a path outside its workspace")
			}
		})
	}
}

func TestPrepareRejectsMalformedStreams(t *testing.T) {
	valid := makeArchive(t, []member{{name: "demo/a", body: "content", mode: 0644}})
	raw := archiveRaw(t, []member{{name: "demo/a", body: "content", mode: 0644}})
	badCRC := append([]byte(nil), valid...)
	badCRC[len(badCRC)-8] ^= 1
	cases := map[string][]byte{
		"not-gzip":       []byte("not gzip"),
		"truncated-gzip": valid[:len(valid)-3],
		"bad-gzip-crc":   badCRC,
		"truncated-tar":  compress(t, raw[:514]),
		"no-tar-end":     compress(t, raw[:1024]),
		"trailing-data":  compress(t, append(raw, []byte("hidden archive")...)),
		"invalid-header": compress(t, bytes.Repeat([]byte{1}, 2048)),
		"missing-root":   makeArchive(t, nil),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			req := request(t, archive)
			result, err := (Preparer{}).Prepare(context.Background(), req)
			assertFailure(t, result, err, contracts.ReasonUnsafeInput)
			assertEmpty(t, req.WorkspaceDir)
			assertEmpty(t, req.StagingDir)
			assertInput(t, req, archive)
		})
	}
}

func TestPrepareStreamedLimits(t *testing.T) {
	archive := makeArchive(t, []member{{name: "demo/a", body: "four", mode: 0644}, {name: "demo/b", body: "five!", mode: 0644}})
	cases := map[string]struct {
		archive []byte
		limits  limits
	}{
		"compressed":    {archive, limits{int64(len(archive) - 1), 100, 10}},
		"file-bytes":    {archive, limits{10000, 8, 10}},
		"entries":       {archive, limits{10000, 100, 1}},
		"trailing-bomb": {compress(t, append(archiveRaw(t, []member{{name: "demo/", kind: tar.TypeDir}}), make([]byte, 1<<20)...)), limits{10000, 100, 1}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := request(t, tc.archive)
			result, err := prepare(context.Background(), req, tc.limits)
			assertFailure(t, result, err, contracts.ReasonLimitExceeded)
			assertEmpty(t, req.WorkspaceDir)
			assertEmpty(t, req.StagingDir)
			assertInput(t, req, tc.archive)
		})
	}
	// Equality is valid; limits are not off by one.
	req := request(t, archive)
	result, err := prepare(context.Background(), req, limits{int64(len(archive)), 9, 2})
	must(t, err)
	if result.Failure != nil {
		t.Fatalf("exact limits failed: %+v", result.Failure)
	}
}

func TestPrepareCountsHiddenArchiveHeaders(t *testing.T) {
	file := physicalMember(t, "demo/file", tar.TypeReg, "four")
	pax := physicalMember(t, "metadata", tar.TypeXHeader, paxRecord("comment", "ignored"))
	longName := physicalMember(t, "././@LongLink", tar.TypeGNULongName, "demo/file\x00")
	longLink := physicalMember(t, "././@LongLink", tar.TypeGNULongLink, "unused\x00")
	multiBlockPAX := physicalMember(t, "metadata", tar.TypeXHeader, paxRecord("comment", strings.Repeat("m", 1600)))
	base256PAX := append([]byte(nil), pax...)
	for i := 124; i < 136; i++ {
		base256PAX[i] = 0
	}
	base256PAX[124] = 0x80
	base256PAX[135] = byte(len(paxRecord("comment", "ignored")))
	checksumHeader(base256PAX[:512])
	// PAX overrides this member's raw size of zero. Framing regular bodies by
	// the raw size field would mistake its real data/padding for a header.
	sizeOverride := physicalMember(t, "demo/file", tar.TypeReg, "")
	sizeOverride = append(sizeOverride, []byte("four")...)
	sizeOverride = append(sizeOverride, make([]byte, 508)...)
	cases := []struct {
		name    string
		parts   [][]byte
		entries int
	}{
		{"repeated-pax", [][]byte{pax, pax, pax, pax, pax, file}, 6},
		{"gnu-long-name", [][]byte{longName, file}, 2},
		{"gnu-long-link", [][]byte{longLink, file}, 2},
		{"metadata-body-is-not-headers", [][]byte{multiBlockPAX, file}, 2},
		{"base256-metadata-size", [][]byte{base256PAX, file}, 2},
		{"prior-member-padding", [][]byte{physicalMember(t, "demo/prior", tar.TypeReg, "prior"), pax, longName, file}, 4},
		{"pax-size-override", [][]byte{physicalMember(t, "metadata", tar.TypeXHeader, paxRecord("size", "4")), sizeOverride}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Join(tc.parts, nil)
			raw = append(raw, make([]byte, 1024)...)
			archive := compress(t, raw)
			// Leave ample decompressed-byte allowance: it must not substitute
			// for counting metadata headers that Next consumes internally.
			for _, entryLimit := range []int{1, tc.entries - 1} {
				req := request(t, archive)
				result, err := prepare(context.Background(), req, limits{1 << 20, 1 << 20, entryLimit})
				assertFailure(t, result, err, contracts.ReasonLimitExceeded)
				assertEmpty(t, req.WorkspaceDir)
				assertEmpty(t, req.StagingDir)
				assertInput(t, req, archive)
			}
			req := request(t, archive)
			result, err := prepare(context.Background(), req, limits{1 << 20, 1 << 20, tc.entries})
			must(t, err)
			if result.Failure != nil {
				t.Fatalf("exact physical header limit failed: %+v", result.Failure)
			}
			body, err := os.ReadFile(filepath.Join(req.WorkspaceDir, "file"))
			must(t, err)
			if string(body) != "four" {
				t.Fatalf("metadata changed member body: %q", body)
			}
			assertInput(t, req, archive)
		})
	}
}

// Build original physical members, including metadata that archive/tar.Writer
// deliberately does not expose. No upstream archive bytes are copied.
func physicalMember(t *testing.T, name string, kind byte, body string) []byte {
	t.Helper()
	raw := archiveRaw(t, []member{{name: name, body: body, mode: 0644}})
	raw = append([]byte(nil), raw[:len(raw)-1024]...)
	raw[156] = kind
	checksumHeader(raw[:512])
	return raw
}

func checksumHeader(header []byte) {
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	sum := 0
	for _, value := range header {
		sum += int(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func paxRecord(key, value string) string {
	body := " " + key + "=" + value + "\n"
	length := len(body) + 1
	for {
		record := fmt.Sprintf("%d%s", length, body)
		if len(record) == length {
			return record
		}
		length = len(record)
	}
}

func TestPrepareUsesStagedBytesAfterInputReplacement(t *testing.T) {
	original := makeArchive(t, []member{{name: "demo/file", body: "original", mode: 0644}})
	replacement := makeArchive(t, []member{{name: "demo/file", body: "replacement", mode: 0644}})
	req := request(t, original)
	filename := req.Inputs.(*testInputs).archive
	req.Inputs = &replacingInputs{ConfinedInputs: req.Inputs, replace: func() {
		must(t, os.WriteFile(filename, replacement, 0600))
	}}
	result, err := (Preparer{}).Prepare(context.Background(), req)
	must(t, err)
	data, err := os.ReadFile(filepath.Join(req.WorkspaceDir, "file"))
	must(t, err)
	if string(data) != "original" {
		t.Fatalf("extraction reopened original pathname: %q", data)
	}
	data, err = os.ReadFile(result.Source.Archive.Path)
	must(t, err)
	if !bytes.Equal(data, original) {
		t.Fatal("staged bytes differ from verified bytes")
	}
}

func TestPrepareDigestIgnoresArchiveOrderAndMetadata(t *testing.T) {
	first := []member{{name: "demo/a", body: "a", mode: 0640, uid: 1, mtime: time.Unix(1, 0)}, {name: "demo/z", body: "z", mode: 0755, uid: 2, mtime: time.Unix(2, 0)}}
	second := []member{{name: "demo/empty/", kind: tar.TypeDir, mode: 0700}, {name: "demo/z", body: "z", mode: 0755, uid: 999, mtime: time.Unix(999, 0)}, {name: "demo/a", body: "a", mode: 0640, uid: 998, mtime: time.Unix(998, 0)}}
	var digests []string
	for _, members := range [][]member{first, second} {
		req := request(t, makeArchive(t, members))
		result, err := (Preparer{}).Prepare(context.Background(), req)
		must(t, err)
		_, digest, err := treedigest.Compute(context.Background(), req.WorkspaceDir, result.Source.IntendedModes)
		must(t, err)
		digests = append(digests, digest)
	}
	if digests[0] != digests[1] {
		t.Fatalf("archive metadata/order altered digest: %v", digests)
	}
}

func TestPrepareCancellationIOAndNonemptyWorkspace(t *testing.T) {
	archive := makeArchive(t, []member{{name: "demo/a", body: "file", mode: 0644}})
	req := request(t, archive)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := (Preparer{}).Prepare(ctx, req)
	assertFailure(t, result, err, contracts.ReasonCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	req.Source.Path = "missing.tar.gz"
	result, err = (Preparer{}).Prepare(context.Background(), req)
	assertFailure(t, result, err, contracts.ReasonIO)
	req.Source.Path = "source.tar.gz"
	marker := filepath.Join(req.WorkspaceDir, "existing")
	must(t, os.WriteFile(marker, []byte("keep"), 0600))
	result, err = (Preparer{}).Prepare(context.Background(), req)
	assertFailure(t, result, err, contracts.ReasonUnsafeInput)
	data, err := os.ReadFile(marker)
	must(t, err)
	if string(data) != "keep" {
		t.Fatal("nonempty workspace changed")
	}
}

func TestPrepareHostileUmask(t *testing.T) {
	const marker = "PATCHSTACK_SOURCE_UMASK_TEST"
	if os.Getenv(marker) != "child" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPrepareHostileUmask$")
		cmd.Env = append(os.Environ(), marker+"=child")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("umask child: %v\n%s", err, out)
		}
		return
	}
	archive := makeArchive(t, []member{{name: "demo/dir/file", body: "readable", mode: 0000}, {name: "demo/empty/", kind: tar.TypeDir, mode: 0000}})
	req := request(t, archive)
	previous := syscall.Umask(0777)
	defer syscall.Umask(previous)
	result, err := (Preparer{}).Prepare(context.Background(), req)
	must(t, err)
	data, err := os.ReadFile(filepath.Join(req.WorkspaceDir, "dir/file"))
	must(t, err)
	if string(data) != "readable" {
		t.Fatal("temporary owner access lost under umask 0777")
	}
	files, _, err := treedigest.Compute(context.Background(), req.WorkspaceDir, result.Source.IntendedModes)
	must(t, err)
	must(t, treedigest.RestoreModes(context.Background(), req.WorkspaceDir, files))
	assertMode(t, filepath.Join(req.WorkspaceDir, "dir/file"), 0000)
	assertMode(t, filepath.Join(req.WorkspaceDir, "dir"), 0755)
	assertMode(t, filepath.Join(req.WorkspaceDir, "empty"), 0755)
}

type testInputs struct {
	*inputfs.Root
	archive string
}

func request(t *testing.T, archive []byte) contracts.SourceRequest {
	t.Helper()
	base := t.TempDir()
	input := filepath.Join(base, "inputs")
	staging := filepath.Join(base, "staging")
	workspace := filepath.Join(base, "source")
	for _, dir := range []string{input, staging, workspace} {
		must(t, os.Mkdir(dir, 0700))
	}
	filename := filepath.Join(input, "source.tar.gz")
	must(t, os.WriteFile(filename, archive, 0600))
	root, err := inputfs.Open(input)
	must(t, err)
	t.Cleanup(func() { root.Close() })
	return contracts.SourceRequest{Inputs: &testInputs{root, filename}, Source: contracts.Source{Path: "source.tar.gz", SHA256: hash(archive), RootDir: "demo"}, StagingDir: staging, WorkspaceDir: workspace}
}

func archiveRaw(t *testing.T, members []member) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range members {
		kind := m.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: m.name, Mode: m.mode, Typeflag: kind, Uid: m.uid, Gid: m.uid, ModTime: m.mtime}
		if kind == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if kind == tar.TypeSymlink || kind == tar.TypeLink {
			h.Linkname = "../../outside"
		}
		must(t, tw.WriteHeader(h))
		if kind == tar.TypeReg {
			_, err := tw.Write([]byte(m.body))
			must(t, err)
		}
	}
	must(t, tw.Close())
	return raw.Bytes()
}

func makeArchive(t *testing.T, members []member) []byte {
	t.Helper()
	return compress(t, archiveRaw(t, members))
}

func compress(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	_, err := gz.Write(raw)
	must(t, err)
	must(t, gz.Close())
	return out.Bytes()
}

func hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func assertFailure(t *testing.T, result contracts.SourceResult, err error, reason contracts.Reason) {
	t.Helper()
	var run *contracts.RunError
	if result.Failure == nil || result.Failure.Stage != contracts.StageSource || result.Failure.Reason != reason || !errors.As(err, &run) || run.Stage != contracts.StageSource || run.Reason != reason {
		t.Fatalf("result/error = %#v, %v, want source %s", result, err, reason)
	}
	if result.Source.WorkspaceDir != "" || result.Source.Archive.Path != "" || len(result.Source.IntendedModes) != 0 {
		t.Fatalf("failure leaked partial source: %#v", result.Source)
	}
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	if len(entries) != 0 {
		t.Fatalf("partial contents in %s: %v", dir, entries)
	}
}

func assertInput(t *testing.T, req contracts.SourceRequest, want []byte) {
	t.Helper()
	data, err := os.ReadFile(req.Inputs.(*testInputs).archive)
	must(t, err)
	if !bytes.Equal(data, want) {
		t.Fatal("original source input was modified")
	}
	assertMode(t, req.Inputs.(*testInputs).archive, 0600)
}

func assertMode(t *testing.T, name string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(name)
	must(t, err)
	if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("mode %s = %v, want %04o", name, info.Mode(), want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type replacingInputs struct {
	contracts.ConfinedInputs
	replace func()
}

func (r *replacingInputs) OpenRegular(ctx context.Context, name string) (io.ReadCloser, error) {
	f, err := r.ConfinedInputs.OpenRegular(ctx, name)
	if err != nil {
		return nil, err
	}
	return &replaceOnClose{ReadCloser: f, replace: r.replace}, nil
}

type replaceOnClose struct {
	io.ReadCloser
	replace func()
}

func (r *replaceOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.replace()
	return err
}
