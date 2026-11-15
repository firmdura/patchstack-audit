// Command acceptance exercises the real CLI with original local fixtures.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/firmdura/patchstack-audit/examples/demo/fixtures"
)

type evidence struct {
	SchemaVersion int    `json:"schema_version"`
	Outcome       string `json:"outcome"`
	Stage         string `json:"stage"`
	Reason        string `json:"reason"`
	Patches       []struct {
		ID       string `json:"id"`
		SHA256   string `json:"sha256"`
		Upstream string `json:"upstream"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
	} `json:"patches"`
	Digest string       `json:"final_tree_sha256"`
	Files  []fileRecord `json:"files"`
}

type fileRecord struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "acceptance:", err)
		os.Exit(1)
	}
}

func run() (retErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			retErr = fmt.Errorf("%v", recovered)
		}
	}()
	check(len(os.Args) == 2, "usage: acceptance /absolute/path/to/patchstack")
	binary, err := filepath.Abs(os.Args[1])
	must(err)
	work, err := os.MkdirTemp("", "patchstack-acceptance-")
	must(err)
	defer os.RemoveAll(work)
	inputs := filepath.Join(work, "inputs")
	must(fixtures.Generate(inputs))
	inputsAgain := filepath.Join(work, "inputs-again")
	must(fixtures.Generate(inputsAgain))
	check(reflect.DeepEqual(snapshot(inputs), snapshot(inputsAgain)), "example generation is not reproducible")
	original := snapshot(inputs)

	runCLI := func(root, output, format string, wantExit int) ([]byte, evidence) {
		before := snapshot(root)
		command := exec.Command(binary, "audit", "--manifest", filepath.Join(root, "stack.yaml"), "--input-root", root, "--output", output, "--format", format)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		gotExit := 0
		if err != nil {
			var exited *exec.ExitError
			if !asExit(err, &exited) {
				panic(err)
			}
			gotExit = exited.ExitCode()
		}
		check(gotExit == wantExit, "exit=%d want=%d; stderr=%s; stdout=%s", gotExit, wantExit, stderr.String(), stdout.String())
		check(reflect.DeepEqual(before, snapshot(root)), "input changed during %s", output)
		noTemporary(work)
		var report evidence
		if format == "json" {
			must(json.Unmarshal(stdout.Bytes(), &report))
		}
		return append([]byte(nil), stdout.Bytes()...), report
	}

	first, second := filepath.Join(work, "run1"), filepath.Join(work, "run2")
	stdout, success := runCLI(inputs, first, "json", 0)
	check(success.SchemaVersion == 1 && success.Outcome == "reproduced" && success.Stage == "complete" && success.Reason == "none", "invalid success evidence: %+v", success)
	check(len(success.Patches) == 2 && success.Patches[0].ID == "add" && success.Patches[1].ID == "label", "patch order changed")
	for _, patch := range success.Patches {
		check(patch.Status == "applied" && patch.Reason == "none" && patch.Upstream == "local:demonstration", "unproven patch outcome: %+v", patch)
	}
	check(bytes.Equal(stdout, read(filepath.Join(first, "report.json"))), "JSON stdout differs from published JSON")
	markdown, _ := runCLI(inputs, second, "markdown", 0)
	check(bytes.Equal(markdown, read(filepath.Join(second, "report.md"))), "Markdown stdout differs from published Markdown")
	check(reflect.DeepEqual(snapshot(first), snapshot(second)), "repeated output bytes/modes differ")
	records, digest := treeDigest(filepath.Join(first, "source"))
	check(reflect.DeepEqual(records, success.Files) && digest == success.Digest, "independent tree digest/file inventory disagrees")
	check(strings.Contains(string(read(filepath.Join(first, "source", "main.c"))), "return a + b;") && strings.Contains(string(read(filepath.Join(first, "source", "main.c"))), "total: %d"), "patched C source does not contain both changes")
	entries, err := os.ReadDir(first)
	must(err)
	check(len(entries) == 3 && entries[0].Name() == "report.json" && entries[1].Name() == "report.md" && entries[2].Name() == "source", "published package contains unexpected files")
	fmt.Println("PASS reproducible example, two real CLI runs, JSON/Markdown, independent digest and unchanged inputs")

	failureCase := func(name string, mutate func(string), wantExit int, stage, reason string) evidence {
		root := filepath.Join(work, name+"-inputs")
		must(fixtures.Generate(root))
		mutate(root)
		output := filepath.Join(work, name+"-output")
		_, report := runCLI(root, output, "json", wantExit)
		check(report.Outcome == "failed" && report.Stage == stage && report.Reason == reason && report.Digest == "" && len(report.Files) == 0, "%s evidence: %+v", name, report)
		_, err := os.Lstat(output)
		check(os.IsNotExist(err), "%s published a partial output: %v", name, err)
		fmt.Printf("PASS %s: exit %d, %s/%s, no partial output\n", name, wantExit, stage, reason)
		return report
	}
	failureCase("wrong-source-hash", func(root string) {
		data := read(filepath.Join(root, "source.tar.gz"))
		manifest := string(read(filepath.Join(root, "stack.yaml")))
		write(filepath.Join(root, "stack.yaml"), []byte(strings.ReplaceAll(manifest, hash(data), strings.Repeat("0", 64))))
	}, 1, "source", "hash_mismatch")
	failureCase("wrong-patch-hash", func(root string) {
		file := filepath.Join(root, "patches", "0001-add.patch")
		write(file, append(read(file), '\n'))
	}, 1, "inventory", "hash_mismatch")
	failureCase("extra-patch", func(root string) {
		write(filepath.Join(root, "patches", "unlisted.patch"), read(filepath.Join(root, "patches", "0001-add.patch")))
	}, 1, "inventory", "inventory_mismatch")
	failed := failureCase("second-patch-failure", func(root string) {
		changeInput(root, "patches/0002-label.patch", func(old []byte) []byte {
			return bytes.ReplaceAll(old, []byte(`-    printf("sum: %d\n", sum(2, 3));`), []byte(`-    printf("missing: %d\n", sum(2, 3));`))
		})
	}, 1, "execution", "patch_failed")
	check(len(failed.Patches) == 2 && failed.Patches[0].Status == "applied" && failed.Patches[1].Status == "failed", "second failure lost execution order")
	failureCase("nonzero-offset", func(root string) {
		changeInput(root, "patches/0001-add.patch", func(old []byte) []byte {
			return bytes.ReplaceAll(old, []byte("@@ -2,7 +2,7 @@"), []byte("@@ -3,7 +3,7 @@"))
		})
		// Prove that this is an applicable offset patch, not a malformed fixture.
		probe := filepath.Join(work, "offset-probe")
		must(os.Mkdir(probe, 0700))
		gz, err := gzip.NewReader(bytes.NewReader(read(filepath.Join(root, "source.tar.gz"))))
		must(err)
		tarReader := tar.NewReader(gz)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			must(err)
			if header.Name == "demo-1.0/main.c" {
				data, err := io.ReadAll(tarReader)
				must(err)
				write(filepath.Join(probe, "main.c"), data)
			}
		}
		must(gz.Close())
		output, err := exec.Command("patch", "--batch", "--forward", "--fuzz=0", "--strip=1", "--no-backup-if-mismatch", "--directory", probe, "--input", filepath.Join(root, "patches", "0001-add.patch")).CombinedOutput()
		must(err)
		check(bytes.Contains(output, []byte("offset")), "offset fixture did not exercise GNU offset application: %s", output)
	}, 1, "execution", "patch_failed")
	failureCase("archive-traversal", func(root string) {
		changeInput(root, "source.tar.gz", func([]byte) []byte {
			var data bytes.Buffer
			gz := gzip.NewWriter(&data)
			tw := tar.NewWriter(gz)
			must(tw.WriteHeader(&tar.Header{Name: "demo-1.0/../../escape", Mode: 0644, Typeflag: tar.TypeReg, Size: 6}))
			_, err := tw.Write([]byte("escape"))
			must(err)
			must(tw.Close())
			must(gz.Close())
			return data.Bytes()
		})
	}, 2, "source", "unsafe_input")
	_, err = os.Stat(filepath.Join(work, "escape"))
	check(os.IsNotExist(err), "archive traversal wrote outside workspace")
	before := snapshot(first)
	_, exists := runCLI(inputs, first, "json", 2)
	check(exists.Outcome == "failed" && exists.Reason == "output_exists" && exists.Digest == "", "existing-output refusal evidence invalid")
	check(reflect.DeepEqual(before, snapshot(first)), "existing output changed")
	check(reflect.DeepEqual(original, snapshot(inputs)), "original inputs changed")
	fmt.Println("PASS existing output refused unchanged; all CLI acceptance checks passed")
	return nil
}

func asExit(err error, out **exec.ExitError) bool {
	exited, ok := err.(*exec.ExitError)
	*out = exited
	return ok
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func check(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

func read(name string) []byte {
	data, err := os.ReadFile(name)
	must(err)
	return data
}

func write(name string, data []byte) { must(os.WriteFile(name, data, 0644)) }
func hash(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func changeInput(root, relative string, change func([]byte) []byte) {
	name := filepath.Join(root, relative)
	old := read(name)
	changed := change(old)
	check(!bytes.Equal(old, changed), "mutation changed no bytes in %s", relative)
	write(name, changed)
	manifest := filepath.Join(root, "stack.yaml")
	write(manifest, bytes.ReplaceAll(read(manifest), []byte(hash(old)), []byte(hash(changed))))
}

func noTemporary(dir string) {
	entries, err := os.ReadDir(dir)
	must(err)
	for _, entry := range entries {
		check(!strings.HasPrefix(entry.Name(), ".patchstack-"), "temporary sibling leaked: %s", entry.Name())
	}
}

func snapshot(root string) map[string]string {
	result := map[string]string{}
	must(filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		must(err)
		relative, err := filepath.Rel(root, name)
		must(err)
		info, err := entry.Info()
		must(err)
		value := fmt.Sprintf("%s %04o", info.Mode().Type(), info.Mode().Perm())
		if info.Mode().IsRegular() {
			value += " " + hash(read(name))
		} else {
			check(info.IsDir(), "unexpected nonregular path %s", name)
		}
		result[relative] = value
		return nil
	}))
	return result
}

func treeDigest(root string) ([]fileRecord, string) {
	var records []fileRecord
	must(filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		must(err)
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		must(err)
		check(info.Mode().IsRegular(), "nonregular output %s", name)
		relative, err := filepath.Rel(root, name)
		must(err)
		records = append(records, fileRecord{Path: filepath.ToSlash(relative), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), SHA256: hash(read(name))})
		return nil
	}))
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	var manifest strings.Builder
	for _, file := range records {
		fmt.Fprintf(&manifest, "%s\x00%s\x00%s\n", file.Path, file.Mode, file.SHA256)
	}
	return records, hash([]byte(manifest.String()))
}
