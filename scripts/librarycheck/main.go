// This program is copied into a temporary external module by test-library.sh.
// Its only PatchStack import is the supported public API.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/firmdura/patchstack-audit/pkg/patchstack"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "external library:", err)
		os.Exit(1)
	}
}

func run() (retErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			retErr = fmt.Errorf("%v", recovered)
		}
	}()
	check(len(os.Args) == 3, "usage: librarycheck INPUTS OUTPUT_PARENT")
	inputs, parent := os.Args[1], os.Args[2]
	before := snapshot(inputs)
	file, err := os.Open(filepath.Join(inputs, "stack.yaml"))
	must(err)
	manifest, err := patchstack.LoadManifest(file)
	must(err)
	must(file.Close())
	var previous []byte
	for _, name := range []string{"library-run1", "library-run2"} {
		output := filepath.Join(parent, name)
		report, err := patchstack.Audit(context.Background(), manifest, patchstack.Options{InputRoot: inputs, OutputDir: output})
		must(err)
		check(report.ExitCode(err) == 0 && report.Outcome == patchstack.OutcomeReproduced && len(report.Patches) == 2, "public Audit did not reproduce complete series")
		must(report.Validate())
		var data bytes.Buffer
		must(patchstack.WriteJSON(&data, report))
		published, err := os.ReadFile(filepath.Join(output, "report.json"))
		must(err)
		check(bytes.Equal(data.Bytes(), published), "public JSON differs from published JSON")
		if previous != nil {
			check(bytes.Equal(previous, published), "public API results are not deterministic")
		}
		previous = published
		entries, err := os.ReadDir(output)
		must(err)
		check(len(entries) == 3 && entries[0].Name() == "report.json" && entries[1].Name() == "report.md" && entries[2].Name() == "source", "API output contains unexpected material")
	}
	bad := manifest
	bad.Source.SHA256 = strings.Repeat("0", 64)
	output := filepath.Join(parent, "library-failure")
	report, err := patchstack.Audit(context.Background(), bad, patchstack.Options{InputRoot: inputs, OutputDir: output})
	must(err)
	must(report.Validate())
	check(report.ExitCode(err) == 1 && report.Reason == patchstack.ReasonHashMismatch && report.FinalTreeSHA256 == "" && len(report.Files) == 0, "expected API failure lost typed semantics")
	_, err = os.Lstat(output)
	check(os.IsNotExist(err), "failed API run left a partial output")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output = filepath.Join(parent, "library-cancelled")
	report, err = patchstack.Audit(ctx, manifest, patchstack.Options{InputRoot: inputs, OutputDir: output})
	var run *patchstack.RunError
	check(errors.As(err, &run) && errors.Is(err, context.Canceled) && run.Reason == patchstack.ReasonCancelled && report.ExitCode(err) == 2, "API cancellation did not preserve error typing")
	_, err = os.Lstat(output)
	check(os.IsNotExist(err), "cancelled API run left output")
	check(reflect.DeepEqual(before, snapshot(inputs)), "public API changed original inputs")
	entries, err := os.ReadDir(parent)
	must(err)
	for _, entry := range entries {
		check(!strings.HasPrefix(entry.Name(), ".patchstack-"), "API left a temporary sibling")
	}
	fmt.Println("PASS external-module public API: deterministic success, typed failure/cancellation, unchanged inputs and no partial output")
	return nil
}

func check(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
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
			data, err := os.ReadFile(name)
			must(err)
			hash := sha256.Sum256(data)
			value += " " + hex.EncodeToString(hash[:])
		} else {
			check(info.IsDir(), "nonregular input in external-module test")
		}
		result[relative] = value
		return nil
	}))
	return result
}
