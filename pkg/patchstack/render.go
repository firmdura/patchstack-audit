package patchstack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// WriteJSON writes a version 1 report as indented JSON followed by a newline.
// It validates the report before writing and preserves patch order. An invalid
// report produces an error without writing any bytes. Writing does not run an
// audit or reopen published source files.
//
// A writer failure returns a RunError with StageOutput and ReasonOutputWrite.
// Use errors.Is to inspect the underlying writer error.
func WriteJSON(w io.Writer, report Report) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return writeReport(w, append(data, '\n'))
}

// WriteMarkdown writes a version 1 report as repeatable Markdown. It validates
// the report before writing; an invalid report produces an error without output.
// Supplied text, including upstream URLs, is escaped so it cannot introduce links,
// HTML or extra report structure. Final tree details appear only for a successful
// report. Writing does not run an audit or reopen published source files.
//
// A writer failure returns a RunError with StageOutput and ReasonOutputWrite.
// Use errors.Is to inspect the underlying writer error.
func WriteMarkdown(w io.Writer, report Report) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	var out bytes.Buffer
	out.WriteString("# PatchStack Audit\n\n")
	fmt.Fprintf(&out, "Schema version: %d\n\nOutcome: %s\n\nStage: %s\n\nReason: %s\n\n", report.SchemaVersion, markdownText(string(report.Outcome)), markdownText(string(report.Stage)), markdownText(string(report.Reason)))
	out.WriteString("## Source declaration\n\n")
	fmt.Fprintf(&out, "Archive: %s\n\nSHA-256: %s\n\nArchive root: %s\n\n", markdownText(report.Source.Path), markdownText(report.Source.SHA256), markdownText(report.Source.RootDir))
	out.WriteString("## Ordered patches\n\n")
	if len(report.Patches) == 0 {
		out.WriteString("No patches declared.\n\n")
	} else {
		counts := make(map[PatchStatus]int)
		for _, patch := range report.Patches {
			counts[patch.Status]++
		}
		fmt.Fprintf(&out, "%d applied, %d failed, %d not run.\n\n", counts[PatchApplied], counts[PatchFailed], counts[PatchNotRun])
		out.WriteString("| Position | ID | File | SHA-256 | Application | Reason | Declared provenance | Declared CVEs |\n")
		out.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for i, patch := range report.Patches {
			fmt.Fprintf(&out, "| %d | %s | %s | %s | %s | %s | %s | %s |\n", i+1, markdownText(patch.ID), markdownText(patch.File), markdownText(patch.SHA256), markdownText(string(patch.Status)), markdownText(string(patch.Reason)), markdownText(patch.Upstream), markdownText(strings.Join(patch.CVEs, ", ")))
		}
		out.WriteByte('\n')
	}
	out.WriteString("Upstream references and CVE identifiers are declarations, not authenticated provenance or security verdicts.\n\n")
	if report.Outcome == OutcomeReproduced {
		out.WriteString("## Final source tree\n\n")
		fmt.Fprintf(&out, "Tree SHA-256: %s\n\n", markdownText(report.FinalTreeSHA256))
		if len(report.Files) == 0 {
			out.WriteString("No regular files.\n\n")
		} else {
			out.WriteString("| Relative path | Intended mode | Content SHA-256 |\n")
			out.WriteString("| --- | --- | --- |\n")
			for _, file := range report.Files {
				fmt.Fprintf(&out, "| %s | %s | %s |\n", markdownText(file.Path), markdownText(file.Mode), markdownText(file.SHA256))
			}
			out.WriteByte('\n')
		}
	}
	out.WriteString("## Digest definition\n\n")
	out.WriteString(markdownText(report.DigestDefinition))
	out.WriteString("\n\n## Evidence limitations\n\n")
	out.WriteString(markdownText(report.Limitations))
	out.WriteByte('\n')
	return writeReport(w, out.Bytes())
}

// Character references are decoded after Markdown structure is parsed, keeping
// punctuation, line breaks and control characters out of its structural syntax.
// In particular, escaping '&' prevents supplied character references from being
// interpreted as a second layer of markup.
func markdownText(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r == ' ' || unicode.IsLetter(r) || unicode.IsNumber(r) {
			out.WriteRune(r)
		} else {
			out.WriteString("&#")
			out.WriteString(strconv.FormatInt(int64(r), 10))
			out.WriteByte(';')
		}
	}
	return out.String()
}

func writeReport(w io.Writer, data []byte) error {
	if w == nil {
		return &RunError{Stage: StageOutput, Reason: ReasonOutputWrite, Err: fmt.Errorf("nil report writer")}
	}
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &RunError{Stage: StageOutput, Reason: ReasonOutputWrite, Err: err}
	}
	return nil
}
