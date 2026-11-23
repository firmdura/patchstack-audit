package patchinput

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

var hunkHeader = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$`)
var indexHeader = regexp.MustCompile(`^index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: (100644|100755))?$`)

func parse(data []byte) ([]contracts.PatchTarget, error) {
	if len(data) == 0 {
		return nil, errors.New("end of patch: expected nonempty unified text")
	}
	if pos := bytes.IndexAny(data, "\x00\r"); pos >= 0 {
		return nil, fmt.Errorf("line %d: unexpected %q byte in unified text", bytes.Count(data[:pos], []byte{'\n'})+1, data[pos])
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("line %d: missing terminating LF", bytes.Count(data, []byte{'\n'})+1)
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	fail := func(i int, err error) ([]contracts.PatchTarget, error) {
		if i == len(lines) {
			return nil, fmt.Errorf("end of patch after line %d: %w", i, err)
		}
		return nil, fmt.Errorf("line %d: %w", i+1, err)
	}
	var targets []contracts.PatchTarget
	for i := 0; i < len(lines); {
		var envelope *gitEnvelope
		if strings.HasPrefix(lines[i], "diff --git ") {
			var err error
			envelope, i, err = consumeGitEnvelope(lines, i)
			if err != nil {
				return fail(i, err)
			}
		}
		if i == len(lines) {
			return fail(i, errors.New("missing unified file headers"))
		}
		oldPath, err := headerPath(lines[i], "--- ")
		if err != nil {
			return fail(i, err)
		}
		i++
		if i == len(lines) {
			return fail(i, errors.New("missing new-file header"))
		}
		newPath, err := headerPath(lines[i], "+++ ")
		if err != nil {
			return fail(i, err)
		}
		target := contracts.PatchTarget{OldPath: oldPath, NewPath: newPath}
		switch {
		case oldPath == "" && newPath != "":
			target.Operation = contracts.OperationAdd
		case oldPath != "" && newPath == "":
			target.Operation = contracts.OperationDelete
		case oldPath != "" && oldPath == newPath:
			target.Operation = contracts.OperationModify
		default:
			return fail(i, errors.New("headers must modify one identical path or add/delete one /dev/null side"))
		}
		if envelope != nil {
			if err := envelope.validateTarget(target); err != nil {
				return fail(i, err)
			}
		}
		i++
		state := fileState{}
		for i < len(lines) && strings.HasPrefix(lines[i], "@@ ") {
			i, err = consumeHunk(lines, i, target.Operation, &state)
			if err != nil {
				return fail(i, err)
			}
		}
		if state.hunks == 0 || (target.Operation != contracts.OperationModify && state.hunks != 1) {
			return fail(i, errors.New("expected counted text hunks; additions/deletions require one complete hunk"))
		}
		targets = append(targets, target)
		// Only the next exact file header or EOF may follow a complete section.
		// Unknown prologues and trailing garbage must not reach GNU patch.
		if i < len(lines) && !strings.HasPrefix(lines[i], "--- ") && !strings.HasPrefix(lines[i], "diff --git ") {
			return fail(i, errors.New("unsupported text outside unified file sections"))
		}
	}
	return targets, nil
}

type gitEnvelope struct {
	path                 string
	operation            contracts.Operation
	oldIsZero, newIsZero bool
}

// The consume functions return the next line index on success, or the index
// where validation stopped (possibly EOF) on failure.
func consumeGitEnvelope(lines []string, start int) (*gitEnvelope, int, error) {
	fields := strings.Split(lines[start], " ")
	if len(fields) != 4 || fields[0] != "diff" || fields[1] != "--git" {
		return nil, start, errors.New("unsupported Git diff header")
	}
	oldPath, err := contracts.StripPatchPath(fields[2])
	if err != nil {
		return nil, start, err
	}
	newPath, err := contracts.StripPatchPath(fields[3])
	if err != nil {
		return nil, start, err
	}
	if oldPath == "" || oldPath != newPath {
		return nil, start, errors.New("Git wrapper must identify one identical non-null target")
	}
	envelope := &gitEnvelope{path: oldPath}
	i := start + 1
	var mode string
	if i < len(lines) {
		if value, ok := strings.CutPrefix(lines[i], "new file mode "); ok {
			envelope.operation, mode = contracts.OperationAdd, value
		} else if value, ok := strings.CutPrefix(lines[i], "deleted file mode "); ok {
			envelope.operation, mode = contracts.OperationDelete, value
		}
		if envelope.operation != "" {
			if mode != "100644" && mode != "100755" {
				return nil, i, errors.New("Git metadata describes an unsupported nonregular mode")
			}
			i++
		}
	}
	if i == len(lines) {
		return nil, i, errors.New("missing Git index metadata and text headers")
	}
	index := indexHeader.FindStringSubmatch(lines[i])
	if index == nil {
		return nil, i, errors.New("unsupported Git index or operation metadata")
	}
	if mode != "" && index[3] != "" && mode != index[3] {
		return nil, i, errors.New("Git regular-file mode descriptors disagree")
	}
	envelope.oldIsZero = strings.Trim(index[1], "0") == ""
	envelope.newIsZero = strings.Trim(index[2], "0") == ""
	return envelope, i + 1, nil
}

func (e *gitEnvelope) validateTarget(target contracts.PatchTarget) error {
	path := target.OldPath
	if path == "" {
		path = target.NewPath
	}
	if e.path != path || (e.operation != "" && e.operation != target.Operation) {
		return errors.New("Git wrapper and unified headers disagree")
	}
	if e.oldIsZero != (target.Operation == contracts.OperationAdd) || e.newIsZero != (target.Operation == contracts.OperationDelete) {
		return errors.New("Git index null side and unified headers disagree")
	}
	return nil
}

func headerPath(line, prefix string) (string, error) {
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("expected %s header", strings.TrimSpace(prefix))
	}
	path, timestamp, hasTimestamp := strings.Cut(line[len(prefix):], "\t")
	if hasTimestamp {
		if _, err := time.Parse("2006-01-02 15:04:05.999999999 -0700", timestamp); err != nil {
			return "", errors.New("unsupported header timestamp")
		}
	}
	return contracts.StripPatchPath(path)
}

type fileState struct {
	hunks            int
	oldEnd, newEnd   uint64
	oldNoLF, newNoLF bool
}

func consumeHunk(lines []string, start int, operation contracts.Operation, state *fileState) (int, error) {
	match := hunkHeader.FindStringSubmatch(lines[start])
	if match == nil {
		return start, errors.New("malformed unified hunk header")
	}
	numbers := [4]uint64{}
	for i, value := range match[1:] {
		if value == "" {
			numbers[i] = 1
			continue
		}
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil {
			return start, errors.New("invalid unified hunk range")
		}
		numbers[i] = n
	}
	oldStart, oldCount, newStart, newCount := numbers[0], numbers[1], numbers[2], numbers[3]
	if oldCount > uint64(len(lines)-start) || newCount > uint64(len(lines)-start) ||
		oldStart > math.MaxInt64-oldCount || newStart > math.MaxInt64-newCount ||
		(oldCount != 0 && oldStart == 0) || (newCount != 0 && newStart == 0) ||
		(oldCount == 0 && newCount == 0) {
		return start, errors.New("impossible unified hunk range")
	}
	if state.hunks > 0 && (oldStart < state.oldEnd || newStart < state.newEnd) {
		return start, errors.New("overlapping or out-of-order unified hunks")
	}
	if operation == contracts.OperationAdd && (oldStart != 0 || oldCount != 0 || newStart != 1 || newCount == 0) {
		return start, errors.New("addition must describe a complete new file")
	}
	if operation == contracts.OperationDelete && (newStart != 0 || newCount != 0 || oldStart != 1 || oldCount == 0) {
		return start, errors.New("deletion must describe a complete old file")
	}
	oldRemaining, newRemaining := oldCount, newCount
	i, lastKind, changed := start+1, byte(0), false
	for {
		if i < len(lines) && lines[i] == `\ No newline at end of file` {
			if lastKind == 0 {
				return i, errors.New("misplaced no-newline marker")
			}
			if lastKind != '+' {
				state.oldNoLF = true
			}
			if lastKind != '-' {
				state.newNoLF = true
			}
			lastKind = 0
			i++
			continue
		}
		if oldRemaining == 0 && newRemaining == 0 {
			break
		}
		if i == len(lines) || len(lines[i]) == 0 {
			return i, errors.New("truncated unified hunk")
		}
		kind := lines[i][0]
		switch kind {
		case ' ':
			if oldRemaining == 0 || newRemaining == 0 || state.oldNoLF || state.newNoLF {
				return i, errors.New("inconsistent unified context line")
			}
			oldRemaining--
			newRemaining--
		case '-':
			if oldRemaining == 0 || state.oldNoLF {
				return i, errors.New("inconsistent unified removed line")
			}
			oldRemaining--
			changed = true
		case '+':
			if newRemaining == 0 || state.newNoLF {
				return i, errors.New("inconsistent unified added line")
			}
			newRemaining--
			changed = true
		default:
			return i, errors.New("unsupported unified hunk line")
		}
		lastKind = kind
		i++
	}
	if !changed {
		return start, errors.New("hunk contains no text change")
	}
	state.hunks++
	state.oldEnd, state.newEnd = oldStart+oldCount, newStart+newCount
	return i, nil
}
