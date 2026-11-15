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
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.ContainsAny(data, "\x00\r") {
		return nil, errors.New("expected nonempty LF-terminated unified text without NUL or CR bytes")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	var targets []contracts.PatchTarget
	for i := 0; i < len(lines); {
		var envelope *gitEnvelope
		if strings.HasPrefix(lines[i], "diff --git ") {
			var err error
			envelope, i, err = consumeGitEnvelope(lines, i)
			if err != nil {
				return nil, err
			}
		}
		if i == len(lines) {
			return nil, errors.New("missing unified file headers")
		}
		oldPath, err := headerPath(lines[i], "--- ")
		if err != nil {
			return nil, err
		}
		i++
		if i == len(lines) {
			return nil, errors.New("missing new-file header")
		}
		newPath, err := headerPath(lines[i], "+++ ")
		if err != nil {
			return nil, err
		}
		i++
		target := contracts.PatchTarget{OldPath: oldPath, NewPath: newPath}
		switch {
		case oldPath == "" && newPath != "":
			target.Operation = contracts.OperationAdd
		case oldPath != "" && newPath == "":
			target.Operation = contracts.OperationDelete
		case oldPath != "" && oldPath == newPath:
			target.Operation = contracts.OperationModify
		default:
			return nil, errors.New("headers must modify one identical path or add/delete one /dev/null side")
		}
		if envelope != nil {
			if err := envelope.validateTarget(target); err != nil {
				return nil, err
			}
		}
		state := fileState{}
		for i < len(lines) && strings.HasPrefix(lines[i], "@@ ") {
			next, err := consumeHunk(lines, i, target.Operation, &state)
			if err != nil {
				return nil, err
			}
			i = next
		}
		if state.hunks == 0 || (target.Operation != contracts.OperationModify && state.hunks != 1) {
			return nil, errors.New("expected counted text hunks; additions/deletions require one complete hunk")
		}
		targets = append(targets, target)
		// Only the next exact file header or EOF may follow a complete section.
		// Unknown prologues and trailing garbage must not reach GNU patch.
		if i < len(lines) && !strings.HasPrefix(lines[i], "--- ") && !strings.HasPrefix(lines[i], "diff --git ") {
			return nil, errors.New("unsupported text outside unified file sections")
		}
	}
	return targets, nil
}

type gitEnvelope struct {
	path                 string
	operation            contracts.Operation
	oldIsZero, newIsZero bool
}

func consumeGitEnvelope(lines []string, start int) (*gitEnvelope, int, error) {
	fields := strings.Split(lines[start], " ")
	if len(fields) != 4 || fields[0] != "diff" || fields[1] != "--git" {
		return nil, 0, errors.New("unsupported Git diff header")
	}
	oldPath, err := contracts.StripPatchPath(fields[2])
	if err != nil {
		return nil, 0, err
	}
	newPath, err := contracts.StripPatchPath(fields[3])
	if err != nil {
		return nil, 0, err
	}
	if oldPath == "" || oldPath != newPath {
		return nil, 0, errors.New("Git wrapper must identify one identical non-null target")
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
				return nil, 0, errors.New("Git metadata describes an unsupported nonregular mode")
			}
			i++
		}
	}
	if i == len(lines) {
		return nil, 0, errors.New("missing Git index metadata and text headers")
	}
	index := indexHeader.FindStringSubmatch(lines[i])
	if index == nil {
		return nil, 0, errors.New("unsupported Git index or operation metadata")
	}
	if mode != "" && index[3] != "" && mode != index[3] {
		return nil, 0, errors.New("Git regular-file mode descriptors disagree")
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
		return 0, errors.New("malformed unified hunk header")
	}
	numbers := [4]uint64{}
	for i, value := range match[1:] {
		if value == "" {
			numbers[i] = 1
			continue
		}
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil {
			return 0, errors.New("invalid unified hunk range")
		}
		numbers[i] = n
	}
	oldStart, oldCount, newStart, newCount := numbers[0], numbers[1], numbers[2], numbers[3]
	if oldCount > uint64(len(lines)-start) || newCount > uint64(len(lines)-start) ||
		oldStart > math.MaxInt64-oldCount || newStart > math.MaxInt64-newCount ||
		(oldCount != 0 && oldStart == 0) || (newCount != 0 && newStart == 0) ||
		(oldCount == 0 && newCount == 0) {
		return 0, errors.New("impossible unified hunk range")
	}
	if state.hunks > 0 && (oldStart < state.oldEnd || newStart < state.newEnd) {
		return 0, errors.New("overlapping or out-of-order unified hunks")
	}
	if operation == contracts.OperationAdd && (oldStart != 0 || oldCount != 0 || newStart != 1 || newCount == 0) {
		return 0, errors.New("addition must describe a complete new file")
	}
	if operation == contracts.OperationDelete && (newStart != 0 || newCount != 0 || oldStart != 1 || oldCount == 0) {
		return 0, errors.New("deletion must describe a complete old file")
	}
	oldRemaining, newRemaining := oldCount, newCount
	i, lastKind, changed := start+1, byte(0), false
	for {
		if i < len(lines) && lines[i] == `\ No newline at end of file` {
			if lastKind == 0 {
				return 0, errors.New("misplaced no-newline marker")
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
			return 0, errors.New("truncated unified hunk")
		}
		kind := lines[i][0]
		switch kind {
		case ' ':
			if oldRemaining == 0 || newRemaining == 0 || state.oldNoLF || state.newNoLF {
				return 0, errors.New("inconsistent unified context line")
			}
			oldRemaining--
			newRemaining--
		case '-':
			if oldRemaining == 0 || state.oldNoLF {
				return 0, errors.New("inconsistent unified removed line")
			}
			oldRemaining--
			changed = true
		case '+':
			if newRemaining == 0 || state.newNoLF {
				return 0, errors.New("inconsistent unified added line")
			}
			newRemaining--
			changed = true
		default:
			return 0, errors.New("unsupported unified hunk line")
		}
		lastKind = kind
		i++
	}
	if !changed {
		return 0, errors.New("hunk contains no text change")
	}
	state.hunks++
	state.oldEnd, state.newEnd = oldStart+oldCount, newStart+newCount
	return i, nil
}
