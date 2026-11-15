package contracts

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestContractPaths(t *testing.T) {
	for _, path := range []string{"source.tar.gz", "dir/source.tar.gz", "來源/src.tar.gz", "with space/file.tar.gz"} {
		if err := ValidateRelativePath(path); err != nil {
			t.Fatalf("valid path %q: %v", path, err)
		}
	}
	for _, path := range []string{"", ".", "..", "/absolute", "a/../b", "a/./b", "a//b", "a/", `a\b`, "C:/x", "a\x00b", "a\x1fb", "a\x7fb", string([]byte{0xff})} {
		if ValidateRelativePath(path) == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
	for _, path := range []string{"a/file.c", "b/來源.c"} {
		got, err := StripPatchPath(path)
		if err != nil || got == "" {
			t.Fatalf("valid target %q: %q, %v", path, got, err)
		}
	}
	if got, err := StripPatchPath("/dev/null"); err != nil || got != "" {
		t.Fatal("missing /dev/null sentinel")
	}
	for _, path := range []string{"file.c", "a/../../escape", "a/../escape", "/etc/passwd", "a/file name", "a/file\tname", "a/file\u2003name", `"a/file"`, `a/'file'`} {
		if _, err := StripPatchPath(path); err == nil {
			t.Fatalf("accepted target %q", path)
		}
	}
}

func TestContractOperationalEvidence(t *testing.T) {
	cause := errors.New("/absolute/host/path is diagnostic only")
	err := &RunError{Stage: StageExecution, Reason: ReasonTimeout, Err: cause}
	failure := FailureFromError(StageSource, err)
	if failure.Stage != StageExecution || failure.Reason != ReasonTimeout || !errors.Is(err, cause) {
		t.Fatal("typed operational evidence lost")
	}
	if strings.Contains(string(failure.Reason), "/absolute") {
		t.Fatal("diagnostic leaked")
	}
	if got := FailureFromError(StageSource, cause); got.Stage != StageSource || got.Reason != ReasonIO {
		t.Fatal("untyped errors must fail operationally")
	}
}

// These compile-only adapters exercise the frozen method sets and private staged
// descriptors without implementing any source extraction or patch execution.
type inputShape struct{}

func (inputShape) OpenRegular(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("not implemented in foundation")
}
func (inputShape) ReadDir(context.Context, string) ([]InputEntry, error) {
	return nil, errors.New("not implemented in foundation")
}

var _ ConfinedInputs = inputShape{}

func TestContractConfinedReadReasonStage(t *testing.T) {
	for _, stage := range []Stage{StageSource, StageInventory} {
		for _, reason := range []Reason{ReasonUnsafeInput, ReasonIO, ReasonCancelled} {
			err := &InputError{Reason: reason, Err: errors.New("local diagnostic")}
			got := FailureFromError(stage, err)
			if got.Stage != stage || got.Reason != reason {
				t.Fatalf("wrong caller stage/reason: %#v", got)
			}
		}
		got := FailureFromError(stage, &RunError{Reason: ReasonIO})
		if got.Stage != stage {
			t.Fatal("empty operational stage lost caller stage")
		}
	}
}
