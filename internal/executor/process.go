package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

type processResult struct {
	stdout, stderr, combined      []byte
	err, startErr, errorCause     error
	overflow, timedOut, cancelled bool
}

func (r processResult) operational() (contracts.Reason, error) {
	switch {
	case r.cancelled:
		return contracts.ReasonCancelled, r.errorCause
	case r.timedOut:
		return contracts.ReasonTimeout, context.DeadlineExceeded
	case r.overflow:
		return contracts.ReasonLimitExceeded, errors.New("patch diagnostic capture exceeded fixed limit")
	case r.startErr != nil:
		return contracts.ReasonIO, r.startErr
	}
	if r.err != nil {
		var exited *exec.ExitError
		if !errors.As(r.err, &exited) {
			return contracts.ReasonIO, r.err
		}
	}
	return contracts.ReasonNone, nil
}

// Both streams share a single counter and overflow signal. Writes beyond the
// cap are discarded while the monitor kills the entire process group.
type capture struct {
	mu                       sync.Mutex
	stdout, stderr, combined []byte
	limit                    int64
	overflow                 bool
	exceeded                 chan struct{}
}
type captureWriter struct {
	capture *capture
	stderr  bool
}

func (w captureWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	n := min(int64(len(p)), max(int64(0), c.limit-int64(len(c.combined))))
	c.combined = append(c.combined, p[:n]...)
	if w.stderr {
		c.stderr = append(c.stderr, p[:n]...)
	} else {
		c.stdout = append(c.stdout, p[:n]...)
	}
	if n < int64(len(p)) && !c.overflow {
		c.overflow = true
		close(c.exceeded)
	}
	return len(p), nil
}

func process(ctx context.Context, executable string, args []string, directory string, input *os.File, limits policy) processResult {
	if err := ctx.Err(); err != nil {
		return processResult{cancelled: true, errorCause: err}
	}
	c := &capture{limit: limits.logBytes, exceeded: make(chan struct{})}
	cmd := exec.Command(executable, args...)
	cmd.Dir = directory
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin", "PATCH_GET=0", "QUOTING_STYLE=literal"}
	if input != nil {
		cmd.Stdin = input
	}
	cmd.Stdout = captureWriter{c, false}
	cmd.Stderr = captureWriter{c, true}
	cmd.WaitDelay = time.Second
	configureProcess(cmd)
	if err := cmd.Start(); err != nil {
		return processResult{startErr: err}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(limits.timeout)
	defer timer.Stop()
	var result processResult
	select {
	case result.err = <-done:
	case <-ctx.Done():
		result.cancelled, result.errorCause = true, ctx.Err()
		killProcess(cmd)
		result.err = <-done
	case <-timer.C:
		result.timedOut = true
		killProcess(cmd)
		result.err = <-done
	case <-c.exceeded:
		killProcess(cmd)
		result.err = <-done
	}
	// A child inheriting the process group must not outlive even an exited tool.
	// Wait reaps the direct child; descendant reaping belongs to the OS parent.
	killProcess(cmd)
	c.mu.Lock()
	result.stdout, result.stderr, result.combined, result.overflow = c.stdout, c.stderr, c.combined, c.overflow
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		result.cancelled, result.errorCause = true, err
	}
	return result
}

var _ io.Writer = captureWriter{}
