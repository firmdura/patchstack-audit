//go:build !linux

package executor

import (
	"errors"
	"os"
	"os/exec"
)

func supported() error                   { return errors.New("strict GNU patch execution requires Linux") }
func configureProcess(*exec.Cmd)         {}
func killProcess(*exec.Cmd)              {}
func openStage(string) (*os.File, error) { return nil, supported() }
