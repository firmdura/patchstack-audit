//go:build !linux

// Package inputfs provides confined input reads on Linux.
package inputfs

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

// Root is available only on Linux, the version 1 supported platform.
type Root struct{}

// Open reports unsupported confined input access on non-Linux hosts.
func Open(string) (*Root, error)            { return nil, unsupported() }
func FromDirectory(*os.File) (*Root, error) { return nil, unsupported() }

func (*Root) Close() error               { return nil }
func (*Root) Stat() (os.FileInfo, error) { return nil, unsupported() }
func (*Root) OpenRegular(context.Context, string) (io.ReadCloser, error) {
	return nil, unsupported()
}
func (*Root) ReadDir(context.Context, string) ([]contracts.InputEntry, error) {
	return nil, unsupported()
}
func unsupported() error {
	return &contracts.InputError{Reason: contracts.ReasonIO, Err: errors.New("confined input access requires Linux")}
}
