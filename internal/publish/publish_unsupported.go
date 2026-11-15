//go:build !linux

// Package publish provides atomic no-replace publication on Linux.
package publish

import (
	"context"
	"errors"
	"os"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

type Transaction struct{}

func Begin(context.Context, os.FileInfo, string) (*Transaction, error) {
	return nil, unsupported()
}
func (*Transaction) Dir() string                   { return "" }
func (*Transaction) OutputDir() string             { return "" }
func (*Transaction) Published() bool               { return false }
func (*Transaction) Publish(context.Context) error { return unsupported() }
func (*Transaction) Cleanup() error                { return nil }
func unsupported() error {
	return &contracts.RunError{Stage: contracts.StagePublication, Reason: contracts.ReasonUnsupportedPublication, Err: errors.New("atomic no-replace publication requires Linux")}
}
