//go:build !linux

// Package worker fails closed on platforms without the synthetic Linux worker.
package worker

import (
	"context"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

type Bwrap struct{ WorkspaceRoot string }

func (Bwrap) Execute(context.Context, v1.Snapshot, v1.Operation) (v1.Observation, error) {
	return v1.Observation{}, v1.ErrUnavailable
}
