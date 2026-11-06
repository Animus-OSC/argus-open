// Package profile runs a single reviewed, source-pinned local SDK unit profile.
// It is not an arbitrary-project, multi-tenant or authenticated remote worker.
package profile

import "time"

type execution struct {
	Started    bool
	ExitCode   int
	TimedOut   bool
	Cancelled  bool
	Uncertain  bool
	Truncated  bool
	Stdout     []byte
	Stderr     []byte
	StartedAt  time.Time
	FinishedAt time.Time
}
