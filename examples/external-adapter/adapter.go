// Package example shows how a separate project can inject Argus contracts.
// It is a compile-only integration example, not an authorized worker or forge.
package example

import (
	"context"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/pkg/core"
)

type Adapters struct {
	Events    v1.EventVerifier
	Projects  v1.ProjectRegistry
	Model     v1.ModelProvider
	Snapshots v1.Snapshotter
	Worker    v1.Worker
	Store     v1.TaskStore
}

func Handle(ctx context.Context, adapters Adapters, event v1.Task) v1.Outcome {
	engine := core.Engine{Events: adapters.Events, Projects: adapters.Projects,
		Model: adapters.Model, Snapshots: adapters.Snapshots,
		Worker: adapters.Worker, Store: adapters.Store}
	return engine.Run(ctx, event)
}
