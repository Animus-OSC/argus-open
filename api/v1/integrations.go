package v1

import "context"

// ForgeAdapter authenticates and normalizes provider-specific input. A
// normalized event still passes project policy and admission independently.
type ForgeAdapter interface {
	ContractVersion() string
	VerifyAndNormalize(context.Context, []byte) (Task, error)
}

type ScopedStatus struct {
	TenantID, ProjectID, TaskID, SourceSHA string
	State                                  State
	EvidenceDigest                         string
}

// CIStatusAdapter requires its own authorization and never alters a verdict.
// No live forge or status publisher is included in this synthetic slice.
type CIStatusAdapter interface {
	ContractVersion() string
	Publish(context.Context, ScopedStatus) error
}

// ArtifactStore must enforce authenticated tenant/project scope and verify
// the expected digest. No distributed artifact store is implemented here.
type ArtifactStore interface {
	ContractVersion() string
	Put(context.Context, string, string, Envelope) error
	Get(context.Context, string, string, string) (Envelope, error)
}
