// Package v1 defines the provider-neutral contracts for the synthetic slice.
package v1

import (
	"context"
	"time"
)

const (
	TaskVersion     = "argus.task/v1"
	PlanVersion     = "argus.plan/v1"
	ReceiptVersion  = "argus.receipt/v1"
	ProjectVersion  = "argus.project/v1"
	SnapshotVersion = "argus.snapshot/v1"
	UnitOperation   = "synthetic-python-unit/v1"
)

type State string

const (
	Pass      State = "PASS"
	Fail      State = "FAIL"
	Blocked   State = "BLOCKED"
	NotRun    State = "NOT_RUN"
	Uncertain State = "UNCERTAIN"
)

// Task is an untrusted event until an EventVerifier authenticates its fields.
type Task struct {
	Version        string `json:"version"`
	TaskID         string `json:"task_id"`
	TenantID       string `json:"tenant_id"`
	ProjectID      string `json:"project_id"`
	SourceSHA      string `json:"source_sha"`
	IdempotencyKey string `json:"idempotency_key"`
	Signature      string `json:"signature"`
}

type Project struct {
	Version           string `json:"version"`
	TenantID          string `json:"tenant_id"`
	ProjectID         string `json:"project_id"`
	SourceRef         string `json:"source_ref"`
	SourceSHA         string `json:"source_sha"`
	PolicyVersion     string `json:"policy_version"`
	RequiredOperation string `json:"required_operation"`
	ModelDigest       string `json:"model_digest"`
}

// Snapshot.Ref is opaque to the control plane: it may name a local disposable
// tree or a future content-addressed remote artifact, depending on the adapter.
type Snapshot struct {
	Version   string `json:"version"`
	SourceSHA string `json:"source_sha"`
	Ref       string `json:"ref"`
}

type PlanRequest struct {
	TenantID, ProjectID, SourceSHA string
	MaxResponseBytes               int
	MaxOutputTokens                int
}

type ModelCapabilities struct {
	LocalOnly, StructuredOutput, Cancellation    bool
	MaxInputBytes, MaxOutputBytes, MaxConcurrent int
	MaxContextTokens, MaxOutputTokens            int
}

type ModelUsage struct {
	InputBytes, OutputBytes, InputTokens, OutputTokens, DurationMillis, PeakMemoryBytes int64
}

type ModelResponse struct {
	Identity ModelIdentity
	Plan     []byte
	Usage    ModelUsage
}

type ModelIdentity struct {
	Provider string `json:"provider"`
	Digest   string `json:"digest"`
}

type ModelProvider interface {
	ContractVersion() string
	Capabilities(context.Context) (ModelCapabilities, error)
	Health(context.Context) (ModelIdentity, error)
	Plan(context.Context, PlanRequest) (ModelResponse, error)
}

type EventVerifier interface {
	Verify(context.Context, Task) error
}

type ProjectRegistry interface {
	Lookup(context.Context, string, string) (Project, error)
}

type Snapshotter interface {
	Prepare(context.Context, Project) (snapshot Snapshot, cleanup func(), err error)
}

type Plan struct {
	Version    string      `json:"version"`
	Operations []Operation `json:"operations"`
}

type Operation struct {
	ID string `json:"id"`
}

// Observation is produced only after a real worker process exits and the
// synthetic test harness reports that at least one test completed.
type Observation struct {
	Operation    string    `json:"operation"`
	Worker       string    `json:"worker"`
	ExitCode     int       `json:"exit_code"`
	TestsRun     int       `json:"tests_run"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	OutputSHA256 string    `json:"output_sha256"`
}

// Worker is a trusted adapter boundary. ErrUnavailable and ErrDenied mean no
// subprocess or side effect started; adapters must return ErrUncertain when
// they cannot prove that. ErrNoTests and ErrIncomplete can occur after code
// execution and therefore do not authorize releasing an execution fence.
type Worker interface {
	Execute(context.Context, Snapshot, Operation) (Observation, error)
}

// TaskStore owns idempotency and fencing. Implementations must not release an
// uncertain execution merely because a lease expires or a process restarts.
type TaskStore interface {
	Claim(context.Context, Task) error
	FinishWithoutEvidence(context.Context, Task) error
	Complete(context.Context, Task, Envelope) error
}

type Receipt struct {
	Version        string        `json:"version"`
	TaskID         string        `json:"task_id"`
	TenantID       string        `json:"tenant_id"`
	ProjectID      string        `json:"project_id"`
	SourceSHA      string        `json:"source_sha"`
	IdempotencyKey string        `json:"idempotency_key"`
	EventSHA256    string        `json:"event_sha256"`
	PolicyVersion  string        `json:"policy_version"`
	Model          ModelIdentity `json:"model"`
	Observation    Observation   `json:"observation"`
	State          State         `json:"state"`
}

type Envelope struct {
	Receipt Receipt `json:"receipt"`
	SHA256  string  `json:"sha256"`
}

type Outcome struct {
	State   State     `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Receipt *Envelope `json:"evidence,omitempty"`
}
