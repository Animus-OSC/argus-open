// Package core orchestrates policy-governed work through replaceable adapters.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/policy"
	"github.com/Animus-OSC/argus-open/pkg/evidence"
)

type Engine struct {
	Events    v1.EventVerifier
	Projects  v1.ProjectRegistry
	Model     v1.ModelProvider
	Snapshots v1.Snapshotter
	Worker    v1.Worker
	Store     v1.TaskStore
}

// Run never lets the model choose a shell, change policy, or declare a result.
// Unknown completion retains the task-store fence and is not retried.
func (e Engine) Run(ctx context.Context, task v1.Task) v1.Outcome {
	if e.Events == nil || e.Projects == nil || e.Model == nil || e.Snapshots == nil || e.Worker == nil || e.Store == nil ||
		!policy.ValidTask(task) || e.Events.Verify(ctx, task) != nil {
		return blocked("invalid_or_unverified_event")
	}
	p, err := e.Projects.Lookup(ctx, task.TenantID, task.ProjectID)
	if err != nil || p.Version != v1.ProjectVersion || p.TenantID != task.TenantID || p.ProjectID != task.ProjectID || p.SourceSHA != task.SourceSHA ||
		p.RequiredOperation != v1.UnitOperation || p.PolicyVersion == "" || len(p.PolicyVersion) > 128 ||
		p.SourceRef == "" || len(p.SourceRef) > 4096 || !policy.ValidDigest(p.ModelDigest) {
		return blocked("project_policy_or_source_denied")
	}
	if err := e.Store.Claim(ctx, task); err != nil {
		if errors.Is(err, v1.ErrUncertain) {
			return uncertain("existing_or_incomplete_execution")
		}
		return blocked("duplicate_or_store_unavailable")
	}
	abort := func(reason string) v1.Outcome {
		abortCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e.Store.FinishWithoutEvidence(abortCtx, task) != nil {
			return uncertain("admission_release_failed")
		}
		return blocked(reason)
	}
	if e.Model.ContractVersion() != "argus.model/v1" {
		return abort("model_contract_unsupported")
	}
	modelCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	caps, err := e.Model.Capabilities(modelCtx)
	if err != nil || !caps.LocalOnly || !caps.StructuredOutput || !caps.Cancellation ||
		caps.MaxInputBytes < 256 || caps.MaxOutputBytes < 1 || caps.MaxConcurrent < 1 ||
		caps.MaxContextTokens < 1 || caps.MaxOutputTokens < 1 || caps.MaxOutputTokens > caps.MaxContextTokens {
		return abort("model_capabilities_unavailable")
	}
	identity, err := e.Model.Health(modelCtx)
	if err != nil || identity.Digest != p.ModelDigest || identity.Provider == "" {
		return abort("model_unavailable_or_identity_mismatch")
	}
	limit := min(8192, caps.MaxOutputBytes)
	request := v1.PlanRequest{TenantID: task.TenantID, ProjectID: task.ProjectID,
		SourceSHA: task.SourceSHA, MaxResponseBytes: limit, MaxOutputTokens: min(256, caps.MaxOutputTokens)}
	encodedRequest, err := json.Marshal(request)
	if err != nil || len(encodedRequest) > caps.MaxInputBytes {
		return abort("model_context_limit")
	}
	response, err := e.Model.Plan(modelCtx, request)
	if err != nil || response.Identity != identity || len(response.Plan) > limit ||
		response.Usage.OutputBytes != int64(len(response.Plan)) {
		return abort("model_plan_unavailable")
	}
	op, err := policy.ParsePlan(response.Plan, p.RequiredOperation)
	if err != nil {
		return abort("plan_denied")
	}
	snapshot, cleanup, err := e.Snapshots.Prepare(ctx, p)
	if err != nil || cleanup == nil {
		return abort("source_unavailable")
	}
	defer cleanup()
	if snapshot.Version != v1.SnapshotVersion || snapshot.SourceSHA != task.SourceSHA || snapshot.Ref == "" {
		return abort("source_identity_mismatch")
	}
	observation, err := e.Worker.Execute(ctx, snapshot, op)
	if err != nil {
		if errors.Is(err, v1.ErrUncertain) {
			return uncertain("worker_outcome_unknown")
		}
		if errors.Is(err, v1.ErrNoTests) {
			return uncertain("no_tests_after_worker_started")
		}
		if errors.Is(err, v1.ErrIncomplete) {
			return uncertain("tests_incomplete_after_worker_started")
		}
		if errors.Is(err, v1.ErrUnavailable) || errors.Is(err, v1.ErrDenied) {
			return abort("worker_unavailable_or_denied")
		}
		return uncertain("worker_outcome_unknown")
	}
	if observation.Operation != op.ID || observation.ExitCode < 0 || observation.ExitCode > 255 {
		return uncertain("invalid_worker_observation")
	}
	state := v1.Fail
	if observation.ExitCode == 0 {
		state = v1.Pass
	}
	receipt := v1.Receipt{Version: v1.ReceiptVersion, TaskID: task.TaskID, TenantID: task.TenantID,
		ProjectID: task.ProjectID, SourceSHA: task.SourceSHA, IdempotencyKey: task.IdempotencyKey,
		EventSHA256: evidence.TaskDigest(task), PolicyVersion: p.PolicyVersion,
		Model: identity, Observation: observation, State: state}
	envelope, err := evidence.Seal(receipt)
	if err != nil || evidence.Verify(envelope, envelope.SHA256) != nil {
		return uncertain("evidence_invalid")
	}
	if err := e.Store.Complete(ctx, task, envelope); err != nil {
		return uncertain("evidence_not_durable")
	}
	return v1.Outcome{State: state, Receipt: &envelope}
}

func blocked(reason string) v1.Outcome   { return v1.Outcome{State: v1.Blocked, Reason: reason} }
func uncertain(reason string) v1.Outcome { return v1.Outcome{State: v1.Uncertain, Reason: reason} }
