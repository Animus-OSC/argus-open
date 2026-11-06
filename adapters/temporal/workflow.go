// Package temporaladapter keeps Temporal-specific orchestration outside core.
// It does not dial a server or start a worker on import.
package temporaladapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/policy"
	"github.com/Animus-OSC/argus-open/pkg/core"
	"github.com/Animus-OSC/argus-open/pkg/evidence"
	enums "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

const (
	WorkflowName     = "argus.synthetic.qa.v1"
	ActivityName     = "argus.synthetic.execute.v1"
	DefaultTaskQueue = "argus-synthetic-v1"
)

// Workflow replays deterministic orchestration. An activity failure or timeout
// may hide an already executed process, so it becomes UNCERTAIN and is never
// automatically retried. A real Temporal service is not part of the demo.
func Workflow(ctx workflow.Context, task v1.Task) (v1.Outcome, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    45 * time.Second,
		ScheduleToCloseTimeout: 60 * time.Second,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var result v1.Outcome
	if err := workflow.ExecuteActivity(ctx, ActivityName, task).Get(ctx, &result); err != nil {
		return v1.Outcome{State: v1.Uncertain, Reason: "temporal_activity_outcome_unknown"}, nil
	}
	switch result.State {
	case v1.Pass, v1.Fail:
		if result.Receipt == nil || evidence.Verify(*result.Receipt, result.Receipt.SHA256) != nil ||
			result.Receipt.Receipt.State != result.State || result.Receipt.Receipt.TaskID != task.TaskID ||
			result.Receipt.Receipt.TenantID != task.TenantID || result.Receipt.Receipt.ProjectID != task.ProjectID ||
			result.Receipt.Receipt.SourceSHA != task.SourceSHA || result.Receipt.Receipt.IdempotencyKey != task.IdempotencyKey ||
			result.Receipt.Receipt.EventSHA256 != evidence.TaskDigest(task) {
			return v1.Outcome{State: v1.Uncertain, Reason: "temporal_evidence_invalid"}, nil
		}
	case v1.Blocked, v1.NotRun, v1.Uncertain:
		if result.Receipt != nil {
			return v1.Outcome{State: v1.Uncertain, Reason: "temporal_evidence_invalid"}, nil
		}
	default:
		return v1.Outcome{State: v1.Uncertain, Reason: "temporal_outcome_invalid"}, nil
	}
	return result, nil
}

type Activities struct{ Engine core.Engine }

func (a Activities) Execute(ctx context.Context, task v1.Task) (v1.Outcome, error) {
	return a.Engine.Run(ctx, task), nil
}

func Register(w worker.Worker, engine core.Engine) {
	w.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: WorkflowName})
	w.RegisterActivityWithOptions(Activities{Engine: engine}.Execute, activity.RegisterOptions{Name: ActivityName})
}

// WorkflowID avoids placing user-supplied identifiers directly in the ID.
func WorkflowID(task v1.Task) string {
	b, _ := json.Marshal([]string{task.TenantID, task.ProjectID, task.TaskID})
	h := sha256.Sum256(b)
	return "argus-v1-" + hex.EncodeToString(h[:])
}

// Start requires an already authorized client. It does not construct a
// network client or silently connect to a local/remote Temporal service.
func Start(ctx context.Context, c client.Client, task v1.Task, queue string) (client.WorkflowRun, error) {
	if c == nil || !policy.ValidTask(task) || !policy.ValidIdentifier(queue) {
		return nil, v1.ErrDenied
	}
	return c.ExecuteWorkflow(ctx, StartOptions(task, queue), WorkflowName, task)
}

func StartOptions(task v1.Task, queue string) client.StartWorkflowOptions {
	return client.StartWorkflowOptions{
		ID: WorkflowID(task), TaskQueue: queue,
		WorkflowExecutionTimeout:                 2 * time.Minute,
		WorkflowIDReusePolicy:                    enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy:                 enums.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}
}
