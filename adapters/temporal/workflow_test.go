package temporaladapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/internal/store"
	"github.com/Animus-OSC/argus-open/internal/synthetic"
	argusworker "github.com/Animus-OSC/argus-open/internal/worker"
	"github.com/Animus-OSC/argus-open/pkg/core"
	enums "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
)

func TestWorkflowRunsActualOfflineSliceInSDKTestEnvironment(t *testing.T) {
	p, task, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant", "project")
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.NewLocal(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	engine := core.Engine{Events: synthetic.EventVerifier{}, Projects: synthetic.Registry{Projects: []v1.Project{p}},
		Model: synthetic.FakeModel{}, Snapshots: source.GitArchive{Root: staging}, Worker: argusworker.Bwrap{WorkspaceRoot: staging}, Store: s}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(Activities{Engine: engine}.Execute, activity.RegisterOptions{Name: ActivityName})
	env.ExecuteWorkflow(Workflow, task)
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var out v1.Outcome
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatal(err)
	}
	if out.State == v1.Blocked && out.Reason == "worker_unavailable_or_denied" && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("Bubblewrap unavailable")
	}
	if out.State != v1.Pass || out.Receipt == nil || out.Receipt.Receipt.Observation.TestsRun != 2 {
		t.Fatalf("unexpected synthetic workflow result: %+v", out)
	}
}

func TestActivityFailureIsUncertainAndNotRetried(t *testing.T) {
	var calls atomic.Int32
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(func(context.Context, v1.Task) (v1.Outcome, error) {
		calls.Add(1)
		return v1.Outcome{}, errors.New("lost completion")
	}, activity.RegisterOptions{Name: ActivityName})
	env.ExecuteWorkflow(Workflow, v1.Task{TaskID: "task"})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var result v1.Outcome
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatal(err)
	}
	if result.State != v1.Uncertain || calls.Load() != 1 {
		t.Fatalf("unsafe retry: %+v, calls=%d", result, calls.Load())
	}
}

func TestWorkflowRejectsPassWithoutEvidence(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(func(context.Context, v1.Task) (v1.Outcome, error) {
		return v1.Outcome{State: v1.Pass}, nil
	}, activity.RegisterOptions{Name: ActivityName})
	env.ExecuteWorkflow(Workflow, v1.Task{TaskID: "task"})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var result v1.Outcome
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatal(err)
	}
	if result.State != v1.Uncertain || result.Reason != "temporal_evidence_invalid" {
		t.Fatalf("unverified pass accepted: %+v", result)
	}
}

func TestWorkflowIDAndReusePolicy(t *testing.T) {
	a := v1.Task{TenantID: "a", ProjectID: "project", TaskID: "task"}
	b := a
	b.TenantID = "b"
	if WorkflowID(a) == WorkflowID(b) || WorkflowID(a) != WorkflowID(a) {
		t.Fatal("workflow identity not stable or isolated")
	}
	opts := StartOptions(a, DefaultTaskQueue)
	if opts.WorkflowIDReusePolicy != enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE ||
		opts.WorkflowIDConflictPolicy != enums.WORKFLOW_ID_CONFLICT_POLICY_FAIL || !opts.WorkflowExecutionErrorWhenAlreadyStarted || opts.TaskQueue != DefaultTaskQueue || opts.WorkflowExecutionTimeout <= 0 {
		t.Fatal("workflow reuse not fenced")
	}
	if _, err := Start(context.Background(), nil, a, "../unsafe"); !errors.Is(err, v1.ErrDenied) {
		t.Fatal("invalid start accepted")
	}
}
