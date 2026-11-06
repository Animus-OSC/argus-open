package core_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	syntheticproject "github.com/Animus-OSC/argus-open/examples/synthetic-project"
	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/internal/store"
	"github.com/Animus-OSC/argus-open/internal/synthetic"
	"github.com/Animus-OSC/argus-open/internal/worker"
	"github.com/Animus-OSC/argus-open/pkg/core"
	"github.com/Animus-OSC/argus-open/pkg/evidence"
)

func setup(t *testing.T) (v1.Project, v1.Task, *store.Local) {
	t.Helper()
	p, task, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.NewLocal(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	return p, task, s
}

func engine(t *testing.T, p v1.Project, s *store.Local, m v1.ModelProvider, w v1.Worker) core.Engine {
	t.Helper()
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.(worker.Bwrap); ok {
		w = worker.Bwrap{WorkspaceRoot: root}
	}
	return core.Engine{Events: synthetic.EventVerifier{}, Projects: synthetic.Registry{Projects: []v1.Project{p}},
		Model: m, Snapshots: source.GitArchive{Root: root}, Worker: w, Store: s}
}

func TestOfflineEndToEndAndDuplicate(t *testing.T) {
	p, task, s := setup(t)
	e := engine(t, p, s, synthetic.FakeModel{}, worker.Bwrap{})
	out := e.Run(context.Background(), task)
	if out.State == v1.Blocked && out.Reason == "worker_unavailable_or_denied" && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("Bubblewrap sandbox unavailable")
	}
	if out.State != v1.Pass || out.Receipt == nil {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	if out.Receipt.Receipt.SourceSHA != task.SourceSHA || out.Receipt.Receipt.Observation.ExitCode != 0 ||
		out.Receipt.Receipt.Observation.TestsRun != 2 || evidence.Verify(*out.Receipt, out.Receipt.SHA256) != nil {
		t.Fatal("receipt does not bind actual scoped execution")
	}
	if again := e.Run(context.Background(), task); again.State != v1.Blocked || again.Receipt != nil {
		t.Fatalf("duplicate executed: %+v", again)
	}
}

func TestActualFailingTestProducesFail(t *testing.T) {
	p, task, s := setup(t)
	path := filepath.Join(p.SourceRef, "calculator.py")
	if err := os.WriteFile(path, []byte(syntheticproject.FailingCalculator), 0600); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", args...)
		cmd.Dir = p.SourceRef
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	git("add", "--all")
	git("-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "synthetic failure")
	p.SourceSHA = git("rev-parse", "HEAD")
	task.SourceSHA = p.SourceSHA
	task.Signature = synthetic.Sign(task)
	out := engine(t, p, s, synthetic.FakeModel{}, worker.Bwrap{}).Run(context.Background(), task)
	if out.State == v1.Blocked && out.Reason == "worker_unavailable_or_denied" && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("Bubblewrap unavailable")
	}
	if out.State != v1.Fail || out.Receipt == nil || out.Receipt.Receipt.Observation.ExitCode != 1 || out.Receipt.Receipt.Observation.TestsRun != 2 {
		t.Fatalf("test failure was not preserved: %+v", out)
	}
}

func TestFilteredCommitCannotProducePass(t *testing.T) {
	p, task, ledger := setup(t)
	for name, data := range map[string]string{
		".gitattributes": ".gitattributes export-ignore\nconcealed.py export-ignore\n",
		"concealed.py":   "# synthetic concealed content\n",
	} {
		if err := os.WriteFile(filepath.Join(p.SourceRef, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", args...)
		cmd.Dir = p.SourceRef
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	git("add", "--all")
	git("-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "filtered commit probe")
	p.SourceSHA = git("rev-parse", "HEAD")
	task.SourceSHA = p.SourceSHA
	task.Signature = synthetic.Sign(task)
	w := &countWorker{err: v1.ErrUnavailable}
	out := engine(t, p, ledger, synthetic.FakeModel{}, w).Run(context.Background(), task)
	if out.State != v1.Blocked || out.Reason != "source_unavailable" || out.Receipt != nil || w.calls.Load() != 0 {
		t.Fatalf("filtered source reached execution: %+v", out)
	}
}

type countWorker struct {
	calls atomic.Int32
	err   error
}

func (w *countWorker) Execute(context.Context, v1.Snapshot, v1.Operation) (v1.Observation, error) {
	w.calls.Add(1)
	return v1.Observation{}, w.err
}

func TestUnverifiedEventsAndCrossTenantAreDeniedBeforeExecution(t *testing.T) {
	p, task, _ := setup(t)
	for name, mutate := range map[string]func(*v1.Task){
		"invalid signature": func(t *v1.Task) { t.Signature = strings.Repeat("0", 64) },
		"other tenant":      func(t *v1.Task) { t.TenantID = "tenant-b"; t.Signature = synthetic.Sign(*t) },
		"unknown project":   func(t *v1.Task) { t.ProjectID = "other"; t.Signature = synthetic.Sign(*t) },
		"wrong commit":      func(t *v1.Task) { t.SourceSHA = strings.Repeat("a", 40); t.Signature = synthetic.Sign(*t) },
		"path traversal":    func(t *v1.Task) { t.TaskID = "../escape"; t.Signature = synthetic.Sign(*t) },
	} {
		t.Run(name, func(t *testing.T) {
			fresh, err := store.NewLocal(filepath.Join(t.TempDir(), "ledger"))
			if err != nil {
				t.Fatal(err)
			}
			w := &countWorker{err: v1.ErrUnavailable}
			bad := task
			mutate(&bad)
			out := engine(t, p, fresh, synthetic.FakeModel{}, w).Run(context.Background(), bad)
			if out.State != v1.Blocked || w.calls.Load() != 0 {
				t.Fatalf("unauthorized execution: %+v", out)
			}
		})
	}
}

func TestModelCannotChooseShellOrOverridePolicy(t *testing.T) {
	p, task, _ := setup(t)
	models := map[string]synthetic.FakeModel{
		"shell":            {Response: []byte(`{"version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1","shell":"touch /tmp/argus-injected"}]}`)},
		"missing required": {Response: []byte(`{"version":"argus.plan/v1","operations":[]}`)},
		"unavailable":      {Err: errors.New("offline")},
		"wrong digest":     {Identity: v1.ModelIdentity{Provider: "fake", Digest: "sha256:" + strings.Repeat("0", 64)}},
		"identity drift":   {ResponseIdentity: v1.ModelIdentity{Provider: "fake", Digest: "sha256:" + strings.Repeat("0", 64)}},
	}
	for name, model := range models {
		t.Run(name, func(t *testing.T) {
			s, err := store.NewLocal(filepath.Join(t.TempDir(), "ledger"))
			if err != nil {
				t.Fatal(err)
			}
			w := &countWorker{err: v1.ErrUnavailable}
			out := engine(t, p, s, model, w).Run(context.Background(), task)
			if out.State != v1.Blocked || w.calls.Load() != 0 {
				t.Fatalf("model bypassed policy: %+v", out)
			}
		})
	}
}

func TestUncertainExecutionRetainsFenceAfterReopen(t *testing.T) {
	p, task, _ := setup(t)
	root := filepath.Join(t.TempDir(), "ledger")
	s, err := store.NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	w := &countWorker{err: v1.ErrUncertain}
	out := engine(t, p, s, synthetic.FakeModel{}, w).Run(context.Background(), task)
	if out.State != v1.Uncertain || w.calls.Load() != 1 {
		t.Fatalf("uncertain outcome lost: %+v", out)
	}
	reopened, err := store.NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	again := engine(t, p, reopened, synthetic.FakeModel{}, w).Run(context.Background(), task)
	if again.State != v1.Uncertain || w.calls.Load() != 1 {
		t.Fatalf("uncertain task retried: %+v", again)
	}
}

type slowModel struct{ synthetic.FakeModel }

func (slowModel) Plan(ctx context.Context, _ v1.PlanRequest) (v1.ModelResponse, error) {
	<-ctx.Done()
	return v1.ModelResponse{}, ctx.Err()
}

func TestModelCancellationDoesNotStartWorker(t *testing.T) {
	p, task, s := setup(t)
	w := &countWorker{err: v1.ErrUnavailable}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	out := engine(t, p, s, slowModel{}, w).Run(ctx, task)
	if out.State != v1.Blocked || w.calls.Load() != 0 {
		t.Fatalf("canceled model started worker: %+v", out)
	}
	other := task
	other.TaskID = "task-2"
	other.IdempotencyKey = "key-2"
	other.Signature = synthetic.Sign(other)
	if err := s.Claim(context.Background(), other); err != nil {
		t.Fatalf("safe pre-execution cancellation kept slot: %v", err)
	}
}

type incompleteSideEffectWorker struct {
	marker string
	err    error
}

func (w incompleteSideEffectWorker) Execute(context.Context, v1.Snapshot, v1.Operation) (v1.Observation, error) {
	if err := os.WriteFile(w.marker, []byte("synthetic side effect"), 0600); err != nil {
		return v1.Observation{}, err
	}
	return v1.Observation{}, w.err
}

func TestIncompleteExecutionRetainsFence(t *testing.T) {
	for name, workerErr := range map[string]error{
		"no-tests":              v1.ErrNoTests,
		"incomplete":            v1.ErrIncomplete,
		"uncertain-unavailable": errors.Join(v1.ErrUncertain, v1.ErrUnavailable),
		"uncertain-denied":      errors.Join(v1.ErrUncertain, v1.ErrDenied),
	} {
		t.Run(name, func(t *testing.T) {
			p, task, ledger := setup(t)
			marker := filepath.Join(t.TempDir(), "synthetic-effect")
			out := engine(t, p, ledger, synthetic.FakeModel{}, incompleteSideEffectWorker{marker: marker, err: workerErr}).Run(context.Background(), task)
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("synthetic worker did not start")
			}
			if out.State != v1.Uncertain {
				t.Fatalf("incomplete execution lost uncertainty: %+v", out)
			}
			next := task
			next.TaskID, next.IdempotencyKey = "next-task", "next-key"
			next.Signature = synthetic.Sign(next)
			if err := ledger.Claim(context.Background(), next); !errors.Is(err, v1.ErrCapacity) {
				t.Fatalf("uncertain execution released its fence: %v", err)
			}
		})
	}
}
