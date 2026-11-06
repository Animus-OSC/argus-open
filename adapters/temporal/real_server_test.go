//go:build temporal_integration && linux

package temporaladapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/internal/store"
	"github.com/Animus-OSC/argus-open/internal/synthetic"
	argusworker "github.com/Animus-OSC/argus-open/internal/worker"
	"github.com/Animus-OSC/argus-open/pkg/core"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	temporalworker "go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

const temporalCLIHash = "6968c86c97d91d4b49e19c0c9b0842bfb5eb2d356f22b989006d1e09164eab5b"

// This test requires an explicitly supplied pinned dev-server binary and a
// network namespace containing loopback only. It never touches an existing server.
func TestTemporalDevServerRestartsWithPendingWorkflow(t *testing.T) {
	bin := os.Getenv("ARGUS_TEMPORAL_BIN")
	if bin == "" {
		if os.Getenv("ARGUS_REQUIRE_TEMPORAL") == "1" {
			t.Fatal("ARGUS_TEMPORAL_BIN is required")
		}
		t.Skip("pinned Temporal development server not supplied")
	}
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != temporalCLIHash {
		t.Fatal("unexpected Temporal CLI digest")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("test requires an isolated network namespace with only loopback up")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	dir := t.TempDir()
	db := filepath.Join(dir, "temporal.db")
	startServer := func() (*exec.Cmd, chan error) {
		cmd := exec.Command("/usr/bin/nice", "-n", "15", bin, "server", "start-dev", "--headless", "--ip", "127.0.0.1", "--port", strconv.Itoa(port), "--db-filename", db)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "GOMAXPROCS=2", "GOMEMLIMIT=512MiB"}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		return cmd, done
	}
	stopServer := func(cmd *exec.Cmd, done chan error) {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("Temporal dev server did not stop")
		}
	}
	dial := func() client.Client {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			c, err := client.DialContext(ctx, client.Options{HostPort: address, Identity: "argus-synthetic-devtest"})
			cancel()
			if err == nil {
				return c
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("isolated Temporal dev server did not start")
		return nil
	}
	cmd, done := startServer()
	serverRunning := true
	defer func() {
		if serverRunning {
			stopServer(cmd, done)
		}
	}()
	c := dial()
	p, task, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-temporal", "project-temporal")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	run, err := Start(ctx, c, task, DefaultTaskQueue)
	if err != nil {
		t.Fatal(err)
	}
	workflowID, runID := run.GetID(), run.GetRunID()
	c.Close()
	stopServer(cmd, done)
	serverRunning = false
	cmd, done = startServer()
	serverRunning = true
	c = dial()
	defer c.Close()
	ledger, err := store.NewLocal(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	engine := core.Engine{Events: synthetic.EventVerifier{}, Projects: synthetic.Registry{Projects: []v1.Project{p}},
		Model: synthetic.FakeModel{}, Snapshots: source.GitArchive{Root: staging}, Worker: argusworker.Bwrap{WorkspaceRoot: staging}, Store: ledger}
	w := temporalworker.New(c, DefaultTaskQueue, temporalworker.Options{MaxConcurrentActivityExecutionSize: 1})
	Register(w, engine)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	var result v1.Outcome
	if err := c.GetWorkflow(ctx, workflowID, runID).Get(ctx, &result); err != nil {
		w.Stop()
		t.Fatal(err)
	}
	if result.State != v1.Pass || result.Receipt == nil || result.Receipt.Receipt.Observation.TestsRun != 2 {
		w.Stop()
		t.Fatalf("persisted workflow did not resume to real test evidence: %+v", result)
	}
	if _, err := Start(ctx, c, task, DefaultTaskQueue); err == nil {
		w.Stop()
		t.Fatal("completed workflow ID reused")
	}
	exerciseConcurrentIdempotency(t, ctx, c, task, engine)
	w.Stop()
	t.Logf("pending workflow %s/%s resumed after the synthetic server restart", workflowID, runID)
	exerciseWorkerCrash(t, c, task, dir, address)
}

type gatedSyntheticWorker struct {
	inner   v1.Worker
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedSyntheticWorker) Execute(ctx context.Context, snapshot v1.Snapshot, op v1.Operation) (v1.Observation, error) {
	w.once.Do(func() { close(w.started) })
	select {
	case <-ctx.Done():
		return v1.Observation{}, v1.ErrUncertain
	case <-w.release:
		return w.inner.Execute(ctx, snapshot, op)
	}
}

func exerciseConcurrentIdempotency(t *testing.T, ctx context.Context, c client.Client, task v1.Task, engine core.Engine) {
	t.Helper()
	gate := &gatedSyntheticWorker{inner: engine.Worker, started: make(chan struct{}), release: make(chan struct{})}
	engine.Worker = gate
	const queue = "argus-synthetic-concurrency-v1"
	w := temporalworker.New(c, queue, temporalworker.Options{MaxConcurrentActivityExecutionSize: 2})
	Register(w, engine)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	defer func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}()
	first := task
	first.TaskID, first.IdempotencyKey = "temporal-concurrency-a", "temporal-shared-key"
	first.Signature = synthetic.Sign(first)
	second := first
	second.TaskID = "temporal-concurrency-b"
	second.Signature = synthetic.Sign(second)
	a, err := Start(ctx, c, first, queue)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.started:
	case <-ctx.Done():
		t.Fatal("first synthetic activity did not reach the execution gate")
	}
	b, err := Start(ctx, c, second, queue)
	if err != nil {
		t.Fatal(err)
	}
	var blocked v1.Outcome
	if err := b.Get(ctx, &blocked); err != nil || blocked.State != v1.Blocked {
		t.Fatalf("concurrent task sharing the key was not blocked: %+v %v", blocked, err)
	}
	close(gate.release)
	var passed v1.Outcome
	if err := a.Get(ctx, &passed); err != nil || passed.State != v1.Pass || passed.Receipt == nil {
		t.Fatalf("admitted synthetic task did not complete: %+v %v", passed, err)
	}
	third := first
	third.TaskID = "temporal-concurrency-c"
	third.Signature = synthetic.Sign(third)
	cRun, err := Start(ctx, c, third, queue)
	if err != nil {
		t.Fatal(err)
	}
	if err := cRun.Get(ctx, &blocked); err != nil || blocked.State != v1.Blocked {
		t.Fatalf("completed idempotency key was reused: %+v %v", blocked, err)
	}
	t.Logf("concurrent shared-key workflows %s and %s yielded one PASS and one BLOCKED; later reuse was blocked", a.GetRunID(), b.GetRunID())
}

func exerciseWorkerCrash(t *testing.T, c client.Client, task v1.Task, dir, address string) {
	t.Helper()
	ready := filepath.Join(dir, "worker-ready")
	marker := filepath.Join(dir, "synthetic-side-effect")
	child := exec.Command(os.Args[0], "-test.run=^TestTemporalWorkerCrashHelper$")
	child.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "GOMAXPROCS=2",
		"ARGUS_TEMPORAL_HELPER=1", "ARGUS_TEMPORAL_ADDRESS=" + address, "ARGUS_HELPER_READY=" + ready, "ARGUS_HELPER_MARKER=" + marker}
	child.Stdout, child.Stderr = io.Discard, io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childRunning := true
	defer func() {
		if childRunning {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	waitFile := func(path string) {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("synthetic worker did not create %s", filepath.Base(path))
	}
	waitFile(ready)
	task.TaskID, task.IdempotencyKey = "temporal-crash-task", "temporal-crash-key"
	task.Signature = synthetic.Sign(task)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	run, err := Start(ctx, c, task, DefaultTaskQueue)
	if err != nil {
		t.Fatal(err)
	}
	waitFile(marker)
	if _, err := Start(ctx, c, task, DefaultTaskQueue); err == nil {
		t.Fatal("running workflow ID reused")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	childRunning = false
	var attempts atomic.Int32
	w := temporalworker.New(c, DefaultTaskQueue, temporalworker.Options{MaxConcurrentActivityExecutionSize: 1})
	w.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: WorkflowName})
	w.RegisterActivityWithOptions(func(context.Context, v1.Task) (v1.Outcome, error) {
		attempts.Add(1)
		return v1.Outcome{State: v1.Blocked}, nil
	}, activity.RegisterOptions{Name: ActivityName})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	var result v1.Outcome
	if err := run.Get(ctx, &result); err != nil {
		t.Fatal(err)
	}
	if result.State != v1.Uncertain || attempts.Load() != 0 {
		t.Fatalf("lost activity was retried: %+v attempts=%d", result, attempts.Load())
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "once" {
		t.Fatal("synthetic side effect missing or changed")
	}
	t.Logf("lost activity for %s/%s remained UNCERTAIN and was not retried", run.GetID(), run.GetRunID())
}

func TestTemporalWorkerCrashHelper(t *testing.T) {
	if os.Getenv("ARGUS_TEMPORAL_HELPER") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, client.Options{HostPort: os.Getenv("ARGUS_TEMPORAL_ADDRESS"), Identity: "argus-synthetic-helper"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	w := temporalworker.New(c, DefaultTaskQueue, temporalworker.Options{MaxConcurrentActivityExecutionSize: 1})
	w.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: WorkflowName})
	w.RegisterActivityWithOptions(func(ctx context.Context, _ v1.Task) (v1.Outcome, error) {
		f, err := os.OpenFile(os.Getenv("ARGUS_HELPER_MARKER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return v1.Outcome{}, err
		}
		if _, err := f.WriteString("once"); err != nil {
			_ = f.Close()
			return v1.Outcome{}, err
		}
		if err := f.Close(); err != nil {
			return v1.Outcome{}, err
		}
		<-ctx.Done()
		return v1.Outcome{}, ctx.Err()
	}, activity.RegisterOptions{Name: ActivityName})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("ARGUS_HELPER_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	select {} // parent deliberately kills this disposable worker during the activity
}
