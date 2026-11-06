// Argus provides a synthetic demo, receipt verification, offline audits and a pinned SDK unit profile.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/policy"
	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/internal/store"
	"github.com/Animus-OSC/argus-open/internal/synthetic"
	"github.com/Animus-OSC/argus-open/internal/worker"
	"github.com/Animus-OSC/argus-open/pkg/core"
	"github.com/Animus-OSC/argus-open/pkg/evidence"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: argus demo --state-dir ABSOLUTE_PATH --out NEW_FILE | verify --receipt FILE --sha256 DIGEST | run-profile --profile ID --repo DIR --source-sha SHA --run-id ID --out-dir NEW_DIR | audit --plan FILE --plan-sha256 DIGEST --results FILE --artifacts DIR --out NEW_FILE")
		return 2
	}
	switch args[0] {
	case "run-profile":
		return profileCommand(args[1:], stdout, stderr)
	case "audit":
		return auditCommand(args[1:], stdout, stderr)
	case "demo":
		f := flag.NewFlagSet("demo", flag.ContinueOnError)
		f.SetOutput(stderr)
		stateDir, outPath := f.String("state-dir", "", "private local task ledger"), f.String("out", "", "new receipt file")
		tenant := f.String("tenant", "synthetic-tenant", "synthetic tenant ID")
		project := f.String("project", "synthetic-project", "synthetic project ID")
		taskID := f.String("task-id", "synthetic-task-1", "unique task ID")
		key := f.String("idempotency-key", "synthetic-key-1", "tenant/project scoped key")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || !filepath.IsAbs(*stateDir) || !filepath.IsAbs(*outPath) {
			fmt.Fprintln(stderr, "absolute --state-dir and --out are required")
			return 2
		}
		return demo(*stateDir, *outPath, *tenant, *project, *taskID, *key, stdout, stderr)
	case "verify":
		f := flag.NewFlagSet("verify", flag.ContinueOnError)
		f.SetOutput(stderr)
		path, expected := f.String("receipt", "", "receipt file"), f.String("sha256", "", "independently retained digest")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *path == "" || *expected == "" {
			fmt.Fprintln(stderr, "--receipt and --sha256 are required")
			return 2
		}
		if err := verifyFile(*path, *expected); err != nil {
			fmt.Fprintln(stderr, "BLOCKED: receipt verification failed")
			return 2
		}
		fmt.Fprintln(stdout, "VERIFIED: receipt integrity and verdict consistency")
		return 0
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func demo(stateDir, outPath, tenant, projectID, taskID, key string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "argus-demo-")
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: synthetic workspace unavailable")
		return 2
	}
	defer os.RemoveAll(root)
	project, task, err := synthetic.CreateFixture(ctx, root, tenant, projectID)
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: synthetic source unavailable")
		return 2
	}
	task.TaskID, task.IdempotencyKey = taskID, key
	task.Signature = synthetic.Sign(task)
	if !policy.ValidTask(task) {
		fmt.Fprintln(stderr, "BLOCKED: invalid synthetic identity")
		return 2
	}
	if _, err := os.Lstat(outPath); !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "BLOCKED: receipt destination must not already exist")
		return 2
	}
	staging := filepath.Join(root, "snapshots")
	if err := os.Mkdir(staging, 0700); err != nil {
		fmt.Fprintln(stderr, "BLOCKED: private staging unavailable")
		return 2
	}
	ledger, err := store.NewLocal(stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: private ledger unavailable")
		return 2
	}
	engine := core.Engine{Events: synthetic.EventVerifier{}, Projects: synthetic.Registry{Projects: []v1.Project{project}},
		Model: synthetic.FakeModel{}, Snapshots: source.GitArchive{Root: staging}, Worker: worker.Bwrap{WorkspaceRoot: staging}, Store: ledger}
	result := engine.Run(ctx, task)
	if result.Receipt != nil {
		b, err := json.MarshalIndent(result.Receipt, "", "  ")
		if err != nil || writeNew(outPath, append(b, '\n')) != nil {
			fmt.Fprintln(stderr, "UNCERTAIN: receipt export failed; inspect the completed ledger record before retry")
			return 4
		}
	}
	_ = json.NewEncoder(stdout).Encode(result)
	switch result.State {
	case v1.Pass:
		return 0
	case v1.Fail:
		return 1
	case v1.Uncertain:
		return 4
	default:
		return 2
	}
}

func writeNew(path string, data []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func verifyFile(path, expected string) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("receipt must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return errors.New("invalid receipt encoding")
	}
	e, err := evidence.Decode(data)
	if err != nil {
		return err
	}
	return evidence.Verify(e, expected)
}
