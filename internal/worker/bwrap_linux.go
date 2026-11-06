//go:build linux

// Package worker implements the bounded Linux-only synthetic QA worker.
package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	syntheticproject "github.com/Animus-OSC/argus-open/examples/synthetic-project"
)

const harness = `import sys, unittest
print("ARGUS_START_V1", flush=True)
suite = unittest.defaultTestLoader.discover("/work/tests", pattern="test_*.py", top_level_dir="/work")
count = suite.countTestCases()
if count == 0:
    print("ARGUS_NO_TESTS_V1", flush=True)
    sys.exit(3)
result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
if result.skipped or result.expectedFailures or result.unexpectedSuccesses or result.testsRun != count:
    print("ARGUS_INCOMPLETE_V1", flush=True)
    sys.exit(3)
print("ARGUS_DONE_V1:" + str(result.testsRun), flush=True)
sys.exit(0 if result.wasSuccessful() else 1)
`

var donePattern = regexp.MustCompile(`(?m)^ARGUS_DONE_V1:([0-9]{1,5})$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Bwrap struct{ WorkspaceRoot string }

// Execute has a closed operation catalog; neither a command nor arguments can
// be supplied by a model or a project. The sandbox is for synthetic tests only.
func (b Bwrap) Execute(parent context.Context, snapshot v1.Snapshot, op v1.Operation) (v1.Observation, error) {
	if op.ID != v1.UnitOperation {
		return v1.Observation{}, v1.ErrDenied
	}
	if parent.Err() != nil || os.Geteuid() == 0 || runtime.GOARCH != "amd64" {
		return v1.Observation{}, v1.ErrUnavailable
	}
	root := filepath.Clean(b.WorkspaceRoot)
	if snapshot.Version != v1.SnapshotVersion || !commitPattern.MatchString(snapshot.SourceSHA) || !filepath.IsAbs(snapshot.Ref) ||
		!filepath.IsAbs(root) || filepath.Dir(filepath.Clean(snapshot.Ref)) != root || !strings.HasPrefix(filepath.Base(snapshot.Ref), "snapshot-") {
		return v1.Observation{}, v1.ErrUnavailable
	}
	rootInfo, err := os.Lstat(root)
	resolved, resolveErr := filepath.EvalSymlinks(root)
	if err != nil || resolveErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm()&0077 != 0 || resolved != root || !ownedByCurrentUser(rootInfo) {
		return v1.Observation{}, v1.ErrUnavailable
	}
	workspace := snapshot.Ref
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) {
		return v1.Observation{}, v1.ErrUnavailable
	}
	fixture, ok := trustedFixture(workspace)
	if !ok {
		return v1.Observation{}, v1.ErrDenied
	}
	return b.executeSandbox(parent, workspace, op, fixture)
}

// Only the two known synthetic source variants can reach the worker. This
// prevents untrusted fixture code from forging harness output or exiting early.
func trustedFixture(root string) (map[string][]byte, bool) {
	allowed := map[string][]byte{}
	for _, name := range []string{"calculator.py", "tests/__init__.py", "tests/test_calculator.py"} {
		b, err := syntheticproject.Files.ReadFile(name)
		if err != nil {
			return nil, false
		}
		allowed[name] = b
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, false
	}
	defer dir.Close()
	seen := 0
	err = fs.WalkDir(dir.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if entry.IsDir() {
			if name != "tests" {
				return v1.ErrDenied
			}
			return nil
		}
		expected, ok := allowed[name]
		if !ok || entry.Type()&os.ModeSymlink != 0 {
			return v1.ErrDenied
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return v1.ErrDenied
		}
		f, err := dir.Open(name)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 4097))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > 4096 {
			return v1.ErrDenied
		}
		if !bytes.Equal(data, expected) && !(name == "calculator.py" && string(data) == syntheticproject.FailingCalculator) {
			return v1.ErrDenied
		}
		if name == "calculator.py" && string(data) == syntheticproject.FailingCalculator {
			allowed[name] = []byte(syntheticproject.FailingCalculator)
		}
		seen++
		return nil
	})
	return allowed, err == nil && seen == len(allowed)
}

// A nil fixture is used solely by package tests to probe the sandbox itself.
// Public execution always supplies sealed, preapproved in-memory fixture bytes.
func (b Bwrap) executeSandbox(parent context.Context, workspace string, op v1.Operation, fixture map[string][]byte) (v1.Observation, error) {
	for _, p := range []string{"/usr/bin/bwrap", "/usr/bin/prlimit", "/usr/bin/python3.12", "/usr/lib/python3.12", "/usr/lib/x86_64-linux-gnu", "/usr/lib64"} {
		if _, err := os.Stat(p); err != nil {
			return v1.Observation{}, v1.ErrUnavailable
		}
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	args := []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--dir", "/usr", "--dir", "/usr/bin", "--dir", "/usr/lib",
		"--ro-bind", "/usr/bin/python3.12", "/usr/bin/python3.12",
		"--ro-bind", "/usr/bin/prlimit", "/usr/bin/prlimit",
		"--ro-bind", "/usr/lib/python3.12", "/usr/lib/python3.12",
		"--ro-bind", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"--ro-bind", "/usr/lib64", "/usr/lib64",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--size", "16777216", "--tmpfs", "/tmp",
	}
	var fds []*os.File
	defer func() {
		for _, f := range fds {
			_ = f.Close()
		}
	}()
	bindData := func(dest string, data []byte) error {
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			_ = r.Close()
			_ = w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			_ = r.Close()
			return err
		}
		fds = append(fds, r)
		args = append(args, "--ro-bind-data", strconv.Itoa(2+len(fds)), dest)
		return nil
	}
	if fixture == nil {
		args = append(args, "--ro-bind", workspace, "/work")
	} else {
		args = append(args, "--dir", "/work", "--dir", "/work/tests")
		for _, name := range []string{"calculator.py", "tests/__init__.py", "tests/test_calculator.py"} {
			if err := bindData("/work/"+name, fixture[name]); err != nil {
				return v1.Observation{}, v1.ErrUnavailable
			}
		}
	}
	args = append(args, "--dir", "/runner")
	if err := bindData("/runner/qa.py", []byte(harness)); err != nil {
		return v1.Observation{}, v1.ErrUnavailable
	}
	args = append(args,
		"--chdir", "/work", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/tmp",
		"/usr/bin/prlimit", "--cpu=5", "--as=268435456", "--fsize=1048576", "--nofile=64", "--nproc=1", "--core=0", "--",
		"/usr/bin/python3.12", "-I", "-S", "-B", "/runner/qa.py")
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	cmd.ExtraFiles = fds
	// The parent environment is not passed to bwrap either.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr boundedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now().UTC()
	runErr := cmd.Run()
	finished := time.Now().UTC()
	if cmd.Process == nil {
		return v1.Observation{}, v1.ErrUnavailable
	}
	if ctx.Err() != nil {
		return v1.Observation{}, v1.ErrUncertain
	}
	if !bytes.HasPrefix(stdout.data, []byte("ARGUS_START_V1\n")) {
		return v1.Observation{}, v1.ErrUncertain
	}
	if !stdout.truncated && bytes.Contains(stdout.data, []byte("\nARGUS_NO_TESTS_V1\n")) {
		return v1.Observation{}, v1.ErrNoTests
	}
	if !stdout.truncated && bytes.Contains(stdout.data, []byte("\nARGUS_INCOMPLETE_V1\n")) {
		return v1.Observation{}, v1.ErrIncomplete
	}
	matches := donePattern.FindAllSubmatch(stdout.data, -1)
	if len(matches) != 1 || stdout.truncated || stderr.truncated {
		return v1.Observation{}, v1.ErrUncertain
	}
	count, err := strconv.Atoi(string(matches[0][1]))
	if err != nil || count < 1 {
		return v1.Observation{}, v1.ErrUncertain
	}
	exit := 0
	if runErr != nil {
		var e *exec.ExitError
		if !errors.As(runErr, &e) || e.ExitCode() < 0 {
			return v1.Observation{}, v1.ErrUncertain
		}
		exit = e.ExitCode()
	}
	combined := append(append([]byte(nil), stdout.data...), 0)
	combined = append(combined, stderr.data...)
	h := sha256.Sum256(combined)
	return v1.Observation{Operation: op.ID, Worker: "linux-bwrap-python3.12/v1", ExitCode: exit,
		TestsRun: count, StartedAt: started, FinishedAt: finished, OutputSHA256: "sha256:" + hex.EncodeToString(h[:])}, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid())
}

// Keep output out of receipts and logs, and bound memory even for hostile tests.
type boundedOutput struct {
	data      []byte
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	const max = 64 << 10
	if len(b.data)+len(p) > max {
		b.truncated = true
		remaining := max - len(b.data)
		if remaining > 0 {
			b.data = append(b.data, p[:remaining]...)
		}
	} else {
		b.data = append(b.data, p...)
	}
	return len(p), nil
}
