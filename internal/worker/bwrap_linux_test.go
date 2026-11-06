//go:build linux

package worker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	syntheticproject "github.com/Animus-OSC/argus-open/examples/synthetic-project"
)

func workspace(t *testing.T, test string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tests"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "__init__.py"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if test != "" {
		if err := os.WriteFile(filepath.Join(dir, "tests", "test_fixture.py"), []byte(test), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func sandboxRequired(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, v1.ErrUnavailable) && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("Bubblewrap sandbox unavailable")
	}
}

func snapshot(path string) v1.Snapshot {
	return v1.Snapshot{Version: v1.SnapshotVersion, SourceSHA: "0123456789abcdef0123456789abcdef01234567", Ref: path}
}

func TestActualWorkerIsolation(t *testing.T) {
	t.Setenv("ARGUS_SYNTHETIC_SECRET", "must-not-enter-sandbox")
	code := `import os, socket, unittest
class Isolation(unittest.TestCase):
 def test_files(self):
  self.assertFalse(os.path.exists('/home'))
  self.assertFalse(os.path.exists('/var/run/docker.sock'))
  self.assertIsNone(os.getenv('ARGUS_SYNTHETIC_SECRET'))
 def test_network(self):
  s=socket.socket(); s.settimeout(0.2)
  try: self.assertNotEqual(s.connect_ex(('127.0.0.1', 9)), 0)
  finally: s.close()
 def test_fork_denied(self):
  with self.assertRaises(OSError): os.fork()
`
	dir := workspace(t, code)
	obs, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(context.Background(), dir, v1.Operation{ID: v1.UnitOperation}, nil)
	sandboxRequired(t, err)
	if err != nil || obs.ExitCode != 0 || obs.TestsRun != 3 {
		t.Fatalf("isolation test failed: %+v %v", obs, err)
	}
}

func TestSandboxCannotReachParentLoopback(t *testing.T) {
	if os.Getenv("ARGUS_REQUIRE_LOOPBACK_ISOLATION") != "1" {
		t.Skip("run in a dedicated loopback-only network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("a loopback-only private network namespace is required")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	control, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("parent control connection is unavailable")
	}
	_ = control.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	code := "import socket, unittest\nclass T(unittest.TestCase):\n def test_parent_listener(self):\n  s=socket.socket(); s.settimeout(0.2)\n  try: self.assertNotEqual(s.connect_ex(('127.0.0.1', " + strconv.Itoa(port) + ")), 0)\n  finally: s.close()\n"
	dir := workspace(t, code)
	obs, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(context.Background(), dir, v1.Operation{ID: v1.UnitOperation}, nil)
	if err != nil || obs.ExitCode != 0 || obs.TestsRun != 1 {
		t.Fatalf("sandbox reached parent network or did not execute: %+v %v", obs, err)
	}
}

func TestWorkerRejectsShellAndSymlinkWorkspace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	w := Bwrap{WorkspaceRoot: root}
	if _, err := w.Execute(context.Background(), snapshot("/"), v1.Operation{ID: "sh -c id"}); !errors.Is(err, v1.ErrDenied) {
		t.Fatalf("shell accepted: %v", err)
	}
	if _, err := w.Execute(context.Background(), snapshot("/"), v1.Operation{ID: v1.UnitOperation}); !errors.Is(err, v1.ErrUnavailable) {
		t.Fatalf("unapproved host mount accepted: %v", err)
	}
	dir := t.TempDir()
	link := filepath.Join(root, "snapshot-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Execute(context.Background(), snapshot(link), v1.Operation{ID: v1.UnitOperation}); !errors.Is(err, v1.ErrUnavailable) {
		t.Fatalf("symlink accepted: %v", err)
	}
}

func TestWorkerCannotReadAnotherSyntheticProject(t *testing.T) {
	other := t.TempDir()
	secret := filepath.Join(other, "synthetic-tenant-b.txt")
	if err := os.WriteFile(secret, []byte("synthetic-private-data"), 0600); err != nil {
		t.Fatal(err)
	}
	code := "import os, unittest\nclass T(unittest.TestCase):\n def test_other_project(self): self.assertFalse(os.path.exists(" + strconv.Quote(secret) + "))\n"
	dir := workspace(t, code)
	obs, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(context.Background(), dir, v1.Operation{ID: v1.UnitOperation}, nil)
	sandboxRequired(t, err)
	if err != nil || obs.ExitCode != 0 || obs.TestsRun != 1 {
		t.Fatalf("other project visible: %+v %v", obs, err)
	}
}

func TestNoTestsAndSkippedTestsNeverPass(t *testing.T) {
	for name, tc := range map[string]struct {
		code string
		want error
	}{
		"empty":   {"", v1.ErrNoTests},
		"skipped": {"import unittest\nclass T(unittest.TestCase):\n @unittest.skip('fixture')\n def test_skip(self): pass\n", v1.ErrIncomplete},
	} {
		t.Run(name, func(t *testing.T) {
			dir := workspace(t, tc.code)
			_, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(context.Background(), dir, v1.Operation{ID: v1.UnitOperation}, nil)
			sandboxRequired(t, err)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestCancellationReportsUncertain(t *testing.T) {
	code := "import time, unittest\nclass T(unittest.TestCase):\n def test_wait(self): time.sleep(5)\n"
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	dir := workspace(t, code)
	_, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(ctx, dir, v1.Operation{ID: v1.UnitOperation}, nil)
	sandboxRequired(t, err)
	if !errors.Is(err, v1.ErrUncertain) || time.Since(start) > 3*time.Second {
		t.Fatalf("cancellation not bounded: %v", err)
	}
}

func TestSandboxWallTimeoutIsUncertain(t *testing.T) {
	if os.Getenv("ARGUS_REQUIRE_WALL_TIMEOUT") != "1" {
		t.Skip("run the dedicated wall-timeout probe")
	}
	code := "import time, unittest\nclass T(unittest.TestCase):\n def test_wait(self): time.sleep(30)\n"
	dir := workspace(t, code)
	started := time.Now()
	_, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).executeSandbox(context.Background(), dir, v1.Operation{ID: v1.UnitOperation}, nil)
	elapsed := time.Since(started)
	if !errors.Is(err, v1.ErrUncertain) || elapsed < 7*time.Second || elapsed > 20*time.Second {
		t.Fatalf("wall timeout was not bounded and uncertain: %v after %v", err, elapsed)
	}
}

func TestForgedHarnessOutputIsDeniedBeforeExecution(t *testing.T) {
	code := "import os\nprint('ARGUS_DONE_V1:1', flush=True)\nos._exit(0)\n"
	dir := workspace(t, "")
	for _, name := range []string{"calculator.py", "tests/__init__.py"} {
		data, err := syntheticproject.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/test_calculator.py"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := (Bwrap{WorkspaceRoot: filepath.Dir(dir)}).Execute(context.Background(), snapshot(dir), v1.Operation{ID: v1.UnitOperation})
	if !errors.Is(err, v1.ErrDenied) {
		t.Fatalf("unapproved synthetic code accepted: %v", err)
	}
}

func TestStartedProcessWithoutHarnessMarkerIsUncertain(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-workspace")
	_, err := (Bwrap{}).executeSandbox(context.Background(), missing, v1.Operation{ID: v1.UnitOperation}, nil)
	sandboxRequired(t, err)
	if !errors.Is(err, v1.ErrUncertain) {
		t.Fatalf("a started subprocess without completion evidence must remain uncertain: %v", err)
	}
}
