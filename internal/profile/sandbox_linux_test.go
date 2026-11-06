//go:build linux

package profile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sandboxWorkspace(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "python"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "python", "sentinel.txt"), []byte("immutable-snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func requireProfileSandbox(t *testing.T, dir string) {
	t.Helper()
	result := executeSandboxWithDriver(context.Background(), dir, []byte("print('profile-sandbox-ready')\n"))
	if result.Started && result.ExitCode == 0 && !result.Uncertain && string(result.Stdout) == "profile-sandbox-ready\n" {
		return
	}
	if os.Getenv("ARGUS_REQUIRE_SANDBOX") == "1" {
		t.Fatalf("required profile sandbox unavailable: %+v; stderr=%s", result, result.Stderr)
	}
	t.Skipf("profile sandbox unavailable; run required Linux probes with ARGUS_REQUIRE_SANDBOX=1: stderr=%s", result.Stderr)
}

func TestProfileSandboxIsolation(t *testing.T) {
	dir := sandboxWorkspace(t)
	requireProfileSandbox(t, dir)
	t.Setenv("ARGUS_PROFILE_TEST_SECRET", "must-not-enter")
	networkNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	code := fmt.Sprintf(`import errno, os, pathlib, resource, socket, sys, threading
assert os.getuid() != 0
assert os.getenv('HOME') is None
assert os.getenv('ARGUS_PROFILE_TEST_SECRET') is None
assert not os.path.exists('/home')
assert not os.path.exists('/root')
assert not os.path.exists('/run')
assert not os.path.exists('/var/run/docker.sock')
assert os.readlink('/proc/self/ns/net') != %s
assert [name for _, name in socket.if_nameindex()] == ['lo']
s=socket.socket(); s.settimeout(0.1)
try: assert s.connect_ex(('192.0.2.1', 443)) != 0
finally: s.close()
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert int(status['CapEff'].strip(), 16) == 0
assert status['NoNewPrivs'].strip() == '1'
assert resource.getrlimit(resource.RLIMIT_CPU) == (10, 10)
assert resource.getrlimit(resource.RLIMIT_AS) == (536870912, 536870912)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_NPROC) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (1048576, 1048576)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
assert pathlib.Path('/work/python/sentinel.txt').read_text() == 'immutable-snapshot'
try:
 pathlib.Path('/work/python/sentinel.txt').write_text('changed')
 raise AssertionError('snapshot was writable')
except OSError as e: assert e.errno in (errno.EROFS, errno.EACCES)
pathlib.Path('/tmp/private-probe').write_text('scratch')
threads = [threading.Thread(target=lambda: None) for _ in range(8)]
for thread in threads: thread.start()
for thread in threads: thread.join()
print('isolation-verified')
`, strconv.Quote(networkNS))
	result := executeSandboxWithDriver(context.Background(), dir, []byte(code))
	if !result.Started || result.ExitCode != 0 || result.Uncertain || string(result.Stdout) != "isolation-verified\n" {
		t.Fatalf("isolation failure: %+v; stderr=%s", result, result.Stderr)
	}
	body, err := os.ReadFile(filepath.Join(dir, "python", "sentinel.txt"))
	if err != nil || string(body) != "immutable-snapshot" {
		t.Fatalf("snapshot changed: %q %v", body, err)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		t.Fatal("missing or inverted execution timestamps")
	}
}

func TestProfileSandboxNoExecutionOnInvalidSnapshot(t *testing.T) {
	dir := sandboxWorkspace(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	link := filepath.Join(t.TempDir(), "snapshot-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	public := sandboxWorkspace(t)
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	missingPython := t.TempDir()
	if err := os.Chmod(missingPython, 0700); err != nil {
		t.Fatal(err)
	}
	linkedPython := sandboxWorkspace(t)
	if err := os.RemoveAll(filepath.Join(linkedPython, "python")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "python"), filepath.Join(linkedPython, "python")); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ctx    context.Context
		path   string
		driver []byte
	}{
		"relative":         {context.Background(), "python", []byte("raise Exception()")},
		"missing":          {context.Background(), filepath.Join(dir, "missing"), []byte("raise Exception()")},
		"symlink":          {context.Background(), link, []byte("raise Exception()")},
		"public-root":      {context.Background(), public, []byte("raise Exception()")},
		"missing-python":   {context.Background(), missingPython, []byte("raise Exception()")},
		"symlink-python":   {context.Background(), linkedPython, []byte("raise Exception()")},
		"cancelled":        {cancelled, dir, []byte("raise Exception()")},
		"empty-driver":     {context.Background(), dir, nil},
		"oversized-driver": {context.Background(), dir, bytes.Repeat([]byte("x"), maxSandboxDriverBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			result := executeSandboxWithDriver(tc.ctx, tc.path, tc.driver)
			if result.Started || result.ExitCode != -1 || result.Uncertain || !result.StartedAt.IsZero() || !result.FinishedAt.IsZero() || len(result.Stdout)+len(result.Stderr) != 0 {
				t.Fatalf("invalid preflight executed: %+v", result)
			}
		})
	}
}

func TestProfileSandboxOrdinaryFailurePreserved(t *testing.T) {
	dir := sandboxWorkspace(t)
	requireProfileSandbox(t, dir)
	result := executeSandboxWithDriver(context.Background(), dir, []byte("import sys\nprint('failed-test')\nsys.exit(7)\n"))
	if !result.Started || result.ExitCode != 7 || result.Uncertain || result.TimedOut || result.Cancelled || string(result.Stdout) != "failed-test\n" {
		t.Fatalf("ordinary failure was lost or reported as uncertainty: %+v; stderr=%s", result, result.Stderr)
	}
}

func TestProfileSandboxCancellationAndDeadlineAreUncertain(t *testing.T) {
	dir := sandboxWorkspace(t)
	requireProfileSandbox(t, dir)
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%v", deadline), func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 350*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				timer := time.AfterFunc(350*time.Millisecond, cancel)
				defer timer.Stop()
			}
			defer cancel()
			start := time.Now()
			// A descendant retaining output descriptors must not cause an unbounded
			// Wait, even when the driver's final report never arrives.
			code := "import os,time\nprint('started', flush=True)\nif os.fork() == 0: time.sleep(30); os._exit(0)\ntime.sleep(30)\n"
			result := executeSandboxWithDriver(ctx, dir, []byte(code))
			if !result.Started || !result.Uncertain || result.TimedOut != deadline || result.Cancelled == deadline || !strings.Contains(string(result.Stdout), "started") {
				t.Fatalf("cancellation/deadline not preserved: %+v; stderr=%s", result, result.Stderr)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("sandbox teardown exceeded bounded wait")
			}
		})
	}
}

func TestProfileSandboxOutputIsBoundedAndUncertain(t *testing.T) {
	dir := sandboxWorkspace(t)
	requireProfileSandbox(t, dir)
	code := fmt.Sprintf("import os\nos.write(1,b'a'*%d)\nos.write(2,b'b'*%d)\n", sandboxStdoutLimit+1234, sandboxStderrLimit+1234)
	result := executeSandboxWithDriver(context.Background(), dir, []byte(code))
	if !result.Started || result.ExitCode != 0 || !result.Truncated || !result.Uncertain || len(result.Stdout) != sandboxStdoutLimit || len(result.Stderr) != sandboxStderrLimit {
		t.Fatalf("unbounded or trusted truncated output: started=%v exit=%d truncated=%v uncertain=%v stdout=%d stderr=%d", result.Started, result.ExitCode, result.Truncated, result.Uncertain, len(result.Stdout), len(result.Stderr))
	}
}

func TestProfileSandboxLargeTrustedDriverCannotDeadlock(t *testing.T) {
	dir := sandboxWorkspace(t)
	requireProfileSandbox(t, dir)
	code := []byte("#" + strings.Repeat("x", 32<<10) + "\nprint('large-driver-complete')\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := executeSandboxWithDriver(ctx, dir, code)
	if !result.Started || result.ExitCode != 0 || result.Uncertain || string(result.Stdout) != "large-driver-complete\n" {
		t.Fatalf("large trusted driver failed: %+v; stderr=%s", result, result.Stderr)
	}
}
