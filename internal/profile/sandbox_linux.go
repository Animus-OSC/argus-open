//go:build linux

package profile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

const (
	sandboxWallTimeout    = 20 * time.Second
	sandboxWaitDelay      = 2 * time.Second
	sandboxStdoutLimit    = 64 << 10
	sandboxStderrLimit    = 128 << 10
	maxSandboxDriverBytes = 64 << 10
)

// executeSandbox accepts only an operator-created, immutable private snapshot.
// It is not an admission boundary for hostile multi-tenant source or hosts.
func executeSandbox(parent context.Context, workspace string) execution {
	return executeSandboxWithDriver(parent, workspace, driverSource)
}

// The override is unexported and used only by package isolation regression
// tests. No CLI, profile or project field can replace the embedded driver.
func executeSandboxWithDriver(parent context.Context, workspace string, driver []byte) execution {
	result := execution{ExitCode: -1}
	if parent == nil || parent.Err() != nil || os.Geteuid() == 0 || runtime.GOARCH != "amd64" || len(driver) == 0 || len(driver) > maxSandboxDriverBytes {
		return result
	}
	if !privateSnapshot(workspace) {
		return result
	}
	for _, path := range []string{"/usr/bin/bwrap", "/usr/bin/prlimit", "/usr/bin/python3.12", "/usr/lib/python3.12", "/usr/lib/x86_64-linux-gnu", "/usr/lib64"} {
		if _, err := os.Stat(path); err != nil {
			return result
		}
	}
	// A regular, unlinked descriptor avoids pipe-capacity deadlocks and does not
	// expose a mutable driver pathname to either the project or Bubblewrap.
	driverFile, err := os.CreateTemp("/tmp", "argus-profile-driver-")
	if err != nil {
		return result
	}
	defer driverFile.Close()
	driverName := driverFile.Name()
	defer os.Remove(driverName)
	if _, err := driverFile.Write(driver); err != nil {
		return result
	}
	if _, err := driverFile.Seek(0, 0); err != nil {
		return result
	}
	if err := os.Remove(driverName); err != nil {
		return result
	}

	ctx, cancel := context.WithTimeout(parent, sandboxWallTimeout)
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
		"--ro-bind", workspace, "/work", "--dir", "/runner",
		"--ro-bind-data", "3", "/runner/unittest_driver.py", "--chdir", "/work",
		"--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C",
		"/usr/bin/prlimit", "--cpu=10", "--as=536870912", "--fsize=1048576", "--nofile=64", "--nproc=64", "--core=0", "--",
		"/usr/bin/python3.12", "-I", "-S", "-B", "/runner/unittest_driver.py",
	}
	// #nosec G204 -- fixed Bubblewrap command/options; workspace is a canonical private operator snapshot and the driver is embedded.
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.ExtraFiles = []*os.File{driverFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = sandboxWaitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	stdout := &sandboxOutput{limit: sandboxStdoutLimit}
	stderr := &sandboxOutput{limit: sandboxStderrLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return result
	}
	result.Started = true
	result.StartedAt = time.Now().UTC()
	waitErr := cmd.Wait()
	result.FinishedAt = time.Now().UTC()
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	result.Truncated = stdout.truncated || stderr.truncated
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		result.Cancelled = errors.Is(ctx.Err(), context.Canceled)
	}
	result.Uncertain = result.Truncated || result.TimedOut || result.Cancelled || result.ExitCode < 0 || errors.Is(waitErr, exec.ErrWaitDelay)
	// A normal nonzero exit can represent valid failed tests. The caller must
	// additionally validate the complete report and exact pinned test identities.
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			result.Uncertain = true
		}
	}
	return result
}

func privateSnapshot(workspace string) bool {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return false
	}
	canonical, err := filepath.EvalSymlinks(workspace)
	if err != nil || canonical != workspace {
		return false
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return false
	}
	python := filepath.Join(workspace, "python")
	info, err = os.Lstat(python)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

type sandboxOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (out *sandboxOutput) Write(p []byte) (int, error) {
	original := len(p)
	room := out.limit - out.buffer.Len()
	if len(p) > room {
		p = p[:room]
		out.truncated = true
	}
	_, _ = out.buffer.Write(p)
	return original, nil
}

func (out *sandboxOutput) Bytes() []byte { return out.buffer.Bytes() }
