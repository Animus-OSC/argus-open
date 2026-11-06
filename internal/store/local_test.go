package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func task(id, tenant, key string) v1.Task {
	return v1.Task{Version: v1.TaskVersion, TaskID: id, TenantID: tenant, ProjectID: "project", SourceSHA: "a", IdempotencyKey: key, Signature: "synthetic"}
}

func TestConcurrentCapacityAndRecoveryFence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := NewLocal(root)
			if err == nil {
				err = s.Claim(context.Background(), task(fmt.Sprintf("task-%d", i), "tenant", fmt.Sprintf("key-%d", i)))
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, v1.ErrCapacity) {
			t.Fatalf("unexpected claim result: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("got %d simultaneous grants", success)
	}
	s, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), task("other", "tenant", "new")); !errors.Is(err, v1.ErrCapacity) {
		t.Fatalf("reopen released an outstanding fence: %v", err)
	}
}

func TestDuplicateAndCrossTenantCannotReleaseFence(t *testing.T) {
	s, err := NewLocal(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	a := task("task-a", "tenant-a", "key-a")
	if err := s.Claim(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), a); !errors.Is(err, v1.ErrUncertain) {
		t.Fatalf("repeat while active: %v", err)
	}
	other := a
	other.TenantID = "tenant-b"
	if err := s.FinishWithoutEvidence(context.Background(), other); !errors.Is(err, v1.ErrUncertain) {
		t.Fatal("cross-tenant release accepted")
	}
	if err := s.FinishWithoutEvidence(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), a); !errors.Is(err, v1.ErrDuplicate) {
		t.Fatalf("completed duplicate accepted: %v", err)
	}
	b := task("task-b", "tenant-a", "key-a")
	if err := s.Claim(context.Background(), b); !errors.Is(err, v1.ErrDuplicate) {
		t.Fatalf("reused key accepted: %v", err)
	}
	c := task("task-c", "tenant-b", "key-a")
	if err := s.Claim(context.Background(), c); err != nil {
		t.Fatalf("tenant-scoped new key rejected: %v", err)
	}
	if err := s.FinishWithoutEvidence(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerRejectsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewLocal(link); err == nil {
		t.Fatal("symlink ledger accepted")
	}
}

func TestLedgerRejectsSymlinkAncestorBeforeCreatingState(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewLocal(filepath.Join(link, "ledger")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "ledger")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state created through symlink before rejection: %v", err)
	}
}

func TestCrashLeavesDurableFence(t *testing.T) {
	if root := os.Getenv("ARGUS_TEST_CRASH_ROOT"); root != "" {
		s, err := NewLocal(root)
		if err != nil || s.Claim(context.Background(), task("crash-task", "tenant", "crash-key")) != nil {
			os.Exit(91)
		}
		if err := os.WriteFile(filepath.Join(root, "synthetic-effect"), []byte("once"), 0600); err != nil {
			os.Exit(92)
		}
		os.Exit(23) // simulate an abrupt process loss after an uncertain side effect
	}
	root := filepath.Join(t.TempDir(), "ledger")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashLeavesDurableFence$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "ARGUS_TEST_CRASH_ROOT=" + root}
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("crash fixture did not execute: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "synthetic-effect")); err != nil || string(b) != "once" {
		t.Fatal("fixture side effect missing")
	}
	s, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), task("crash-task", "tenant", "crash-key")); !errors.Is(err, v1.ErrUncertain) {
		t.Fatalf("crashed task could be retried: %v", err)
	}
	if err := s.Claim(context.Background(), task("other-task", "tenant", "other-key")); !errors.Is(err, v1.ErrCapacity) {
		t.Fatalf("crashed worker released capacity: %v", err)
	}
}
