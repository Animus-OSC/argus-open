package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func TestCLIRealOfflineDemoAndIndependentVerification(t *testing.T) {
	root := t.TempDir()
	state, output := filepath.Join(root, "state"), filepath.Join(root, "receipt.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"demo", "--state-dir", state, "--out", output, "--tenant", "tenant-a", "--project", "project-a"}, &stdout, &stderr)
	if code == 2 && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("sandbox unavailable")
	}
	if code != 0 {
		t.Fatalf("demo failed (%d): %s %s", code, stdout.String(), stderr.String())
	}
	var result v1.Outcome
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != v1.Pass || result.Receipt == nil || result.Receipt.Receipt.TenantID != "tenant-a" {
		t.Fatal("invalid demo result")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--receipt", output, "--sha256", result.Receipt.SHA256}, &stdout, &stderr); code != 0 {
		t.Fatal("valid evidence rejected")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"tenant-a"`), []byte(`"tenant-b"`), 1)
	if err := os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"verify", "--receipt", output, "--sha256", result.Receipt.SHA256}, &stdout, &stderr); code != 2 {
		t.Fatal("tampered receipt accepted")
	}
	if code := run([]string{"demo", "--state-dir", state, "--out", filepath.Join(root, "second.json"), "--tenant", "tenant-a", "--project", "project-a"}, &stdout, &stderr); code != 2 {
		t.Fatal("duplicate task was rerun")
	}
}

func TestReceiptParserRejectsDuplicateFieldsAndOversize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "receipt.json")
	for _, data := range [][]byte{[]byte(`{"receipt":{},"receipt":{},"sha256":"bad"}`), bytes.Repeat([]byte(" "), (64<<10)+1)} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		if verifyFile(p, "sha256:bad") == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
}

func TestReceiptExportFailureKeepsDurableCompletionAndRejectsReplay(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	var stdout, stderr bytes.Buffer
	code := run([]string{"demo", "--state-dir", state, "--out", filepath.Join(root, "missing", "receipt.json")}, &stdout, &stderr)
	if code == 2 && os.Getenv("ARGUS_REQUIRE_SANDBOX") != "1" {
		t.Skip("sandbox unavailable")
	}
	if code != 4 || !bytes.Contains(stderr.Bytes(), []byte("inspect the completed ledger")) {
		t.Fatalf("receipt export failure was not reported accurately: %d %s", code, stderr.String())
	}
	records, err := filepath.Glob(filepath.Join(state, "tasks", "*", "receipt.json"))
	if err != nil || len(records) != 1 {
		t.Fatal("completed ledger receipt was not retained")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"demo", "--state-dir", state, "--out", filepath.Join(root, "retry.json")}, &stdout, &stderr); code != 2 {
		t.Fatal("completed task was replayed after export failure")
	}
}
