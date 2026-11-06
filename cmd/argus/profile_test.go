package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileCLIRequiresApprovedSourceAndNewOutput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "must-not-be-created")
	for _, args := range [][]string{
		{"run-profile"},
		{"run-profile", "--profile", "arbitrary-shell", "--repo", dir, "--source-sha", "unapproved", "--run-id", "cli-negative", "--out-dir", out},
		{"run-profile", "--command", "echo forged-pass"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("unapproved execution returned %d: %s %s", code, stdout.String(), stderr.String())
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Fatal("invalid CLI input created output")
		}
	}
}
