package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Animus-OSC/argus-open/pkg/audit"
)

func TestAuditCLIReportsVerdictAndNeverOverwrites(t *testing.T) {
	for _, test := range []struct {
		name               string
		state              audit.State
		code, exit, checks int
		missing            bool
	}{
		{"pass", audit.Pass, 0, 0, 1, false}, {"fail", audit.Fail, 1, 1, 1, false},
		{"missing", audit.Blocked, 2, 0, 0, true}, {"uncertain", audit.Uncertain, 4, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			log := []byte("fixture observation, not real test evidence\n")
			if err := os.WriteFile(filepath.Join(dir, "stage.log"), log, 0600); err != nil {
				t.Fatal(err)
			}
			plan := audit.Plan{Version: audit.PlanVersion, RunID: "run-1", ProjectID: "project", Source: audit.Source{Repository: "fixture", SHA: strings.Repeat("a", 40)}, Stages: []audit.Stage{{ID: "unit", Kind: "unit"}}}
			planRaw, _ := json.Marshal(plan)
			observations := []audit.Observation{}
			if !test.missing {
				var code *int
				if test.state == audit.Pass || test.state == audit.Fail {
					value := test.exit
					code = &value
				}
				observations = append(observations, audit.Observation{StageID: "unit", State: test.state, ExitCode: code, ChecksRun: test.checks, Summary: "Fixture", Evidence: []audit.Artifact{{Path: "stage.log", SHA256: audit.Digest(log)}}})
			}
			result := audit.Results{Version: audit.ResultsVersion, PlanSHA256: audit.Digest(planRaw), RunID: plan.RunID, ProjectID: plan.ProjectID, SourceSHA: plan.Source.SHA, Stages: observations}
			resultRaw, _ := json.Marshal(result)
			planPath, resultsPath, out := filepath.Join(dir, "plan.json"), filepath.Join(dir, "results.json"), filepath.Join(dir, "audit.md")
			for p, data := range map[string][]byte{planPath: planRaw, resultsPath: resultRaw} {
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"audit", "--plan", planPath, "--plan-sha256", audit.Digest(planRaw), "--results", resultsPath, "--artifacts", dir, "--out", out}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != test.code {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			before, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(before, []byte("Result: **"+string(test.state)+"**")) {
				t.Fatalf("wrong report: %s", before)
			}
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("existing output returned %d", code)
			}
			after, _ := os.ReadFile(out)
			if !bytes.Equal(before, after) {
				t.Fatal("existing report overwritten")
			}
			args[4] = "sha256:" + strings.Repeat("0", 64)
			args[len(args)-1] = filepath.Join(dir, "must-not-exist.md")
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("untrusted plan accepted: %d", code)
			}
			if _, err := os.Lstat(args[len(args)-1]); !os.IsNotExist(err) {
				t.Fatal("invalid inputs produced report")
			}
		})
	}
}

func TestAuditCLIRequiresIndependentPlanDigest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"audit"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing inputs accepted: %d", code)
	}
}
