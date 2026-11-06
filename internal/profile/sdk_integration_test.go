//go:build linux && profile_integration

package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/pkg/audit"
)

// This explicit integration suite requires an operator-prepared ordinary clone.
// It never fetches a repository or dependencies and is excluded from core tests.
func sdkIntegrationRepository(t *testing.T) string {
	t.Helper()
	repo := os.Getenv("ARGUS_PROFILE_SDK_REPO")
	if !filepath.IsAbs(repo) || filepath.Clean(repo) != repo {
		t.Fatal("ARGUS_PROFILE_SDK_REPO must name an absolute canonical prepared SDK clone")
	}
	resolved, err := filepath.EvalSymlinks(repo)
	if err != nil || resolved != repo {
		t.Fatal("SDK clone cannot use symlink aliases", err)
	}
	for _, name := range []string{repo, filepath.Join(repo, ".git")} {
		info, err := os.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("an ordinary prepared SDK clone is required: %s: %v", name, err)
		}
	}
	return repo
}

// Faults alter only the trusted test driver's in-memory suite after discovery.
// They do not alter SDK source, profile pins or any production CLI capability.
func sdkIntegrationDriver(t *testing.T, injection string) []byte {
	t.Helper()
	marker := []byte("            suite.run(result)")
	if bytes.Count(driverSource, marker) != 1 {
		t.Fatal("fixed driver injection point changed")
	}
	return bytes.Replace(driverSource, marker, []byte(injection+"\n            suite.run(result)"), 1)
}

const sdkFirstCase = `            def _argus_cases(current):
                for item in current:
                    if isinstance(item, unittest.TestSuite):
                        yield from _argus_cases(item)
                    else:
                        yield item
            first = next(_argus_cases(suite))
`

func sdkIntegrationArtifacts(t *testing.T, c Config, out Outcome, want audit.State, wantChecks int) {
	t.Helper()
	if !out.Started || out.State != want {
		t.Fatalf("outcome=%+v want started/%s", out, want)
	}
	read := func(name string) []byte {
		t.Helper()
		path := filepath.Join(c.OutputDir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("missing/nonprivate artifact %s: %v", name, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, name := range []string{"attempt.json", "source.json", "execution.json", "unit-result.json", "unit.stderr"} {
		read(name)
	}
	planRaw, planDigest, resultsRaw := read("plan.json"), strings.TrimSpace(string(read("plan.sha256"))), read("results.json")
	report, err := audit.Finalize(planRaw, planDigest, resultsRaw, c.OutputDir)
	if err != nil || report.State != want {
		t.Fatalf("persisted evidence does not finalize to %s: %+v %v", want, report, err)
	}
	md := read("audit.md")
	if !bytes.Equal(md, report.Markdown()) || !bytes.Contains(md, []byte(fmt.Sprintf("Result: **%s**", want))) {
		t.Fatalf("audit does not match finalized state %s", want)
	}
	var results audit.Results
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		t.Fatal(err)
	}
	if len(results.Stages) != 2 || results.Stages[0].StageID != "source-snapshot" || results.Stages[0].State != audit.Pass ||
		results.Stages[1].StageID != "sdk-unit" || results.Stages[1].State != want || results.Stages[1].ChecksRun != wantChecks {
		t.Fatalf("wrong persisted stage observations: %+v", results.Stages)
	}
	unit := results.Stages[1]
	if want == audit.Pass || want == audit.Fail {
		exit := 0
		if want == audit.Fail {
			exit = 1
		}
		if unit.ExitCode == nil || *unit.ExitCode != exit {
			t.Fatalf("wrong completed exit: %+v", unit)
		}
	} else if unit.ExitCode != nil {
		t.Fatalf("non-completed state has exit code: %+v", unit)
	}
	var complete struct {
		Version     string      `json:"version"`
		State       audit.State `json:"state"`
		AuditSHA256 string      `json:"audit_sha256"`
		CompletedAt time.Time   `json:"completed_at"`
	}
	if err := json.Unmarshal(read("complete.json"), &complete); err != nil {
		t.Fatal(err)
	}
	if complete.Version != "argus.profile-completion/v1" || complete.State != want || complete.AuditSHA256 != audit.Digest(md) || complete.CompletedAt.IsZero() {
		t.Fatalf("incorrect durable completion marker: %+v", complete)
	}
	var sourceRecord struct {
		SHA      string      `json:"source_sha"`
		Expected string      `json:"expected_tree_sha256"`
		Observed string      `json:"observed_tree_sha256"`
		Files    int         `json:"files"`
		State    audit.State `json:"state"`
	}
	if err := json.Unmarshal(read("source.json"), &sourceRecord); err != nil {
		t.Fatal(err)
	}
	if sourceRecord.SHA != SourceSHA || sourceRecord.Expected != TreeSHA256 || sourceRecord.Observed != TreeSHA256 || sourceRecord.Files != sourceFiles || sourceRecord.State != audit.Pass {
		t.Fatalf("actual SDK source was not approved: %+v", sourceRecord)
	}
	info, err := os.Stat(c.OutputDir)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("evidence directory not private", err)
	}
}

func TestSDKProfileIntegration(t *testing.T) {
	repo := sdkIntegrationRepository(t)
	cases := []struct {
		name         string
		injection    string
		want         audit.State
		checks       int
		interruption string
	}{
		{"production_driver", "", audit.Pass, 33, ""},
		{"assertion_failure", sdkFirstCase + `            def _argus_fail():
                raise AssertionError("argus integration forced assertion")
            setattr(first, first._testMethodName, _argus_fail)`, audit.Fail, 33, ""},
		{"required_test_skip", sdkFirstCase + `            def _argus_skip():
                raise unittest.SkipTest("argus integration forced skip")
            setattr(first, first._testMethodName, _argus_skip)`, audit.Blocked, 32, ""},
		{"empty_discovery", `            suite = unittest.TestSuite()
            report["discovered_ids"] = []`, audit.Blocked, 0, ""},
		{"early_exit", `            __import__("os")._exit(0)`, audit.Uncertain, 0, ""},
		{"deadline", `            __import__("time").sleep(10)`, audit.Uncertain, 0, "deadline"},
		{"cancellation", `            __import__("time").sleep(10)`, audit.Uncertain, 0, "cancel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Profile: ID, RepositoryDir: repo, SourceSHA: SourceSHA, RunID: "sdk-integration-" + tc.name, OutputDir: filepath.Join(t.TempDir(), "evidence")}
			var actual execution
			executor := func(ctx context.Context, snapshot string) execution {
				if tc.injection == "" {
					actual = executeSandbox(ctx, snapshot)
					return actual
				}
				driver := sdkIntegrationDriver(t, tc.injection)
				if tc.interruption == "deadline" {
					child, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					actual = executeSandboxWithDriver(child, snapshot, driver)
				} else if tc.interruption == "cancel" {
					child, cancel := context.WithCancel(ctx)
					defer cancel()
					timer := time.AfterFunc(2*time.Second, cancel)
					defer timer.Stop()
					actual = executeSandboxWithDriver(child, snapshot, driver)
				} else {
					actual = executeSandboxWithDriver(ctx, snapshot, driver)
				}
				return actual
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := run(ctx, c, source.PreparePythonTree, executor)
			if err != nil {
				t.Fatalf("real profile orchestration error: %v (execution=%+v)", err, actual)
			}
			sdkIntegrationArtifacts(t, c, out, tc.want, tc.checks)
			if tc.interruption == "deadline" && !actual.TimedOut {
				t.Fatalf("deadline did not interrupt actual process: %+v", actual)
			}
			if tc.interruption == "cancel" && !actual.Cancelled {
				t.Fatalf("cancellation did not interrupt actual process: %+v", actual)
			}
			if tc.name == "early_exit" && (actual.ExitCode != 0 || len(actual.Stdout) != 0) {
				t.Fatalf("early exit fault was not exercised: %+v", actual)
			}
			if tc.name == "assertion_failure" && !bytes.Contains(actual.Stderr, []byte("AssertionError: argus integration forced assertion")) {
				t.Fatal("full pipeline lost the actual failure traceback")
			}
			if tc.name == "production_driver" || tc.name == "assertion_failure" || tc.name == "required_test_skip" {
				report, err := parseTestReport(actual.Stdout)
				if err != nil || !report.Completed || len(report.DiscoveredIDs) != 33 || len(report.Records) != 33 {
					t.Fatalf("actual reviewed test execution incomplete: %+v %v", report, err)
				}
				expected := map[string]bool{}
				for _, id := range expectedTestIDs {
					expected[id] = true
				}
				counts := map[string]int{}
				for _, record := range report.Records {
					if !expected[record.ID] {
						t.Fatalf("unexpected test identity %q", record.ID)
					}
					counts[record.Status]++
				}
				switch tc.name {
				case "production_driver":
					if counts["PASS"] != 33 {
						t.Fatalf("wrong actual outcomes: %v", counts)
					}
				case "assertion_failure":
					if counts["PASS"] != 32 || counts["FAIL"] != 1 {
						t.Fatalf("wrong injected outcomes: %v", counts)
					}
				case "required_test_skip":
					if counts["PASS"] != 32 || counts["SKIP"] != 1 {
						t.Fatalf("wrong injected outcomes: %v", counts)
					}
				}
			}
		})
	}
}
