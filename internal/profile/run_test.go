package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Animus-OSC/argus-open/pkg/audit"
)

func runApprovedReport(t *testing.T) testReport {
	t.Helper()
	if len(expectedTestIDs) != 33 {
		t.Fatal("the approved SDK profile must retain its reviewed 33 test identities")
	}
	r := testReport{Version: "argus.unittest/v1", PythonVersion: "3.12.3", DiscoveredIDs: append([]string(nil), expectedTestIDs...), Records: []testRecord{}, Completed: true}
	for _, id := range expectedTestIDs {
		r.Records = append(r.Records, testRecord{ID: id, Status: "PASS"})
	}
	return r
}

func runReportedExecution(t *testing.T, report testReport) execution {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return execution{Started: true, ExitCode: 0, Stdout: raw, Stderr: []byte("bounded unittest log\n"), StartedAt: now, FinishedAt: now.Add(time.Second)}
}

func TestAssessCompleteReviewedSDKTests(t *testing.T) {
	for _, status := range []string{"PASS", "FAIL", "ERROR"} {
		t.Run(status, func(t *testing.T) {
			r := runApprovedReport(t)
			r.Records[0].Status = status
			e := runReportedExecution(t, r)
			want, exit := audit.Pass, 0
			if status != "PASS" {
				want, exit, e.ExitCode = audit.Fail, 1, 1
			}
			state, code, checks, summary := assess(e)
			if state != want || code == nil || *code != exit || checks != 33 || summary == "" {
				t.Fatalf("wrong assessment: state=%s exit=%v checks=%d summary=%q", state, code, checks, summary)
			}
		})
	}
}

func TestAssessIncompleteOrDifferentTestCatalogNeverPasses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testReport)
		want audit.State
	}{
		{"zero tests", func(r *testReport) { r.DiscoveredIDs, r.Records = []string{}, []testRecord{} }, audit.Blocked},
		{"dropped required test", func(r *testReport) { r.DiscoveredIDs, r.Records = r.DiscoveredIDs[1:], r.Records[1:] }, audit.Blocked},
		{"unknown test", func(r *testReport) {
			r.DiscoveredIDs[0], r.Records[0].ID = "unknown.TestCase.test_extra", "unknown.TestCase.test_extra"
		}, audit.Blocked},
		{"missing terminal record", func(r *testReport) { r.Records = r.Records[1:] }, audit.Uncertain},
		{"incomplete driver", func(r *testReport) { r.Completed = false }, audit.Uncertain},
		{"different Python minor", func(r *testReport) { r.PythonVersion = "3.13.1" }, audit.Blocked},
		{"skip", func(r *testReport) { r.Records[0].Status = "SKIP" }, audit.Blocked},
		{"expected failure", func(r *testReport) { r.Records[0].Status = "XFAIL" }, audit.Blocked},
		{"unexpected success", func(r *testReport) { r.Records[0].Status = "XPASS" }, audit.Blocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runApprovedReport(t)
			c.edit(&r)
			state, exit, _, _ := assess(runReportedExecution(t, r))
			if state != c.want || exit != nil {
				t.Fatalf("incomplete profile assessed %s exit=%v; want %s with no completed exit", state, exit, c.want)
			}
		})
	}
}

func TestAssessProcessContradictionsAndLostCompletion(t *testing.T) {
	cases := []struct {
		name string
		edit func(*execution)
		want audit.State
	}{
		{"not launched", func(e *execution) { e.Started = false }, audit.Blocked},
		{"timeout", func(e *execution) { e.TimedOut = true }, audit.Uncertain},
		{"cancelled", func(e *execution) { e.Cancelled = true }, audit.Uncertain},
		{"worker uncertainty", func(e *execution) { e.Uncertain = true }, audit.Uncertain},
		{"truncated log", func(e *execution) { e.Truncated = true }, audit.Uncertain},
		{"signal", func(e *execution) { e.ExitCode = -1 }, audit.Uncertain},
		{"missing typed result", func(e *execution) { e.Stdout = nil }, audit.Uncertain},
		{"malformed typed result", func(e *execution) { e.Stdout = []byte(`{"completed":true}`) }, audit.Uncertain},
		{"trailing data", func(e *execution) { e.Stdout = append(e.Stdout, []byte(" {}")...) }, audit.Uncertain},
		{"duplicate completion field", func(e *execution) {
			e.Stdout = bytes.Replace(e.Stdout, []byte(`"completed":true`), []byte(`"completed":true,"completed":true`), 1)
		}, audit.Uncertain},
		{"nonzero exit with all PASS", func(e *execution) { e.ExitCode = 1 }, audit.Uncertain},
		{"unexpected exit code", func(e *execution) { e.ExitCode = 7 }, audit.Uncertain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := runReportedExecution(t, runApprovedReport(t))
			c.edit(&e)
			state, exit, _, _ := assess(e)
			if state != c.want || exit != nil {
				t.Fatalf("lost/contradictory process accepted as %s exit=%v; want %s", state, exit, c.want)
			}
		})
	}
	t.Run("zero exit with observed FAIL", func(t *testing.T) {
		r := runApprovedReport(t)
		r.Records[0].Status = "FAIL"
		state, exit, _, _ := assess(runReportedExecution(t, r))
		if state != audit.Uncertain || exit != nil {
			t.Fatalf("contradictory failure accepted as %s exit=%v", state, exit)
		}
	})
}

func runTestConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "registered-sdk")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Profile: ID, RepositoryDir: repo, SourceSHA: SourceSHA, RunID: "local-profile-test", OutputDir: filepath.Join(root, "new-report")}
}

func runForbiddenCallbacks(t *testing.T) (prepareFunc, executorFunc, *int, *int) {
	t.Helper()
	prepares, executions := new(int), new(int)
	prepare := func(context.Context, string, string, string) (string, func(), error) {
		*prepares++
		return "", nil, errors.New("prepare must not be reached")
	}
	execute := func(context.Context, string) execution {
		*executions++
		return execution{Started: true, ExitCode: 0}
	}
	return prepare, execute, prepares, executions
}

func TestRunRejectsUnapprovedInputBeforeReservingOrExecuting(t *testing.T) {
	for _, name := range []string{"profile", "source", "run ID", "relative repo", "relative output"} {
		t.Run(name, func(t *testing.T) {
			c := runTestConfig(t)
			originalOut := c.OutputDir
			switch name {
			case "profile":
				c.Profile = "arbitrary-shell/v1"
			case "source":
				c.SourceSHA = strings.Repeat("b", 40)
			case "run ID":
				c.RunID = "run\nforged"
			case "relative repo":
				c.RepositoryDir = "relative-repository"
			case "relative output":
				c.OutputDir = "relative-output"
			}
			prepare, execute, prepares, executions := runForbiddenCallbacks(t)
			out, err := run(context.Background(), c, prepare, execute)
			if err == nil || out.State != audit.Blocked || out.Started || *prepares != 0 || *executions != 0 {
				t.Fatalf("unapproved input progressed: out=%+v err=%v prepares=%d executions=%d", out, err, *prepares, *executions)
			}
			if _, err := os.Lstat(originalOut); !os.IsNotExist(err) {
				t.Fatal("unapproved input reserved output", err)
			}
		})
	}
}

func TestRunExistingOutputNeverExecutesOrOverwrites(t *testing.T) {
	c := runTestConfig(t)
	if err := os.Mkdir(c.OutputDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(c.OutputDir, "preserve.txt")
	if err := os.WriteFile(marker, []byte("existing evidence\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prepare, execute, prepares, executions := runForbiddenCallbacks(t)
	out, err := run(context.Background(), c, prepare, execute)
	if err == nil || out.State != audit.Blocked || out.Started || *prepares != 0 || *executions != 0 {
		t.Fatalf("existing output reused: %+v, %v", out, err)
	}
	got, err := os.ReadFile(marker)
	entries, listErr := os.ReadDir(c.OutputDir)
	if err != nil || listErr != nil || string(got) != "existing evidence\n" || len(entries) != 1 {
		t.Fatal("existing evidence modified")
	}
}

func TestRunRejectsOutputWithinSourceIncludingHiddenPaths(t *testing.T) {
	for _, name := range []string{"ordinary", "hidden", "git metadata"} {
		t.Run(name, func(t *testing.T) {
			c := runTestConfig(t)
			parent := c.RepositoryDir
			if name == "hidden" {
				parent = filepath.Join(parent, ".hidden")
			}
			if name == "git metadata" {
				parent = filepath.Join(parent, ".git")
			}
			if err := os.MkdirAll(parent, 0700); err != nil {
				t.Fatal(err)
			}
			c.OutputDir = filepath.Join(parent, "must-not-exist")
			prepare, execute, prepares, executions := runForbiddenCallbacks(t)
			out, err := run(context.Background(), c, prepare, execute)
			if err == nil || out.Started || *prepares != 0 || *executions != 0 {
				t.Fatalf("output inside source accepted: %+v %v", out, err)
			}
			if _, err := os.Lstat(c.OutputDir); !os.IsNotExist(err) {
				t.Fatal("source directory changed", err)
			}
		})
	}
}

func TestRunRejectsSymlinkAliasesBeforeOutputCreation(t *testing.T) {
	for _, mode := range []string{"repository alias", "output into source alias", "output outside source alias"} {
		t.Run(mode, func(t *testing.T) {
			c := runTestConfig(t)
			root := filepath.Dir(c.RepositoryDir)
			if mode == "repository alias" {
				alias := filepath.Join(root, "repository-alias")
				if err := os.Symlink(c.RepositoryDir, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				c.RepositoryDir = alias
			} else {
				target := filepath.Join(c.RepositoryDir, ".hidden")
				if mode == "output outside source alias" {
					target = filepath.Join(root, "outside")
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(root, "output-alias")
				if err := os.Symlink(target, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				c.OutputDir = filepath.Join(alias, "must-not-exist")
			}
			prepare, execute, prepares, executions := runForbiddenCallbacks(t)
			out, err := run(context.Background(), c, prepare, execute)
			if err == nil || out.Started || *prepares != 0 || *executions != 0 {
				t.Fatalf("ambiguous path accepted: %+v %v", out, err)
			}
			if _, err := os.Lstat(c.OutputDir); !os.IsNotExist(err) {
				t.Fatal("alias output created", err)
			}
		})
	}
}

func runCheckBlockedReport(t *testing.T, c Config, out Outcome, err error) {
	t.Helper()
	if err != nil || out.State != audit.Blocked || out.Started {
		t.Fatalf("failed source outcome: %+v %v", out, err)
	}
	raw, err := os.ReadFile(filepath.Join(c.OutputDir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results audit.Results
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatal(err)
	}
	if len(results.Stages) != 2 || results.Stages[0].StageID != "source-snapshot" || results.Stages[0].State != audit.Blocked || results.Stages[0].ExitCode != nil || results.Stages[1].StageID != "sdk-unit" || results.Stages[1].State != audit.NotRun || results.Stages[1].ExitCode != nil || results.Stages[1].ChecksRun != 0 {
		t.Fatalf("source failure lost honest stage states: %+v", results)
	}
	md, err := os.ReadFile(filepath.Join(c.OutputDir, "audit.md"))
	if err != nil || !bytes.Contains(md, []byte("Result: **BLOCKED**")) || !bytes.Contains(md, []byte("NOT_RUN")) {
		t.Fatalf("blocked audit unavailable: %v %s", err, md)
	}
	if _, err := os.Stat(filepath.Join(c.OutputDir, "complete.json")); err != nil {
		t.Fatal("honest blocked completion marker missing", err)
	}
	info, err := os.Stat(c.OutputDir)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("output directory is not private", err)
	}
	entries, err := os.ReadDir(c.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("nonprivate output artifact: %s %v", entry.Name(), err)
		}
	}
}

func TestRunSourcePreparationFailureProducesBlockedAuditWithoutExecution(t *testing.T) {
	c := runTestConfig(t)
	prepares, executions, cleanups := 0, 0, 0
	prepare := func(ctx context.Context, staging, repo, sha string) (string, func(), error) {
		prepares++
		if ctx == nil || repo != c.RepositoryDir || sha != SourceSHA || !filepath.IsAbs(staging) {
			t.Fatal("wrong source preparation scope")
		}
		return "", func() { cleanups++ }, errors.New("fixture source unavailable")
	}
	execute := func(context.Context, string) execution { executions++; return execution{Started: true, ExitCode: 0} }
	out, err := run(context.Background(), c, prepare, execute)
	runCheckBlockedReport(t, c, out, err)
	if prepares != 1 || executions != 0 || cleanups != 1 {
		t.Fatalf("prepare=%d execute=%d cleanup=%d", prepares, executions, cleanups)
	}
}

func TestRunMismatchedContentPinFailsBeforeExecution(t *testing.T) {
	c := runTestConfig(t)
	executions, cleanups := 0, 0
	prepare := func(_ context.Context, staging, _, _ string) (string, func(), error) {
		snapshot, err := os.MkdirTemp(staging, "snapshot-")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(snapshot, "python"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapshot, "python", "changed.py"), []byte("unapproved bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return snapshot, func() { cleanups++; _ = os.RemoveAll(snapshot) }, nil
	}
	execute := func(context.Context, string) execution { executions++; return execution{Started: true, ExitCode: 0} }
	out, err := run(context.Background(), c, prepare, execute)
	runCheckBlockedReport(t, c, out, err)
	if executions != 0 || cleanups != 1 {
		t.Fatalf("changed source executed=%d cleanup=%d", executions, cleanups)
	}
	raw, err := os.ReadFile(filepath.Join(c.OutputDir, "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	if source["expected_tree_sha256"] != TreeSHA256 || source["observed_tree_sha256"] == TreeSHA256 || source["state"] != "BLOCKED" {
		t.Fatalf("content mismatch not recorded: %+v", source)
	}
}
