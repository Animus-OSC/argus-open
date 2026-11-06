package profile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Animus-OSC/argus-open/internal/source"
	"github.com/Animus-OSC/argus-open/pkg/audit"
)

type Config struct {
	Profile       string
	RepositoryDir string
	SourceSHA     string
	RunID         string
	OutputDir     string
}
type Outcome struct {
	State     audit.State
	Started   bool
	OutputDir string
}

var runID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type prepareFunc func(context.Context, string, string, string) (string, func(), error)
type executorFunc func(context.Context, string) execution

// Run executes only the reviewed SDK source and fixed unittest operation.
// OutputDir is reserved before any execution and is never reused or removed.
// This trusted local caller path provides no distributed idempotency or auth.
func Run(ctx context.Context, c Config) (Outcome, error) {
	return run(ctx, c, source.PreparePythonTree, executeSandbox)
}
func run(ctx context.Context, c Config, prepare prepareFunc, execute executorFunc) (Outcome, error) {
	out := Outcome{State: audit.Blocked, OutputDir: c.OutputDir}
	if c.Profile != ID || c.SourceSHA != SourceSHA || !runID.MatchString(c.RunID) || !filepath.IsAbs(c.RepositoryDir) || !filepath.IsAbs(c.OutputDir) {
		return out, errors.New("unapproved profile, source or paths")
	}
	repoInfo, repoErr := os.Lstat(c.RepositoryDir)
	repoResolved, repoResolveErr := filepath.EvalSymlinks(c.RepositoryDir)
	parentResolved, parentErr := filepath.EvalSymlinks(filepath.Dir(c.OutputDir))
	if repoErr != nil || repoResolveErr != nil || !repoInfo.IsDir() || repoResolved != filepath.Clean(c.RepositoryDir) || parentErr != nil || parentResolved != filepath.Clean(filepath.Dir(c.OutputDir)) || filepath.Clean(c.OutputDir) != c.OutputDir {
		return out, errors.New("profile paths require stable canonical directories")
	}
	relative, err := filepath.Rel(repoResolved, c.OutputDir)
	if err != nil || relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return out, errors.New("output must be outside source repository")
	}
	if err = os.Mkdir(c.OutputDir, 0700); err != nil {
		return out, errors.New("output directory must be new")
	}
	output, err := os.OpenRoot(c.OutputDir)
	if err != nil {
		return out, err
	}
	defer output.Close()
	write := func(name string, data []byte) error {
		f, err := output.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(data); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	put := func(name string, value any) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return write(name, append(raw, '\n'))
	}
	plan := audit.Plan{Version: audit.PlanVersion, RunID: c.RunID, ProjectID: "animus-datalab-sdk", Source: audit.Source{Repository: Repository, SHA: SourceSHA}, Stages: []audit.Stage{{ID: "source-snapshot", Kind: "static"}, {ID: "sdk-unit", Kind: "unit"}}}
	planRaw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return out, err
	}
	planRaw = append(planRaw, '\n')
	planDigest := audit.Digest(planRaw)
	for name, data := range map[string][]byte{"plan.json": planRaw, "plan.sha256": []byte(planDigest + "\n")} {
		if err = write(name, data); err != nil {
			return out, err
		}
	}
	if err = put("attempt.json", map[string]any{"version": "argus.profile-attempt/v1", "profile": ID, "source_sha": SourceSHA, "tree_sha256": TreeSHA256, "run_id": c.RunID, "plan_sha256": planDigest, "reserved_at": time.Now().UTC(), "scope": "reviewed pinned SDK unit tests only; no production authority"}); err != nil {
		return out, err
	}
	observations := []audit.Observation{}
	artifact := func(name string, raw []byte) audit.Artifact {
		return audit.Artifact{Path: name, SHA256: audit.Digest(raw)}
	}
	addFile := func(name string, raw []byte) (audit.Artifact, error) {
		err := write(name, raw)
		return artifact(name, raw), err
	}
	staging, err := os.MkdirTemp("", "argus-profile-stage-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(staging)
	snapshot, cleanup, sourceErr := prepare(ctx, staging, c.RepositoryDir, SourceSHA)
	if cleanup != nil {
		defer cleanup()
	}
	digest, count := "", 0
	if sourceErr == nil {
		digest, count, sourceErr = treeDigest(snapshot)
		if sourceErr == nil && (digest != TreeSHA256 || count != sourceFiles) {
			sourceErr = errors.New("unapproved source bytes")
		}
	}
	sourceState, sourceSummary := audit.Pass, "Reviewed committed Python subtree matched SHA-256 catalog; dirty worktree bytes were not used"
	if sourceErr != nil {
		sourceState, sourceSummary = audit.Blocked, "Reviewed source snapshot unavailable or does not match catalog"
	}
	sourceRecord, _ := json.MarshalIndent(map[string]any{"source_sha": SourceSHA, "expected_tree_sha256": TreeSHA256, "observed_tree_sha256": digest, "files": count, "state": sourceState}, "", "  ")
	sourceArtifact, err := addFile("source.json", append(sourceRecord, '\n'))
	if err != nil {
		return out, err
	}
	var zero = 0
	sourceObservation := audit.Observation{StageID: "source-snapshot", State: sourceState, ChecksRun: count, Summary: sourceSummary, Evidence: []audit.Artifact{sourceArtifact}}
	if sourceState == audit.Pass {
		sourceObservation.ExitCode = &zero
	}
	observations = append(observations, sourceObservation)
	if sourceErr != nil {
		observations = append(observations, audit.Observation{StageID: "sdk-unit", State: audit.NotRun, Summary: "No tests launched because source approval failed", Evidence: []audit.Artifact{}})
	} else {
		e := execute(ctx, snapshot)
		out.Started = e.Started
		if e.Started {
			out.State = audit.Uncertain
		}
		state, exit, checks, summary := assess(e)
		refs := []audit.Artifact{}
		for _, file := range []struct {
			name string
			raw  []byte
		}{{"unit-result.json", e.Stdout}, {"unit.stderr", e.Stderr}} {
			ref, err := addFile(file.name, file.raw)
			if err != nil {
				return out, err
			}
			refs = append(refs, ref)
		}
		process, _ := json.MarshalIndent(map[string]any{"started": e.Started, "exit_code": e.ExitCode, "timed_out": e.TimedOut, "cancelled": e.Cancelled, "uncertain": e.Uncertain, "truncated": e.Truncated, "started_at": e.StartedAt, "finished_at": e.FinishedAt}, "", "  ")
		ref, err := addFile("execution.json", append(process, '\n'))
		if err != nil {
			return out, err
		}
		refs = append(refs, ref)
		observations = append(observations, audit.Observation{StageID: "sdk-unit", State: state, ExitCode: exit, ChecksRun: checks, Summary: summary, Evidence: refs})
	}
	results := audit.Results{Version: audit.ResultsVersion, PlanSHA256: planDigest, RunID: c.RunID, ProjectID: plan.ProjectID, SourceSHA: SourceSHA, Stages: observations}
	raw, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return out, err
	}
	raw = append(raw, '\n')
	if err = write("results.json", raw); err != nil {
		return out, err
	}
	report, err := audit.Finalize(planRaw, planDigest, raw, c.OutputDir)
	if err != nil {
		return out, err
	}
	if err = write("audit.md", report.Markdown()); err != nil {
		return out, err
	}
	if err = put("complete.json", map[string]any{"version": "argus.profile-completion/v1", "state": report.State, "audit_sha256": audit.Digest(report.Markdown()), "completed_at": time.Now().UTC()}); err != nil {
		return out, err
	}
	out.State = report.State
	return out, nil
}

func assess(e execution) (audit.State, *int, int, string) {
	if !e.Started {
		return audit.Blocked, nil, 0, "Sandbox preflight refused; no SDK tests launched"
	}
	if e.TimedOut || e.Cancelled || e.Uncertain || e.Truncated || e.ExitCode < 0 {
		return audit.Uncertain, nil, 0, "Execution timed out, was cancelled or lost a complete bounded outcome; reconcile before retry"
	}
	report, err := parseTestReport(e.Stdout)
	if err != nil || !report.Completed {
		return audit.Uncertain, nil, 0, "Typed test completion is absent, malformed or incomplete"
	}
	if !strings.HasPrefix(report.PythonVersion, "3.12.") {
		return audit.Blocked, nil, 0, "The reviewed profile requires Python 3.12"
	}
	discovered := append([]string(nil), report.DiscoveredIDs...)
	sort.Strings(discovered)
	expected := append([]string(nil), expectedTestIDs...)
	sort.Strings(expected)
	if len(discovered) != len(expected) {
		return audit.Blocked, nil, 0, "Required test discovery differs from the reviewed catalog"
	}
	for i := range expected {
		if expected[i] != discovered[i] {
			return audit.Blocked, nil, 0, "Required test identities differ from the reviewed catalog"
		}
	}
	checks, failures, incomplete := 0, 0, false
	for _, record := range report.Records {
		if record.Status != "SKIP" {
			checks++
		}
		switch record.Status {
		case "FAIL", "ERROR":
			failures++
		case "SKIP", "XFAIL", "XPASS":
			incomplete = true
		}
	}
	if incomplete {
		return audit.Blocked, nil, checks, "Skipped or expected-failure tests do not satisfy the required unit profile"
	}
	if checks != len(expected) {
		return audit.Blocked, nil, checks, "Not every required test completed"
	}
	if failures > 0 && e.ExitCode == 1 {
		exit := 1
		return audit.Fail, &exit, checks, "Required SDK tests completed with observed failures or errors"
	}
	if failures == 0 && e.ExitCode == 0 {
		exit := 0
		return audit.Pass, &exit, checks, "All reviewed SDK unit tests completed successfully; this is not service, ML quality or production evidence"
	}
	return audit.Uncertain, nil, checks, "Process exit contradicts the typed test result"
}
