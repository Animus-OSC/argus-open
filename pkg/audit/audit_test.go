package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Animus-OSC/argus-open/pkg/audit"
)

const bodyMarker = "RAW_ARTIFACT_BODY_MUST_NOT_APPEAR_IN_MARKDOWN"

type fixture struct {
	plan    audit.Plan
	results audit.Results
	dir     string
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func newFixture(t *testing.T, ids ...string) *fixture {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{"unit"}
	}
	f := &fixture{dir: t.TempDir()}
	body := []byte(bodyMarker + "\n<script>private artifact</script>\n")
	if e := os.WriteFile(filepath.Join(f.dir, "output.log"), body, 0600); e != nil {
		t.Fatal(e)
	}
	f.plan = audit.Plan{Version: audit.PlanVersion, RunID: "run-1", ProjectID: "project-1", Source: audit.Source{Repository: "https://example.invalid/project", SHA: strings.Repeat("a", 40)}}
	for _, id := range ids {
		f.plan.Stages = append(f.plan.Stages, audit.Stage{ID: id, Kind: "unit"})
	}
	f.results = audit.Results{Version: audit.ResultsVersion, PlanSHA256: audit.Digest(encode(t, f.plan)), RunID: f.plan.RunID, ProjectID: f.plan.ProjectID, SourceSHA: f.plan.Source.SHA}
	for _, id := range ids {
		exit := 0
		f.results.Stages = append(f.results.Stages, audit.Observation{StageID: id, State: audit.Pass, ExitCode: &exit, ChecksRun: 2, Summary: "Observed two deterministic checks", Evidence: []audit.Artifact{{Path: "output.log", SHA256: audit.Digest(body)}}})
	}
	return f
}
func (f *fixture) finalize(t *testing.T) (audit.Report, error) {
	t.Helper()
	p := encode(t, f.plan)
	return audit.Finalize(p, audit.Digest(p), encode(t, f.results), f.dir)
}
func object(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func observation(v map[string]any) map[string]any { return v["stages"].([]any)[0].(map[string]any) }
func artifact(v map[string]any) map[string]any {
	return observation(v)["evidence"].([]any)[0].(map[string]any)
}

func TestFinalizeCompletedPassAndFail(t *testing.T) {
	for _, state := range []audit.State{audit.Pass, audit.Fail} {
		t.Run(string(state), func(t *testing.T) {
			f := newFixture(t, "unit", "security")
			wantExit := 0
			if state == audit.Fail {
				exit := 7
				f.results.Stages[1].State = audit.Fail
				f.results.Stages[1].ExitCode = &exit
				wantExit = 1
			}
			r, e := f.finalize(t)
			if e != nil {
				t.Fatal(e)
			}
			if r.State != state || r.ExitCode() != wantExit || len(r.Stages) != 2 {
				t.Fatalf("unexpected completed verdict: %+v, exit %d", r, r.ExitCode())
			}
			if r.PlanSHA256 != audit.Digest(encode(t, f.plan)) || r.ResultsSHA256 != audit.Digest(encode(t, f.results)) {
				t.Fatal("lost exact input binding")
			}
			for _, s := range r.Stages {
				if s.Integrity != "CHECKED" || s.ChecksRun != 2 {
					t.Fatalf("incomplete stage accepted: %+v", s)
				}
			}
		})
	}
}
func TestMissingObservationsBlockCompleteAudit(t *testing.T) {
	for _, keep := range []int{0, 1} {
		t.Run(fmt.Sprintf("observed_%d_of_2", keep), func(t *testing.T) {
			f := newFixture(t, "unit", "security")
			f.results.Stages = f.results.Stages[:keep]
			r, e := f.finalize(t)
			if e != nil {
				t.Fatal(e)
			}
			if r.State != audit.Blocked || r.ExitCode() != 2 || len(r.Stages) != 2 {
				t.Fatalf("missing observations produced completion: %+v", r)
			}
			if r.Stages[1].Reported != audit.NotRun || r.Stages[1].State != audit.NotRun {
				t.Fatal("missing stage lost NOT_RUN")
			}
		})
	}
}
func TestUncertainHasPrecedenceOverFailureAndMissingEvidence(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprintf("uncertain_first_%t", first), func(t *testing.T) {
			f := newFixture(t, "a", "b", "missing")
			f.results.Stages = f.results.Stages[:2]
			u, failed := 0, 1
			if !first {
				u, failed = 1, 0
			}
			f.results.Stages[u].State = audit.Uncertain
			f.results.Stages[u].ExitCode = nil
			f.results.Stages[u].Evidence[0].SHA256 = audit.Digest([]byte("substituted"))
			exit := 9
			f.results.Stages[failed].State = audit.Fail
			f.results.Stages[failed].ExitCode = &exit
			r, e := f.finalize(t)
			if e != nil {
				t.Fatal(e)
			}
			if r.State != audit.Uncertain || r.ExitCode() != 4 {
				t.Fatalf("unknown execution downgraded: %+v", r)
			}
			if r.Stages[u].State != audit.Uncertain || r.Stages[u].Integrity != "FAILED" {
				t.Fatalf("uncertain/integrity distinction lost: %+v", r.Stages[u])
			}
		})
	}
}
func TestNonCompletedObservationsRemainIncomplete(t *testing.T) {
	for _, state := range []audit.State{audit.Blocked, audit.NotRun, audit.Uncertain} {
		t.Run(string(state), func(t *testing.T) {
			f := newFixture(t)
			o := &f.results.Stages[0]
			o.State = state
			o.ExitCode = nil
			o.ChecksRun = 0
			o.Evidence = []audit.Artifact{}
			r, e := f.finalize(t)
			if e != nil {
				t.Fatal(e)
			}
			want := state
			if state == audit.NotRun {
				want = audit.Blocked
			}
			if r.State != want || r.Stages[0].Reported != state || r.Stages[0].Integrity != "NOT_CHECKED" {
				t.Fatalf("incomplete state changed: %+v", r)
			}
		})
	}
}

func TestResultWireRejectsInvalidTypesFieldsAndScope(t *testing.T) {
	f := newFixture(t)
	p := encode(t, f.plan)
	base := encode(t, f.results)
	cases := map[string]func(map[string]any){
		"wrong run":                func(v map[string]any) { v["run_id"] = "other" },
		"wrong project":            func(v map[string]any) { v["project_id"] = "other" },
		"wrong source":             func(v map[string]any) { v["source_sha"] = strings.Repeat("b", 40) },
		"wrong plan digest":        func(v map[string]any) { v["plan_sha256"] = audit.Digest([]byte("other plan")) },
		"wrong version":            func(v map[string]any) { v["version"] = "argus.audit-results/v2" },
		"unknown observation":      func(v map[string]any) { observation(v)["stage_id"] = "not-declared" },
		"unknown state":            func(v map[string]any) { observation(v)["state"] = "SUCCESS" },
		"zero checks":              func(v map[string]any) { observation(v)["checks_run"] = 0 },
		"negative checks":          func(v map[string]any) { observation(v)["checks_run"] = -1 },
		"fractional checks":        func(v map[string]any) { observation(v)["checks_run"] = 1.5 },
		"boolean checks":           func(v map[string]any) { observation(v)["checks_run"] = true },
		"string checks":            func(v map[string]any) { observation(v)["checks_run"] = "2" },
		"null PASS exit":           func(v map[string]any) { observation(v)["exit_code"] = nil },
		"string exit":              func(v map[string]any) { observation(v)["exit_code"] = "0" },
		"fractional exit":          func(v map[string]any) { observation(v)["exit_code"] = 0.5 },
		"negative exit":            func(v map[string]any) { observation(v)["exit_code"] = -1 },
		"out of range exit":        func(v map[string]any) { observation(v)["exit_code"] = 256 },
		"nonzero PASS exit":        func(v map[string]any) { observation(v)["exit_code"] = 1 },
		"zero FAIL exit":           func(v map[string]any) { observation(v)["state"] = "FAIL" },
		"number noncompleted exit": func(v map[string]any) { observation(v)["state"] = "BLOCKED" },
		"no completed artifacts":   func(v map[string]any) { observation(v)["evidence"] = []any{} },
		"empty summary":            func(v map[string]any) { observation(v)["summary"] = "" },
		"newline summary":          func(v map[string]any) { observation(v)["summary"] = "good\n# forged result" },
		"bidi summary":             func(v map[string]any) { observation(v)["summary"] = "good\u202eforged" },
		"unknown field":            func(v map[string]any) { v["authority"] = "release" },
		"case alias": func(v map[string]any) {
			observation(v)["STATE"] = observation(v)["state"]
			delete(observation(v), "state")
		},
		"duplicate observation": func(v map[string]any) { v["stages"] = []any{observation(v), observation(v)} },
		"duplicate artifact":    func(v map[string]any) { observation(v)["evidence"] = []any{artifact(v), artifact(v)} },
	}
	for _, key := range []string{"version", "plan_sha256", "run_id", "project_id", "source_sha", "stages"} {
		key := key
		cases["missing root "+key] = func(v map[string]any) { delete(v, key) }
		cases["null root "+key] = func(v map[string]any) { v[key] = nil }
	}
	for _, key := range []string{"stage_id", "state", "exit_code", "checks_run", "summary", "evidence"} {
		key := key
		cases["missing observation "+key] = func(v map[string]any) { delete(observation(v), key) }
		if key != "exit_code" {
			cases["null observation "+key] = func(v map[string]any) { observation(v)[key] = nil }
		}
	}
	for _, key := range []string{"path", "sha256"} {
		key := key
		cases["missing artifact "+key] = func(v map[string]any) { delete(artifact(v), key) }
		cases["null artifact "+key] = func(v map[string]any) { artifact(v)[key] = nil }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := object(t, base)
			mutate(v)
			r, e := audit.Finalize(p, audit.Digest(p), encode(t, v), f.dir)
			if e == nil {
				t.Fatalf("invalid wire accepted as %s", r.State)
			}
		})
	}
}
func TestPlanWireRejectsInvalidRequiredFieldsAndStageCatalog(t *testing.T) {
	f := newFixture(t)
	base := encode(t, f.plan)
	cases := map[string]func(map[string]any){
		"empty stages":    func(v map[string]any) { v["stages"] = []any{} },
		"unknown kind":    func(v map[string]any) { v["stages"].([]any)[0].(map[string]any)["kind"] = "deploy-production" },
		"duplicate stage": func(v map[string]any) { v["stages"] = []any{v["stages"].([]any)[0], v["stages"].([]any)[0]} },
		"invalid SHA":     func(v map[string]any) { v["source"].(map[string]any)["sha"] = "deadbeef" },
		"source case alias": func(v map[string]any) {
			v["source"].(map[string]any)["SHA"] = v["source"].(map[string]any)["sha"]
			delete(v["source"].(map[string]any), "sha")
		},
		"wrong stage type":   func(v map[string]any) { v["stages"] = map[string]any{"unit": true} },
		"unknown root field": func(v map[string]any) { v["approved"] = true },
	}
	for _, key := range []string{"version", "run_id", "project_id", "source", "stages"} {
		key := key
		cases["missing "+key] = func(v map[string]any) { delete(v, key) }
		cases["null "+key] = func(v map[string]any) { v[key] = nil }
	}
	for _, key := range []string{"repository", "sha"} {
		key := key
		cases["null source "+key] = func(v map[string]any) { v["source"].(map[string]any)[key] = nil }
		cases["missing source "+key] = func(v map[string]any) { delete(v["source"].(map[string]any), key) }
	}
	for _, key := range []string{"id", "kind"} {
		key := key
		cases["null stage "+key] = func(v map[string]any) { v["stages"].([]any)[0].(map[string]any)[key] = nil }
		cases["missing stage "+key] = func(v map[string]any) { delete(v["stages"].([]any)[0].(map[string]any), key) }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := object(t, base)
			mutate(v)
			p := encode(t, v)
			r, e := audit.Finalize(p, audit.Digest(p), encode(t, f.results), f.dir)
			if e == nil {
				t.Fatalf("invalid plan accepted as %s", r.State)
			}
		})
	}
}
func TestRawJSONAmbiguityAndBoundsNeverProducePass(t *testing.T) {
	f := newFixture(t)
	p := encode(t, f.plan)
	r := encode(t, f.results)
	cases := []struct {
		name          string
		plan, results []byte
		expected      string
	}{
		{"untrusted plan digest", p, r, audit.Digest([]byte("different approved plan"))},
		{"empty plan", nil, r, audit.Digest(nil)}, {"empty results", p, nil, audit.Digest(p)},
		{"plan trailing", append(bytes.Clone(p), []byte(" {}")...), r, ""},
		{"results trailing", p, append(bytes.Clone(r), []byte(" {}")...), audit.Digest(p)},
		{"plan duplicate", bytes.Replace(p, []byte(`"run_id":"run-1"`), []byte(`"run_id":"run-1","run_id":"run-1"`), 1), r, ""},
		{"results duplicate", p, bytes.Replace(r, []byte(`"checks_run":2`), []byte(`"checks_run":2,"checks_run":0`), 1), audit.Digest(p)},
		{"plan oversized", append(bytes.Clone(p), bytes.Repeat([]byte(" "), audit.MaxPlanBytes)...), r, ""},
		{"results oversized", p, append(bytes.Clone(r), bytes.Repeat([]byte(" "), audit.MaxResultsBytes)...), audit.Digest(p)},
		{"invalid UTF8", p, append(bytes.Clone(r), 0xff), audit.Digest(p)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected := tc.expected
			if expected == "" {
				expected = audit.Digest(tc.plan)
			}
			out, e := audit.Finalize(tc.plan, expected, tc.results, f.dir)
			if e == nil {
				t.Fatalf("ambiguous/unbounded wire accepted as %s", out.State)
			}
		})
	}
}
func TestArtifactReferenceMustBeRelativeCanonicalAndUnique(t *testing.T) {
	for _, name := range []string{"../outside.log", "/etc/passwd", "./output.log", "nested/../output.log", "nested//output.log", "nested\\output.log", "C:output.log", "."} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.results.Stages[0].Evidence[0].Path = name
			r, e := f.finalize(t)
			if e == nil {
				t.Fatalf("non-contained reference accepted as %s", r.State)
			}
		})
	}
}
func TestUnverifiableArtifactsBlockInsteadOfChangingTestVerdict(t *testing.T) {
	for _, condition := range []string{"hash mismatch", "missing", "directory", "oversized", "leaf symlink", "parent symlink", "unix socket"} {
		t.Run(condition, func(t *testing.T) {
			f := newFixture(t)
			a := &f.results.Stages[0].Evidence[0]
			switch condition {
			case "hash mismatch":
				a.SHA256 = audit.Digest([]byte("substituted bytes"))
			case "missing":
				a.Path = "absent.log"
			case "directory":
				a.Path = "directory"
				if e := os.Mkdir(filepath.Join(f.dir, a.Path), 0700); e != nil {
					t.Fatal(e)
				}
			case "oversized":
				file, e := os.Create(filepath.Join(f.dir, "huge.log"))
				if e != nil {
					t.Fatal(e)
				}
				if e = file.Truncate(audit.MaxArtifactBytes + 1); e != nil {
					file.Close()
					t.Fatal(e)
				}
				if e = file.Close(); e != nil {
					t.Fatal(e)
				}
				a.Path = "huge.log"
			case "leaf symlink":
				if e := os.Symlink("output.log", filepath.Join(f.dir, "link.log")); e != nil {
					t.Skipf("symlinks unavailable: %v", e)
				}
				a.Path = "link.log"
			case "parent symlink":
				dir := t.TempDir()
				if e := os.WriteFile(filepath.Join(dir, "output.log"), []byte(bodyMarker), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(dir, filepath.Join(f.dir, "parent")); e != nil {
					t.Skipf("symlinks unavailable: %v", e)
				}
				a.Path = "parent/output.log"
				a.SHA256 = audit.Digest([]byte(bodyMarker))
			case "unix socket":
				// Unix socket paths are short even when the test name or TMPDIR is long.
				socketDir, e := os.MkdirTemp("", "audit-uds-")
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = os.Remove(socketDir) })
				f.dir = socketDir
				a.Path = "socket"
				listener, e := net.Listen("unix", filepath.Join(f.dir, a.Path))
				if e != nil {
					t.Skipf("Unix sockets unavailable: %v", e)
				}
				defer listener.Close()
			}
			r, e := f.finalize(t)
			if e != nil {
				t.Fatal(e)
			}
			if r.State != audit.Blocked || r.ExitCode() != 2 || r.Stages[0].Reported != audit.Pass || r.Stages[0].Integrity != "FAILED" {
				t.Fatalf("artifact failure became successful/failed test evidence: %+v", r)
			}
		})
	}
}
func TestAggregateArtifactBudgetBlocksOtherwiseValidObservations(t *testing.T) {
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = fmt.Sprintf("unit-%d", i)
	}
	f := newFixture(t, ids...)
	data := make([]byte, audit.MaxArtifactBytes)
	if e := os.WriteFile(filepath.Join(f.dir, "shared-large.log"), data, 0600); e != nil {
		t.Fatal(e)
	}
	h := audit.Digest(data)
	for i := range f.results.Stages {
		f.results.Stages[i].Evidence = []audit.Artifact{{Path: "shared-large.log", SHA256: h}}
	}
	r, e := f.finalize(t)
	if e != nil {
		t.Fatal(e)
	}
	if r.State != audit.Blocked || r.Stages[len(r.Stages)-1].Integrity != "FAILED" {
		t.Fatalf("aggregate evidence budget not enforced: %+v", r)
	}
}
func codeProtects(line, marker string) bool {
	pos := strings.Index(line, marker)
	if pos < 0 {
		return false
	}
	opening, start := 0, 0
	for i := 0; i < len(line); {
		if line[i] != '`' {
			i++
			continue
		}
		end := i
		for end < len(line) && line[end] == '`' {
			end++
		}
		length := end - i
		if opening == 0 {
			opening, start = length, end
		} else if length == opening {
			if pos >= start && pos < i {
				return true
			}
			opening = 0
		}
		i = end
	}
	return false
}
func TestMarkdownKeepsUntrustedMetadataInertAndOmitsArtifactBodies(t *testing.T) {
	f := newFixture(t)
	f.plan.Source.Repository = "https://evil.example/[link](javascript:alert(1))"
	f.results.PlanSHA256 = audit.Digest(encode(t, f.plan))
	f.results.Stages[0].Summary = "<script>alert(1)</script> [click](javascript:alert(1)) https://evil.example hidden@evil.example | injected | ``nested`code``"
	r, e := f.finalize(t)
	if e != nil {
		t.Fatal(e)
	}
	md := string(r.Markdown())
	if strings.Contains(md, bodyMarker) || strings.Contains(md, "private artifact") {
		t.Fatal("raw artifact body leaked into report")
	}
	for _, marker := range []string{"<script>", "javascript:", "https://evil.example", "hidden@evil.example"} {
		found := false
		for _, line := range strings.Split(md, "\n") {
			if strings.Contains(line, marker) {
				found = true
				if !codeProtects(line, marker) {
					t.Fatalf("metadata can become active Markdown/HTML: %s", line)
				}
			}
		}
		if !found {
			t.Fatalf("diagnostic metadata %q missing", marker)
		}
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| ") && strings.Count(line, "|") != 8 {
			t.Fatalf("untrusted input changed table structure: %s", line)
		}
	}
	if !strings.Contains(md, "does not authenticate") || !strings.Contains(md, "authorize production") {
		t.Fatal("report omits trust boundary")
	}
}

func TestPublishedAuditExamplesUseThePublicFinalizer(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "audit-finalizer")
	plan, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(dir, "plan.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		state audit.State
		exit  int
	}{
		{"results-pass.json", audit.Pass, 0},
		{"results-incomplete.json", audit.Blocked, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, err := os.ReadFile(filepath.Join(dir, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			report, err := audit.Finalize(plan, strings.TrimSpace(string(expected)), results, filepath.Join(dir, "evidence"))
			if err != nil {
				t.Fatal(err)
			}
			if report.State != tc.state || report.ExitCode() != tc.exit || len(report.Stages) != 4 {
				t.Fatalf("published fixture no longer has declared result: %+v", report)
			}
			if tc.state == audit.Blocked {
				last := report.Stages[len(report.Stages)-1]
				if last.Stage.ID != "e2e" || last.State != audit.NotRun {
					t.Fatalf("omitted E2E must remain visible and incomplete: %+v", last)
				}
			}
		})
	}
}
