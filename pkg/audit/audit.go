// Package audit checks completeness and integrity of caller-collected evidence.
// It does not execute project code, authenticate observers or authorize releases.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	PlanVersion           = "argus.audit-plan/v1"
	ResultsVersion        = "argus.audit-results/v1"
	MaxPlanBytes          = 64 << 10
	MaxResultsBytes       = 1 << 20
	MaxArtifactBytes      = 8 << 20
	maxTotalArtifactBytes = 64 << 20
)

type State string

const (
	Pass      State = "PASS"
	Fail      State = "FAIL"
	Blocked   State = "BLOCKED"
	NotRun    State = "NOT_RUN"
	Uncertain State = "UNCERTAIN"
)

type Source struct {
	Repository string `json:"repository"`
	SHA        string `json:"sha"`
}
type Stage struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}
type Plan struct {
	Version   string  `json:"version"`
	RunID     string  `json:"run_id"`
	ProjectID string  `json:"project_id"`
	Source    Source  `json:"source"`
	Stages    []Stage `json:"stages"`
}
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Observation struct {
	StageID   string     `json:"stage_id"`
	State     State      `json:"state"`
	ExitCode  *int       `json:"exit_code"`
	ChecksRun int        `json:"checks_run"`
	Summary   string     `json:"summary"`
	Evidence  []Artifact `json:"evidence"`
}
type Results struct {
	Version    string        `json:"version"`
	PlanSHA256 string        `json:"plan_sha256"`
	RunID      string        `json:"run_id"`
	ProjectID  string        `json:"project_id"`
	SourceSHA  string        `json:"source_sha"`
	Stages     []Observation `json:"stages"`
}
type StageReport struct {
	Stage     Stage
	Reported  State
	State     State
	ChecksRun int
	Summary   string
	Evidence  []Artifact
	Integrity string
}
type Report struct {
	Plan          Plan
	PlanSHA256    string
	ResultsSHA256 string
	State         State
	Stages        []StageReport
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// object requires exact, non-null keys. Only exit_code may explicitly be null.
func object(raw json.RawMessage, nullable string, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, errors.New("invalid object fields")
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || (key != nullable && bytes.Equal(bytes.TrimSpace(v), []byte("null"))) {
			return nil, errors.New("missing or null field")
		}
	}
	return fields, nil
}

// uniqueJSON rejects duplicate keys at every depth, excessive nesting and data
// after the root. encoding/json alone accepts duplicate and case-aliased keys.
func uniqueJSON(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := dec.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := dec.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for dec.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := dec.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := dec.Token()
	return err == io.EOF
}

func textField(s string, limit int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= limit && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	})
}

func decodePlan(raw []byte, expected string) (Plan, error) {
	var p Plan
	if len(raw) == 0 || len(raw) > MaxPlanBytes || !digest.MatchString(expected) || Digest(raw) != expected || !uniqueJSON(raw) {
		return p, errors.New("invalid plan encoding or independently supplied digest")
	}
	fields, err := object(raw, "", "version", "run_id", "project_id", "source", "stages")
	if err != nil {
		return p, err
	}
	if _, err = object(fields["source"], "", "repository", "sha"); err != nil {
		return p, err
	}
	var stages []json.RawMessage
	if json.Unmarshal(fields["stages"], &stages) != nil || len(stages) < 1 || len(stages) > 64 {
		return p, errors.New("invalid stage list")
	}
	for _, rawStage := range stages {
		if _, err = object(rawStage, "", "id", "kind"); err != nil {
			return p, err
		}
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Version != PlanVersion || !identifier.MatchString(p.RunID) || !identifier.MatchString(p.ProjectID) || !revision.MatchString(p.Source.SHA) || !textField(p.Source.Repository, 512) {
		return p, errors.New("invalid plan scope")
	}
	seen := map[string]bool{}
	for _, stage := range p.Stages {
		if !identifier.MatchString(stage.ID) || seen[stage.ID] {
			return p, errors.New("invalid or duplicate stage")
		}
		seen[stage.ID] = true
		switch stage.Kind {
		case "build", "static", "unit", "integration", "security", "ml", "e2e", "userspace", "custom":
		default:
			return p, errors.New("unknown stage kind")
		}
	}
	return p, nil
}

func decodeResults(raw []byte, p Plan, planDigest string) (Results, error) {
	var r Results
	if len(raw) == 0 || len(raw) > MaxResultsBytes || !uniqueJSON(raw) {
		return r, errors.New("invalid results encoding")
	}
	fields, err := object(raw, "", "version", "plan_sha256", "run_id", "project_id", "source_sha", "stages")
	if err != nil {
		return r, err
	}
	var stages []json.RawMessage
	if json.Unmarshal(fields["stages"], &stages) != nil || len(stages) > 64 {
		return r, errors.New("invalid observations")
	}
	for _, rawStage := range stages {
		f, err := object(rawStage, "exit_code", "stage_id", "state", "exit_code", "checks_run", "summary", "evidence")
		if err != nil {
			return r, err
		}
		var artifacts []json.RawMessage
		if json.Unmarshal(f["evidence"], &artifacts) != nil || len(artifacts) > 8 {
			return r, errors.New("invalid artifact list")
		}
		for _, artifact := range artifacts {
			if _, err := object(artifact, "", "path", "sha256"); err != nil {
				return r, err
			}
		}
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.Version != ResultsVersion || r.PlanSHA256 != planDigest || r.RunID != p.RunID || r.ProjectID != p.ProjectID || r.SourceSHA != p.Source.SHA {
		return r, errors.New("results do not match pinned plan scope")
	}
	expected, seen := map[string]bool{}, map[string]bool{}
	for _, s := range p.Stages {
		expected[s.ID] = true
	}
	for _, o := range r.Stages {
		if !expected[o.StageID] || seen[o.StageID] || !textField(o.Summary, 1024) || o.ChecksRun < 0 || o.ChecksRun > 1000000000 {
			return r, errors.New("invalid, duplicate or unknown observation")
		}
		seen[o.StageID] = true
		switch o.State {
		case Pass, Fail:
			if o.ExitCode == nil || *o.ExitCode < 0 || *o.ExitCode > 255 || o.ChecksRun < 1 || len(o.Evidence) < 1 || (o.State == Pass && *o.ExitCode != 0) || (o.State == Fail && *o.ExitCode == 0) {
				return r, errors.New("inconsistent completed observation")
			}
		case Blocked, NotRun, Uncertain:
			if o.State == NotRun && o.ChecksRun != 0 {
				return r, errors.New("NOT_RUN cannot contain executed checks")
			}
			if o.ExitCode != nil {
				return r, errors.New("non-completed observation must have null exit_code")
			}
		default:
			return r, errors.New("unknown observation state")
		}
		paths := map[string]bool{}
		for _, a := range o.Evidence {
			if !validPath(a.Path) || !digest.MatchString(a.SHA256) || paths[a.Path] {
				return r, errors.New("invalid or duplicate artifact reference")
			}
			paths[a.Path] = true
		}
	}
	return r, nil
}

func validPath(p string) bool {
	if !textField(p, 512) || p == "." || strings.ContainsAny(p, "\\:") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// checkArtifact assumes root and all evidence are trusted, quiescent local
// storage. It rejects symlinks, including intermediate components. Concurrent
// hostile mutation of the evidence store is outside this local-only contract.
func checkArtifact(root *os.Root, a Artifact, total *int64) error {
	if *total >= maxTotalArtifactBytes {
		return errors.New("artifact budget exhausted")
	}
	remaining := int64(maxTotalArtifactBytes) - *total
	parts := strings.Split(a.Path, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("missing or symlink artifact")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return errors.New("invalid artifact parent")
		}
		if i == len(parts)-1 && (!info.Mode().IsRegular() || (info.Size() > MaxArtifactBytes || info.Size() > remaining)) {
			return errors.New("artifact must be a bounded regular file")
		}
	}
	f, err := root.Open(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || (info.Size() > MaxArtifactBytes || info.Size() > remaining) {
		return errors.New("invalid open artifact")
	}
	hash := sha256.New()
	limit := int64(MaxArtifactBytes)
	if remaining < limit {
		limit = remaining
	}
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	*total += n
	if err != nil || n > MaxArtifactBytes || *total > maxTotalArtifactBytes {
		return errors.New("artifact budget exceeded")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return errors.New("artifact digest mismatch")
	}
	return nil
}

// Finalize requires an independently retained digest of the caller-approved
// plan, not a digest taken from the results. All plan stages are mandatory.
// A PASS describes local consistency/completeness, not execution authenticity.
func Finalize(planRaw []byte, expectedPlan string, resultsRaw []byte, artifactDir string) (Report, error) {
	var report Report
	p, err := decodePlan(planRaw, expectedPlan)
	if err != nil {
		return report, err
	}
	r, err := decodeResults(resultsRaw, p, expectedPlan)
	if err != nil {
		return report, err
	}
	root, err := os.OpenRoot(artifactDir)
	if err != nil {
		return report, errors.New("artifact root unavailable")
	}
	defer root.Close()
	report = Report{Plan: p, PlanSHA256: expectedPlan, ResultsSHA256: Digest(resultsRaw), State: Pass}
	observations := map[string]Observation{}
	for _, o := range r.Stages {
		observations[o.StageID] = o
	}
	var total int64
	for _, stage := range p.Stages {
		entry := StageReport{Stage: stage, Reported: NotRun, State: NotRun, Summary: "No observation supplied", Integrity: "NOT_CHECKED"}
		if o, ok := observations[stage.ID]; ok {
			entry.Reported, entry.State, entry.ChecksRun, entry.Summary, entry.Evidence = o.State, o.State, o.ChecksRun, o.Summary, o.Evidence
			entry.Integrity = "CHECKED"
			if len(o.Evidence) == 0 {
				entry.Integrity = "NOT_CHECKED"
			}
			for _, artifact := range o.Evidence {
				if err := checkArtifact(root, artifact, &total); err != nil {
					entry.Integrity = "FAILED"
					if entry.State != Uncertain {
						entry.State = Blocked
					}
				}
			}
		}
		report.Stages = append(report.Stages, entry)
		if severity(entry.State) > severity(report.State) {
			report.State = entry.State
		}
	}
	if report.State == NotRun {
		report.State = Blocked
	}
	return report, nil
}

func severity(s State) int {
	switch s {
	case Uncertain:
		return 4
	case Blocked, NotRun:
		return 3
	case Fail:
		return 2
	case Pass:
		return 1
	default:
		return 5
	}
}
func (r Report) ExitCode() int {
	switch r.State {
	case Pass:
		return 0
	case Fail:
		return 1
	case Uncertain:
		return 4
	default:
		return 2
	}
}

// Metadata is displayed as quoted code, so GFM cannot turn URLs or HTML into
// active links. Encode pipes to keep table boundaries intact in every context.
func markdown(s string) string {
	quoted := strings.ReplaceAll(strconv.QuoteToASCII(s), "|", "\\u007c")
	longest, current := 0, 0
	for _, char := range quoted {
		if char == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	delimiter := strings.Repeat("`", longest+1)
	return delimiter + " " + quoted + " " + delimiter
}

// Markdown includes metadata only, never artifact bodies or active links.
func (r Report) Markdown() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Argus audit\n\nResult: **%s**\n\nRun: %s  \nProject: %s  \nRepository: %s  \nSource SHA: %s  \nPlan digest: %s  \nResults digest: %s\n\n", r.State, markdown(r.Plan.RunID), markdown(r.Plan.ProjectID), markdown(r.Plan.Source.Repository), r.Plan.Source.SHA, r.PlanSHA256, r.ResultsSHA256)
	b.WriteString("This report checks caller-collected observations, completeness and local artifact hashes. It does not authenticate the observer, prove execution or authorize production. All declared stages are mandatory.\n\n")
	b.WriteString("| Stage | Kind | Reported | Assessed | Checks run | Artifact integrity | Summary |\n| --- | --- | --- | --- | ---: | --- | --- |\n")
	for _, s := range r.Stages {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s | %s |\n", markdown(s.Stage.ID), s.Stage.Kind, s.Reported, s.State, s.ChecksRun, s.Integrity, markdown(s.Summary))
	}
	b.WriteString("\n## Evidence references\n\n")
	for _, s := range r.Stages {
		for _, a := range s.Evidence {
			fmt.Fprintf(&b, "- %s: %s (%s)\n", markdown(s.Stage.ID), markdown(a.Path), a.SHA256)
		}
	}
	b.WriteString("\nMissing stages are NOT_RUN and block the aggregate. UNCERTAIN takes precedence over incomplete evidence, then FAIL, then PASS. No artifact bodies are embedded.\n")
	return []byte(b.String())
}
