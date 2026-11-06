package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Animus-OSC/argus-open/pkg/audit"
)

func auditCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "caller-approved audit plan")
	planDigest := flags.String("plan-sha256", "", "independently retained digest of the exact plan bytes")
	resultsPath := flags.String("results", "", "caller-collected stage observations")
	artifactDir := flags.String("artifacts", "", "trusted quiescent local evidence directory")
	out := flags.String("out", "", "new Markdown report file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *planDigest == "" || !filepath.IsAbs(*planPath) || !filepath.IsAbs(*resultsPath) || !filepath.IsAbs(*artifactDir) || !filepath.IsAbs(*out) {
		fmt.Fprintln(stderr, "absolute --plan, --results, --artifacts, --out and an independent --plan-sha256 are required")
		return 2
	}
	plan, err := readAuditInput(*planPath, audit.MaxPlanBytes)
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: audit plan unavailable or exceeds limit")
		return 2
	}
	results, err := readAuditInput(*resultsPath, audit.MaxResultsBytes)
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: audit observations unavailable or exceed limit")
		return 2
	}
	report, err := audit.Finalize(plan, *planDigest, results, *artifactDir)
	if err != nil {
		fmt.Fprintln(stderr, "BLOCKED: audit contract, scope or artifact root validation failed")
		return 2
	}
	if err := writeNew(*out, report.Markdown()); err != nil {
		fmt.Fprintln(stderr, "BLOCKED: audit report export failed; destination must be a new file")
		return 2
	}
	fmt.Fprintf(stdout, "AUDIT: %s\n", report.State)
	return report.ExitCode()
}

func readAuditInput(path string, limit int64) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.Base(path))
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("audit input must be a regular file")
	}
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid audit input")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("invalid audit input size")
	}
	return raw, nil
}
