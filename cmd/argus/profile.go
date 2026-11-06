package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Animus-OSC/argus-open/internal/profile"
	"github.com/Animus-OSC/argus-open/pkg/audit"
)

func profileCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run-profile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	id := flags.String("profile", "", "reviewed closed profile ID")
	repo := flags.String("repo", "", "absolute ordinary standalone Git clone")
	source := flags.String("source-sha", "", "independently approved pinned source commit")
	runID := flags.String("run-id", "", "caller-scoped unique run ID")
	output := flags.String("out-dir", "", "new absolute private output directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := profile.Run(ctx, profile.Config{Profile: *id, RepositoryDir: *repo, SourceSHA: *source, RunID: *runID, OutputDir: *output})
	if err != nil {
		if result.State == audit.Uncertain {
			fmt.Fprintln(stderr, "UNCERTAIN: profile export failed after launch; inspect the reserved attempt before retry")
			return 4
		}
		fmt.Fprintln(stderr, "BLOCKED: profile, source, output or runtime is unavailable; output must be new")
		return 2
	}
	fmt.Fprintf(stdout, "PROFILE: %s\n", result.State)
	switch result.State {
	case audit.Pass:
		return 0
	case audit.Fail:
		return 1
	case audit.Uncertain:
		return 4
	default:
		return 2
	}
}
