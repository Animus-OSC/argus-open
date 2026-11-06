package synthetic

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	syntheticproject "github.com/Animus-OSC/argus-open/examples/synthetic-project"
)

// CreateFixture creates a new synthetic Git repository, never a real project.
func CreateFixture(ctx context.Context, root, tenant, project string) (v1.Project, v1.Task, error) {
	repo := filepath.Join(root, "synthetic-project")
	if err := os.Mkdir(repo, 0700); err != nil {
		return v1.Project{}, v1.Task{}, err
	}
	err := fs.WalkDir(syntheticproject.Files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		dest := filepath.Join(repo, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.Mkdir(dest, 0700)
		}
		b, err := syntheticproject.Files.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, b, 0600)
	})
	if err != nil {
		return v1.Project{}, v1.Task{}, err
	}
	for _, operation := range []string{"init", "add", "commit"} {
		if _, err := git(ctx, repo, operation); err != nil {
			return v1.Project{}, v1.Task{}, err
		}
	}
	sha, err := git(ctx, repo, "head")
	if err != nil {
		return v1.Project{}, v1.Task{}, err
	}
	sha = strings.TrimSpace(sha)
	p := v1.Project{Version: v1.ProjectVersion, TenantID: tenant, ProjectID: project, SourceRef: repo, SourceSHA: sha,
		PolicyVersion: "synthetic-policy/v1", RequiredOperation: v1.UnitOperation, ModelDigest: ModelDigest}
	t := v1.Task{Version: v1.TaskVersion, TaskID: "synthetic-task-1", TenantID: tenant, ProjectID: project,
		SourceSHA: sha, IdempotencyKey: "synthetic-key-1"}
	t.Signature = Sign(t)
	return p, t, nil
}

func git(ctx context.Context, dir, operation string) (string, error) {
	var cmd *exec.Cmd
	switch operation {
	case "init":
		cmd = exec.CommandContext(ctx, "/usr/bin/git", "init", "-q", "--object-format=sha1")
	case "add":
		cmd = exec.CommandContext(ctx, "/usr/bin/git", "add", "--all")
	case "commit":
		cmd = exec.CommandContext(ctx, "/usr/bin/git", "-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "synthetic fixture")
	case "head":
		cmd = exec.CommandContext(ctx, "/usr/bin/git", "rev-parse", "HEAD")
	default:
		return "", errors.New("unknown synthetic git operation")
	}
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("synthetic git operation failed")
	}
	return string(out), nil
}
