package source

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Animus-OSC/argus-open/internal/synthetic"
)

func subtreeGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", args...)
	cmd.Dir = repo
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subtree fixture Git failed: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func subtreeCommit(t *testing.T, repo string) string {
	t.Helper()
	subtreeGit(t, repo, "add", "--all")
	subtreeGit(t, repo, "-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-q", "-m", "fixed python subtree fixture")
	return subtreeGit(t, repo, "rev-parse", "HEAD")
}

func subtreeWrite(t *testing.T, repo, name string, data []byte) {
	t.Helper()
	p := filepath.Join(repo, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func subtreeFixture(t *testing.T) (repo, staging string) {
	t.Helper()
	p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	repo = p.SourceRef
	subtreeWrite(t, repo, "python/src/module.py", []byte("# $Format:%H$\nVALUE = 'committed'\n"))
	subtreeWrite(t, repo, "python/tests/test_module.py", []byte("# fixed source test fixture\n"))
	staging = filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	return repo, staging
}

func TestPreparePythonTreeExcludesOversizedBannerAndDirtyWorktree(t *testing.T) {
	repo, staging := subtreeFixture(t)
	subtreeWrite(t, repo, "assets/banner.png", make([]byte, 2<<20))
	sha := subtreeCommit(t, repo)
	want, err := os.ReadFile(filepath.Join(repo, "python/src/module.py"))
	if err != nil {
		t.Fatal(err)
	}
	subtreeWrite(t, repo, "python/src/module.py", []byte("dirty worktree bytes must not execute\n"))
	subtreeWrite(t, repo, "python/untracked.py", []byte("untracked bytes must not execute\n"))
	if dir, cleanup, err := Prepare(context.Background(), staging, repo, sha); err == nil {
		cleanup()
		t.Fatalf("complete-tree limits changed; oversized banner accepted in %s", dir)
	}
	dir, cleanup, err := PreparePythonTree(context.Background(), staging, repo, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got, err := os.ReadFile(filepath.Join(dir, "python/src/module.py"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("snapshot did not preserve committed Python bytes: %v", err)
	}
	for _, excluded := range []string{"assets", "calculator.py", "tests", "python/untracked.py"} {
		if _, err := os.Lstat(filepath.Join(dir, excluded)); !os.IsNotExist(err) {
			t.Fatalf("outside/uncommitted path entered fixed subtree: %s: %v", excluded, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "python/tests/test_module.py")); err != nil {
		t.Fatal("committed subtree path missing:", err)
	}
}

func TestPreparePythonTreeRejectsCommittedAttributeChanges(t *testing.T) {
	for _, attribute := range []string{"export-ignore", "export-subst"} {
		t.Run(attribute, func(t *testing.T) {
			repo, staging := subtreeFixture(t)
			subtreeWrite(t, repo, ".gitattributes", []byte("python/src/module.py "+attribute+"\n"))
			sha := subtreeCommit(t, repo)
			if _, cleanup, err := PreparePythonTree(context.Background(), staging, repo, sha); err == nil {
				cleanup()
				t.Fatal("attribute-mutated subtree accepted")
			}
		})
	}
}

func TestPreparePythonTreeIgnoresLocalAttributes(t *testing.T) {
	repo, staging := subtreeFixture(t)
	sha := subtreeCommit(t, repo)
	subtreeWrite(t, repo, ".git/info/attributes", []byte("python/src/module.py export-ignore export-subst\n"))
	dir, cleanup, err := PreparePythonTree(context.Background(), staging, repo, sha)
	if err != nil {
		t.Fatal("local attributes affected isolated subtree snapshot:", err)
	}
	defer cleanup()
	got, err := os.ReadFile(filepath.Join(dir, "python/src/module.py"))
	if err != nil || !strings.Contains(string(got), "$Format:%H$") {
		t.Fatal("local attributes removed or substituted committed source", err)
	}
}

func TestPreparePythonTreeRejectsMissingInvalidAndUnsupportedEntries(t *testing.T) {
	for _, mode := range []string{"missing", "file", "symlink", "submodule", "oversized-blob", "invalid-sha", "gitfile"} {
		t.Run(mode, func(t *testing.T) {
			repo, staging := subtreeFixture(t)
			switch mode {
			case "missing", "file":
				if err := os.RemoveAll(filepath.Join(repo, "python")); err != nil {
					t.Fatal(err)
				}
				if mode == "file" {
					subtreeWrite(t, repo, "python", []byte("not a subtree"))
				}
			case "symlink":
				if err := os.Symlink("module.py", filepath.Join(repo, "python/src/link.py")); err != nil {
					t.Fatal(err)
				}
			case "oversized-blob":
				subtreeWrite(t, repo, "python/oversized", make([]byte, (1<<20)+1))
			}
			sha := subtreeCommit(t, repo)
			if mode == "submodule" {
				subtreeGit(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+sha+",python/nested")
				subtreeGit(t, repo, "-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "submodule subtree fixture")
				sha = subtreeGit(t, repo, "rev-parse", "HEAD")
			}
			if mode == "invalid-sha" {
				sha = "--remote=unapproved"
			}
			if mode == "gitfile" {
				gitDir := filepath.Join(t.TempDir(), "git-dir")
				if err := os.Rename(filepath.Join(repo, ".git"), gitDir); err != nil {
					t.Fatal(err)
				}
				subtreeWrite(t, repo, ".git", []byte("gitdir: "+gitDir+"\n"))
			}
			if _, cleanup, err := PreparePythonTree(context.Background(), staging, repo, sha); err == nil {
				cleanup()
				t.Fatalf("unsupported source accepted: %s", mode)
			}
		})
	}
}
