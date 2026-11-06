package source

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Animus-OSC/argus-open/internal/synthetic"
)

// The control proves that the installed Git actually recognizes this promisor
// fixture and that GIT_NO_LAZY_FETCH is effective for it. The configured ext
// transport is only /usr/bin/touch of a disposable marker, never a network URL.
func TestInstalledGitPromisorControls(t *testing.T) {
	p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	object := exec.Command("/usr/bin/git", "rev-parse", "HEAD:calculator.py")
	object.Dir, object.Env = p.SourceRef, env
	out, err := object.Output()
	if err != nil {
		t.Fatal(err)
	}
	oid := strings.TrimSpace(string(out))
	if !shaPattern.MatchString(oid) {
		t.Fatal("invalid fixture blob identity")
	}
	if err := os.Remove(filepath.Join(p.SourceRef, ".git", "objects", oid[:2], oid[2:])); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "helper-ran")
	config := filepath.Join(p.SourceRef, ".git", "config")
	f, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(f, "\n[extensions]\n partialClone = origin\n[remote \"origin\"]\n url = ext::/usr/bin/touch "+marker+"\n promisor = true\n partialclonefilter = blob:none\n[protocol \"ext\"]\n allow = always\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	run := func(extra ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/git", "archive", "--format=tar", p.SourceSHA)
		cmd.Dir, cmd.Env = p.SourceRef, append(append([]string{}, env...), extra...)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Run(); err == nil || ctx.Err() != nil {
			t.Fatalf("missing object did not fail promptly: %v", err)
		}
	}
	run()
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("positive control did not execute configured local helper:", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	run("GIT_NO_LAZY_FETCH=1")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("installed Git did not suppress lazy-fetch helper: %v", err)
	}
}

func TestPrepareRejectsRedirectedObjectStore(t *testing.T) {
	for _, mode := range []string{"alternate", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
			if err != nil {
				t.Fatal(err)
			}
			objects := filepath.Join(p.SourceRef, ".git", "objects")
			target := t.TempDir()
			if mode == "alternate" {
				err = os.WriteFile(filepath.Join(objects, "info", "alternates"), []byte(target+"\n"), 0600)
			} else {
				err = os.Symlink(target, filepath.Join(objects, "redirect"))
			}
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "staging")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if _, cleanup, err := Prepare(context.Background(), root, p.SourceRef, p.SourceSHA); err == nil {
				if cleanup != nil {
					cleanup()
				}
				t.Fatal("redirected object store accepted")
			}
		})
	}
}

func TestPrepareRejectsUnsupportedCommittedEntries(t *testing.T) {
	for _, mode := range []string{"symlink", "submodule", "oversized-blob"} {
		t.Run(mode, func(t *testing.T) {
			p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
			if err != nil {
				t.Fatal(err)
			}
			git := func(args ...string) string {
				t.Helper()
				cmd := exec.Command("/usr/bin/git", args...)
				cmd.Dir = p.SourceRef
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git fixture command failed: %v", err)
				}
				return strings.TrimSpace(string(out))
			}
			switch mode {
			case "symlink":
				if err := os.Symlink("calculator.py", filepath.Join(p.SourceRef, "unsafe-link")); err != nil {
					t.Fatal(err)
				}
				git("add", "--all")
			case "submodule":
				git("update-index", "--add", "--cacheinfo", "160000,"+p.SourceSHA+",nested")
			case "oversized-blob":
				if err := os.WriteFile(filepath.Join(p.SourceRef, "oversized"), make([]byte, (1<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
				git("add", "--all")
			}
			git("-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "unsupported entry")
			sha := git("rev-parse", "HEAD")
			root := filepath.Join(t.TempDir(), "staging")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if _, cleanup, err := Prepare(context.Background(), root, p.SourceRef, sha); err == nil {
				if cleanup != nil {
					cleanup()
				}
				t.Fatalf("%s committed entry accepted", mode)
			}
		})
	}
}
