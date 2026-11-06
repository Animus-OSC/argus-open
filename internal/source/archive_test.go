package source

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Animus-OSC/argus-open/internal/synthetic"
)

func TestPrepareExactSyntheticCommit(t *testing.T) {
	p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.SourceRef, "calculator.py"), []byte("dirty checkout"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := Prepare(context.Background(), root, p.SourceRef, p.SourceSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "tests", "test_calculator.py")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "calculator.py"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "dirty checkout") {
		t.Fatal("uncommitted source entered snapshot")
	}
	if _, _, err := Prepare(context.Background(), root, p.SourceRef, "--remote=bad"); err == nil {
		t.Fatal("unsafe source identity accepted")
	}
}

func TestArchiveRejectsEscapeLinksAndWrongCommit(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for name, header := range map[string]tar.Header{
		"traversal": {Name: "../escape", Typeflag: tar.TypeReg, Mode: 0600},
		"absolute":  {Name: "/escape", Typeflag: tar.TypeReg, Mode: 0600},
		"backslash": {Name: `a\b`, Typeflag: tar.TypeReg, Mode: 0600},
		"symlink":   {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"hardlink":  {Name: "link", Typeflag: tar.TypeLink, Linkname: "../outside"},
	} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			if err := w.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": sha}}); err != nil {
				t.Fatal(err)
			}
			if err := w.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := unpack(t.TempDir(), &b, sha); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": strings.Repeat("b", 40)}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(&tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unpack(t.TempDir(), &b, sha); err == nil {
		t.Fatal("wrong commit accepted")
	}
}

// The Git archive header binds a commit ID but export attributes can remove
// paths or substitute content. A snapshot must also match the full Git tree.
func TestPrepareMatchesGitTree(t *testing.T) {
	for _, mode := range []string{"committed-export-ignore", "committed-export-subst", "local-export-ignore", "local-export-subst", "local-export-subst-equal-size", "committed-executable"} {
		t.Run(mode, func(t *testing.T) {
			p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
			if err != nil {
				t.Fatal(err)
			}
			write := func(name, data string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(p.SourceRef, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			git := func(args ...string) string {
				t.Helper()
				cmd := exec.Command("/usr/bin/git", args...)
				cmd.Dir = p.SourceRef
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git operation failed: %v", err)
				}
				return strings.TrimSpace(string(out))
			}
			switch mode {
			case "committed-export-ignore":
				write(".gitattributes", ".gitattributes export-ignore\nconcealed.py export-ignore\n")
				write("concealed.py", "# synthetic concealed content\n")
			case "committed-export-subst":
				write(".gitattributes", "calculator.py export-subst\n")
				write("calculator.py", "# $Format:%H$\n")
			case "local-export-ignore":
				write("concealed.py", "# synthetic concealed content\n")
				write(".git/info/attributes", "concealed.py export-ignore\n")
			case "local-export-subst":
				write("calculator.py", "# $Format:%H$\n")
				write(".git/info/attributes", "calculator.py export-subst\n")
			case "local-export-subst-equal-size":
				write("calculator.py", "# $Format:%<(17)%h$\n")
				write(".git/info/attributes", "calculator.py export-subst\n")
			case "committed-executable":
				if err := os.Chmod(filepath.Join(p.SourceRef, "calculator.py"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			git("add", "--all")
			git("-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "archive attribute probe")
			sha := git("rev-parse", "HEAD")
			if mode == "local-export-subst-equal-size" {
				cmd := exec.Command("/usr/bin/git", "archive", "--format=tar", sha)
				cmd.Dir = p.SourceRef
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
				archive, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				reader := tar.NewReader(bytes.NewReader(archive))
				var substituted []byte
				for {
					header, err := reader.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if header.Name == "calculator.py" {
						substituted, err = io.ReadAll(reader)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				original, err := os.ReadFile(filepath.Join(p.SourceRef, "calculator.py"))
				if err != nil || len(substituted) != len(original) || bytes.Equal(substituted, original) {
					t.Fatal("fixture did not create a same-size substituted blob")
				}
			}
			root := filepath.Join(t.TempDir(), "staging")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			dir, cleanup, err := Prepare(context.Background(), root, p.SourceRef, sha)
			if cleanup != nil {
				defer cleanup()
			}
			if mode == "committed-executable" {
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(filepath.Join(dir, "calculator.py"))
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatal("committed executable bit was not preserved with private permissions")
				}
				return
			}
			if strings.HasPrefix(mode, "local-") {
				if err != nil {
					t.Fatal("local Git attributes affected the isolated archive:", err)
				}
				got, err := os.ReadFile(filepath.Join(dir, "calculator.py"))
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(filepath.Join(p.SourceRef, "calculator.py"))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("local Git attributes changed a committed blob")
				}
				return
			}
			if err == nil {
				t.Fatal("accepted an archive that differs from the complete Git tree")
			}
		})
	}
}

// The registered repository's config is attacker-controlled in this probe.
// Git's promisor mechanism would invoke a transport before the worker sandbox
// when an object is missing. The helper is a harmless local marker command.
func TestPrepareMissingBlobCannotInvokePromisorHelper(t *testing.T) {
	p, _, err := synthetic.CreateFixture(context.Background(), t.TempDir(), "tenant-a", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/git", "rev-parse", "HEAD:calculator.py")
	cmd.Dir = p.SourceRef
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	oid := strings.TrimSpace(string(out))
	object := filepath.Join(p.SourceRef, ".git", "objects", oid[:2], oid[2:])
	if err := os.Rename(object, filepath.Join(t.TempDir(), "removed-blob")); err != nil {
		t.Fatal("fixture must have a loose blob:", err)
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
		t.Fatal("could not set up promisor probe", writeErr, closeErr)
	}
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := Prepare(context.Background(), root, p.SourceRef, p.SourceSHA); err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("missing blob accepted")
	}
	if _, err := os.Stat(marker); err == nil || !os.IsNotExist(err) {
		t.Fatal("Git invoked the configured helper before worker isolation")
	}
}
