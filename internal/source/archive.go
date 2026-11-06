// Package source materializes an exact Git commit into a bounded disposable tree.
package source

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

const maxBytes = 4 << 20
const maxTreeBytes = 512 << 10

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Root is an operator-owned private staging directory shared only with its
// configured local worker, not a general-purpose project-supplied mount.
type GitArchive struct{ Root string }

func (g GitArchive) Prepare(ctx context.Context, p v1.Project) (v1.Snapshot, func(), error) {
	dir, cleanup, err := Prepare(ctx, g.Root, p.SourceRef, p.SourceSHA)
	if err != nil {
		return v1.Snapshot{}, nil, err
	}
	return v1.Snapshot{Version: v1.SnapshotVersion, SourceSHA: p.SourceSHA, Ref: dir}, cleanup, nil
}

// Prepare snapshots the complete operator-registered synthetic repository.
// Git reads its objects through a private, fixed-config directory; it never
// loads the registered repository's local config or runs a transport.
func Prepare(parent context.Context, root, repo, sha string) (string, func(), error) {
	return prepare(parent, root, repo, sha, "")
}

// PreparePythonTree snapshots only the fixed python/ subtree for a separately
// reviewed SDK profile. The caller must independently approve the commit and
// content; this function does not authorize source execution. A standalone
// repository with an ordinary .git directory is required, not a Git submodule.
// All complete-tree safety checks and limits apply to the selected subtree.
func PreparePythonTree(parent context.Context, root, repo, sha string) (string, func(), error) {
	return prepare(parent, root, repo, sha, "python")
}

func prepare(parent context.Context, root, repo, sha, subdir string) (string, func(), error) {
	if subdir != "" && subdir != "python" {
		return "", nil, errors.New("unsupported fixed source subtree")
	}
	if !shaPattern.MatchString(sha) || !filepath.IsAbs(root) || !filepath.IsAbs(repo) {
		return "", nil, errors.New("invalid commit identity")
	}
	repoInfo, repoErr := os.Lstat(repo)
	repoResolved, repoResolveErr := filepath.EvalSymlinks(repo)
	if repoErr != nil || repoResolveErr != nil || !repoInfo.IsDir() || repoInfo.Mode()&os.ModeSymlink != 0 || repoResolved != filepath.Clean(repo) {
		return "", nil, errors.New("invalid registered repository")
	}
	objects := filepath.Join(repo, ".git", "objects")
	for _, name := range []string{filepath.Join(repo, ".git"), objects} {
		entry, err := os.Lstat(name)
		if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			return "", nil, errors.New("registered repository has no ordinary Git object directory")
		}
	}
	info, err := os.Lstat(root)
	resolved, resolveErr := filepath.EvalSymlinks(root)
	if err != nil || resolveErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0077 != 0 || resolved != filepath.Clean(root) {
		return "", nil, errors.New("staging root is not private")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if err := validateObjectStore(ctx, objects); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(root, "snapshot-")
	if err != nil {
		return "", nil, err
	}
	gitDir, err := isolatedGitDir(root)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir); _ = os.RemoveAll(gitDir) }
	gitEnv := gitEnvironment(gitDir, objects)
	archiveArgs := []string{"archive", "--format=tar", sha}
	if subdir != "" {
		archiveArgs = append(archiveArgs, "--", subdir)
	}
	// #nosec G204 -- sha is 40 lowercase hex digits; subdir is empty or the fixed python subtree.
	cmd := exec.CommandContext(ctx, "/usr/bin/git", archiveArgs...)
	cmd.Dir = gitDir
	cmd.Env = gitEnv
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		cleanup()
		return "", nil, err
	}
	err = unpack(dir, io.LimitReader(pipe, maxBytes+1), sha)
	if err != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("source archive invalid: %w", err)
	}
	if waitErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("source archive unavailable: %w", waitErr)
	}
	if err := verifyCommitTree(ctx, gitDir, gitEnv, dir, sha, subdir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("source archive does not match commit tree: %w", err)
	}
	_ = os.RemoveAll(gitDir)
	return dir, cleanup, nil
}

// Alternates or symlinked entries could redirect Git's object reads outside
// the registered store. This check assumes the operator-owned tree is not
// concurrently replaced; it is not an atomic hostile-filesystem boundary.
func validateObjectStore(ctx context.Context, objects string) error {
	return filepath.WalkDir(objects, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == filepath.Join(objects, "info", "alternates") || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("alternate or symlinked Git object store is unsupported")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("unsupported Git object store entry")
		}
		return nil
	})
}

func isolatedGitDir(root string) (string, error) {
	dir, err := os.MkdirTemp(root, "git-meta-")
	if err != nil {
		return "", err
	}
	for _, name := range []string{"objects/info", "objects/pack", "refs"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0700); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	for name, data := range map[string]string{
		"config": "[core]\n repositoryformatversion = 0\n bare = true\n",
		"HEAD":   "ref: refs/heads/unborn\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

func gitEnvironment(gitDir, objects string) []string {
	return []string{
		"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C",
		"GIT_DIR=" + gitDir, "GIT_OBJECT_DIRECTORY=" + objects,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.allow", "GIT_CONFIG_VALUE_0=never",
	}
}

type treeBlob struct {
	oid        string
	size       int64
	executable bool
}

// Git's archive commit header alone is insufficient: export-ignore can omit
// paths and export-subst can change blobs. Compare every archive file with the
// exact committed tree, recomputing its Git object ID without filters.
func verifyCommitTree(ctx context.Context, gitDir string, gitEnv []string, snapshot, sha, subdir string) error {
	if !shaPattern.MatchString(sha) || (subdir != "" && subdir != "python") {
		return errors.New("invalid commit identity")
	}
	treeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	treeArgs := []string{"ls-tree", "-r", "-z", "--full-tree", "-l", sha}
	if subdir != "" {
		treeArgs = append(treeArgs, "--", subdir)
	}
	// #nosec G204 -- sha is 40 lowercase hex digits; subdir is empty or the fixed python subtree.
	cmd := exec.CommandContext(treeCtx, "/usr/bin/git", treeArgs...)
	cmd.Dir, cmd.Env = gitDir, gitEnv
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, maxTreeBytes+1))
	if readErr != nil || len(data) > maxTreeBytes {
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || len(data) == 0 || len(data) > maxTreeBytes || data[len(data)-1] != 0 {
		return errors.New("invalid or oversized commit tree")
	}
	expected := make(map[string]treeBlob)
	var total int64
	for _, raw := range bytes.Split(data[:len(data)-1], []byte{0}) {
		header, rawName, ok := bytes.Cut(raw, []byte{'\t'})
		fields, name := strings.Fields(string(header)), string(rawName)
		if !ok || len(fields) != 4 || (fields[0] != "100644" && fields[0] != "100755") ||
			fields[1] != "blob" || !shaPattern.MatchString(fields[2]) || !validPath(name) ||
			(subdir != "" && !strings.HasPrefix(name, subdir+"/")) {
			return errors.New("unsupported commit tree entry")
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > 1<<20 || total+size > maxBytes {
			return errors.New("commit tree exceeds size limits")
		}
		if _, exists := expected[name]; exists || len(expected) >= 100 {
			return errors.New("duplicate or oversized commit tree")
		}
		expected[name] = treeBlob{oid: fields[2], size: size, executable: fields[0] == "100755"}
		total += size
	}
	root, err := os.OpenRoot(snapshot)
	if err != nil {
		return err
	}
	defer root.Close()
	seen := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		want, ok := expected[name]
		if !ok || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected archive path")
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != want.size || (info.Mode().Perm()&0100 != 0) != want.executable {
			return errors.New("archive blob has invalid type or size")
		}
		hash := exec.CommandContext(ctx, "/usr/bin/git", "hash-object", "--no-filters", "--stdin")
		hash.Dir, hash.Env, hash.Stdin = gitDir, gitEnv, f
		got, err := hash.Output()
		if err != nil || strings.TrimSpace(string(got)) != want.oid {
			return errors.New("archive blob differs from committed object")
		}
		seen++
		return nil
	})
	if err != nil || seen != len(expected) {
		return errors.New("archive paths or blobs differ from commit tree")
	}
	return nil
}

func validPath(name string) bool {
	if name == "" || len(name) > 4096 || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

func unpack(root string, input io.Reader, expectedSHA string) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	tr := tar.NewReader(input)
	var total int64
	count := 0
	seenCommit := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			if !seenCommit || count < 2 {
				return errors.New("archive lacks exact commit identity")
			}
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if h.Typeflag == tar.TypeXGlobalHeader {
			if count != 1 || h.Name != "pax_global_header" || len(h.PAXRecords) != 1 || h.PAXRecords["comment"] != expectedSHA {
				return errors.New("archive commit identity mismatch")
			}
			seenCommit = true
			continue
		}
		if !seenCommit {
			return errors.New("archive lacks exact commit identity")
		}
		if count > 100 || h.Size < 0 || h.Size > 1<<20 || total+h.Size > maxBytes {
			return errors.New("archive exceeds limits")
		}
		total += h.Size
		name := strings.TrimSuffix(h.Name, "/")
		if !validPath(name) {
			return errors.New("invalid archive path")
		}
		dest := filepath.FromSlash(name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := dir.MkdirAll(dest, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := dir.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return err
			}
			f, err := dir.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if h.Mode&0100 != 0 {
				mode = 0700
			}
			if err := f.Chmod(mode); err != nil {
				_ = f.Close()
				return err
			}
			_, cpErr := io.CopyN(f, tr, h.Size)
			closeErr := f.Close()
			if cpErr != nil || closeErr != nil {
				return fmt.Errorf("archive file incomplete")
			}
		default:
			return errors.New("archive links or special files denied")
		}
	}
}
