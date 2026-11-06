// Package store provides a single-host, fail-closed filesystem task ledger.
// It is not a distributed lock or a production storage implementation.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/pkg/evidence"
)

type Local struct{ root string }

func NewLocal(root string) (*Local, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("ledger path must be absolute")
	}
	if err := privateDir(root); err != nil {
		return nil, err
	}
	for _, name := range []string{"tasks", "keys"} {
		if err := privateDir(filepath.Join(root, name)); err != nil {
			return nil, err
		}
	}
	return &Local{root: root}, nil
}

func privateDir(path string) error {
	if err := rejectSymlinkAncestors(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("ledger directory is not private")
	}
	return nil
}

// This rejects pre-existing symlink ancestors before creating state. The local
// ledger still requires trusted, non-mutable parent directories; these checks
// do not defend against a concurrent same-UID or hostile-parent replacement.
func rejectSymlinkAncestors(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("ledger path traverses a symlink")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func key(parts ...string) string {
	b, _ := json.Marshal(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *Local) Claim(ctx context.Context, t v1.Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	active := filepath.Join(s.root, "active")
	if err := os.Mkdir(active, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			if s.owns(t) {
				return v1.ErrUncertain
			}
			return v1.ErrCapacity
		}
		return err
	}
	if err := syncDir(s.root); err != nil {
		return v1.ErrUncertain
	}
	if err := writeOnce(filepath.Join(active, "owner"), []byte(taskFingerprint(t))); err != nil {
		return v1.ErrUncertain
	}
	tasks := filepath.Join(s.root, "tasks")
	dir := filepath.Join(tasks, key(t.TaskID))
	if err := os.Mkdir(dir, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			if _, err := os.Lstat(filepath.Join(dir, "complete")); err == nil {
				if s.release(t) != nil {
					return v1.ErrUncertain
				}
				return v1.ErrDuplicate
			}
			return v1.ErrUncertain
		}
		return err
	}
	// A crash from here onwards retains the task fence, even before execution.
	if err := syncDir(tasks); err != nil {
		return v1.ErrUncertain
	}
	if err := writeOnce(filepath.Join(dir, "intent"), []byte(taskFingerprint(t))); err != nil {
		return v1.ErrUncertain
	}
	keys := filepath.Join(s.root, "keys")
	if err := os.Mkdir(filepath.Join(keys, key(t.TenantID, t.ProjectID, t.IdempotencyKey)), 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			if writeOnce(filepath.Join(dir, "complete"), []byte("duplicate")) != nil || s.release(t) != nil {
				return v1.ErrUncertain
			}
			return v1.ErrDuplicate
		}
		return v1.ErrUncertain
	}
	if err := syncDir(keys); err != nil || ctx.Err() != nil {
		return v1.ErrUncertain
	}
	return nil
}

func taskFingerprint(t v1.Task) string {
	return key(t.Version, t.TaskID, t.TenantID, t.ProjectID, t.SourceSHA, t.IdempotencyKey, t.Signature)
}

// FinishWithoutEvidence is valid only before execution, or after a worker has
// positively terminated without external side effects. Unknown outcomes retain
// their fence and must never call this method.
func (s *Local) FinishWithoutEvidence(ctx context.Context, t v1.Task) error {
	if ctx.Err() != nil || !s.owns(t) {
		return v1.ErrUncertain
	}
	dir := filepath.Join(s.root, "tasks", key(t.TaskID))
	intent, err := s.read(filepath.Join("tasks", key(t.TaskID), "intent"))
	if err != nil || string(intent) != taskFingerprint(t) {
		return v1.ErrUncertain
	}
	if writeOnce(filepath.Join(dir, "complete"), []byte("blocked")) != nil || s.release(t) != nil {
		return v1.ErrUncertain
	}
	return nil
}

func (s *Local) Complete(ctx context.Context, t v1.Task, e v1.Envelope) error {
	if ctx.Err() != nil || !s.owns(t) || evidence.Verify(e, e.SHA256) != nil ||
		e.Receipt.TaskID != t.TaskID || e.Receipt.TenantID != t.TenantID ||
		e.Receipt.ProjectID != t.ProjectID || e.Receipt.SourceSHA != t.SourceSHA ||
		e.Receipt.IdempotencyKey != t.IdempotencyKey || e.Receipt.EventSHA256 != evidence.TaskDigest(t) {
		return v1.ErrUncertain
	}
	dir := filepath.Join(s.root, "tasks", key(t.TaskID))
	intent, err := s.read(filepath.Join("tasks", key(t.TaskID), "intent"))
	if err != nil || string(intent) != taskFingerprint(t) {
		return v1.ErrUncertain
	}
	b, err := json.Marshal(e)
	if err != nil {
		return v1.ErrUncertain
	}
	if err := writeOnce(filepath.Join(dir, "receipt.json"), b); err != nil {
		return v1.ErrUncertain
	}
	if err := writeOnce(filepath.Join(dir, "complete"), []byte(e.SHA256)); err != nil {
		return v1.ErrUncertain
	}
	return s.release(t)
}

func (s *Local) owns(t v1.Task) bool {
	b, err := s.read(filepath.Join("active", "owner"))
	return err == nil && string(b) == taskFingerprint(t)
}

// read is confined to the operator-owned ledger and accepts only bounded data.
func (s *Local) read(name string) ([]byte, error) {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 {
		return nil, errors.New("invalid ledger entry")
	}
	return b, nil
}

func (s *Local) release(t v1.Task) error {
	if !s.owns(t) {
		return v1.ErrUncertain
	}
	active := filepath.Join(s.root, "active")
	if err := os.Remove(filepath.Join(active, "owner")); err != nil {
		return v1.ErrUncertain
	}
	if err := os.Remove(active); err != nil {
		return v1.ErrUncertain
	}
	return syncDir(s.root)
}

func writeOnce(path string, data []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync ledger directory: %w", err)
	}
	return nil
}
