// Package evidence checks canonical digest and scoped verdict consistency.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
	"github.com/Animus-OSC/argus-open/internal/policy"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TaskDigest(t v1.Task) string {
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Decode enforces exact v1 JSON field names and rejects duplicate or trailing
// data before a caller verifies the independently held digest.
func Decode(raw []byte) (v1.Envelope, error) {
	var e v1.Envelope
	if len(raw) == 0 || len(raw) > 64<<10 || !policy.UniqueJSON(raw) || !policy.ExactKeys(raw, "receipt", "sha256") {
		return e, errors.New("invalid evidence encoding")
	}
	var top, receipt map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !policy.ExactKeys(top["receipt"], "version", "task_id", "tenant_id", "project_id", "source_sha", "idempotency_key", "event_sha256", "policy_version", "model", "observation", "state") ||
		json.Unmarshal(top["receipt"], &receipt) != nil || !policy.ExactKeys(receipt["model"], "provider", "digest") ||
		!policy.ExactKeys(receipt["observation"], "operation", "worker", "exit_code", "tests_run", "started_at", "finished_at", "output_sha256") {
		return e, errors.New("invalid evidence fields")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return e, errors.New("trailing evidence")
	}
	return e, nil
}

func Seal(r v1.Receipt) (v1.Envelope, error) {
	if err := validate(r); err != nil {
		return v1.Envelope{}, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return v1.Envelope{}, err
	}
	h := sha256.Sum256(b)
	return v1.Envelope{Receipt: r, SHA256: "sha256:" + hex.EncodeToString(h[:])}, nil
}

// Verify requires an independently supplied expected digest. SHA-256 does not
// authenticate its producer; callers must obtain the expected digest safely.
func Verify(e v1.Envelope, expected string) error {
	if !digestPattern.MatchString(expected) || e.SHA256 != expected {
		return errors.New("evidence digest mismatch")
	}
	sealed, err := Seal(e.Receipt)
	if err != nil || sealed.SHA256 != expected {
		return errors.New("invalid evidence")
	}
	return nil
}

func validate(r v1.Receipt) error {
	o := r.Observation
	if r.Version != v1.ReceiptVersion || !policy.ValidIdentifier(r.TaskID) || !policy.ValidIdentifier(r.TenantID) || !policy.ValidIdentifier(r.ProjectID) || !policy.ValidIdentifier(r.IdempotencyKey) || !digestPattern.MatchString(r.EventSHA256) ||
		!commitPattern.MatchString(r.SourceSHA) || r.PolicyVersion == "" ||
		r.Model.Provider == "" || !digestPattern.MatchString(r.Model.Digest) ||
		o.Operation != v1.UnitOperation || o.Worker == "" || o.TestsRun < 1 || o.TestsRun > 99999 || o.ExitCode < 0 || o.ExitCode > 255 ||
		o.StartedAt.IsZero() || o.FinishedAt.Before(o.StartedAt) || !digestPattern.MatchString(o.OutputSHA256) {
		return errors.New("incomplete receipt")
	}
	if (r.State != v1.Pass || o.ExitCode != 0) && (r.State != v1.Fail || o.ExitCode <= 0) {
		return errors.New("inconsistent verdict")
	}
	return nil
}
