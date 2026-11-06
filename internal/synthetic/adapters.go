// Package synthetic provides fake, offline-only event, registry and model adapters.
package synthetic

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

// This public fixture key is not a production identity or authorization scheme.
var fixtureKey = []byte("argus-public-synthetic-fixture-key-v1")

func Sign(t v1.Task) string {
	t.Signature = ""
	b, _ := json.Marshal(t)
	h := hmac.New(sha256.New, fixtureKey)
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

type EventVerifier struct{}

func (EventVerifier) Verify(ctx context.Context, t v1.Task) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	got, err := hex.DecodeString(t.Signature)
	if err != nil || !hmac.Equal(got, mustDecode(Sign(t))) {
		return v1.ErrDenied
	}
	return nil
}

func mustDecode(s string) []byte { b, _ := hex.DecodeString(s); return b }

type Registry struct{ Projects []v1.Project }

func (r Registry) Lookup(ctx context.Context, tenant, project string) (v1.Project, error) {
	if ctx.Err() != nil {
		return v1.Project{}, ctx.Err()
	}
	for _, p := range r.Projects {
		if p.TenantID == tenant && p.ProjectID == project {
			return p, nil
		}
	}
	return v1.Project{}, v1.ErrDenied
}

var ModelDigest = func() string {
	h := sha256.Sum256([]byte("argus-fake-model-v1"))
	return "sha256:" + hex.EncodeToString(h[:])
}()

// FakeModel deliberately never contacts Ollama or any network endpoint.
type FakeModel struct {
	Response         []byte
	Err              error
	Identity         v1.ModelIdentity
	ResponseIdentity v1.ModelIdentity
}

func (FakeModel) ContractVersion() string { return "argus.model/v1" }

func (m FakeModel) Capabilities(ctx context.Context) (v1.ModelCapabilities, error) {
	if ctx.Err() != nil {
		return v1.ModelCapabilities{}, ctx.Err()
	}
	if m.Err != nil {
		return v1.ModelCapabilities{}, m.Err
	}
	return v1.ModelCapabilities{LocalOnly: true, StructuredOutput: true, Cancellation: true,
		MaxInputBytes: 4096, MaxOutputBytes: 8192, MaxConcurrent: 1, MaxContextTokens: 1024, MaxOutputTokens: 256}, nil
}

func (m FakeModel) Health(ctx context.Context) (v1.ModelIdentity, error) {
	if ctx.Err() != nil {
		return v1.ModelIdentity{}, ctx.Err()
	}
	if m.Err != nil {
		return v1.ModelIdentity{}, m.Err
	}
	if m.Identity.Provider != "" || m.Identity.Digest != "" {
		return m.Identity, nil
	}
	return v1.ModelIdentity{Provider: "fake-ollama", Digest: ModelDigest}, nil
}

func (m FakeModel) Plan(ctx context.Context, req v1.PlanRequest) (v1.ModelResponse, error) {
	if ctx.Err() != nil {
		return v1.ModelResponse{}, ctx.Err()
	}
	if m.Err != nil {
		return v1.ModelResponse{}, m.Err
	}
	raw := m.Response
	if raw == nil {
		raw = []byte(`{"version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"}]}`)
	}
	if req.MaxResponseBytes <= 0 || req.MaxOutputTokens <= 0 || len(raw) > req.MaxResponseBytes {
		return v1.ModelResponse{}, errors.New("model output exceeds limit")
	}
	identity, err := m.Health(ctx)
	if err != nil {
		return v1.ModelResponse{}, err
	}
	if m.ResponseIdentity.Provider != "" || m.ResponseIdentity.Digest != "" {
		identity = m.ResponseIdentity
	}
	return v1.ModelResponse{Identity: identity, Plan: append([]byte(nil), raw...),
		Usage: v1.ModelUsage{OutputBytes: int64(len(raw))}}, nil
}
