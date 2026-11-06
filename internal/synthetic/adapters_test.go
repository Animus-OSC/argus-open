package synthetic

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func TestFakeModelContractIsBoundedLocalAndCancelable(t *testing.T) {
	m := FakeModel{}
	ctx := context.Background()
	caps, err := m.Capabilities(ctx)
	if err != nil || !caps.LocalOnly || !caps.StructuredOutput || !caps.Cancellation || caps.MaxConcurrent != 1 {
		t.Fatal("unsafe fake capabilities")
	}
	id, err := m.Health(ctx)
	if err != nil || id.Digest != ModelDigest {
		t.Fatal("fake identity invalid")
	}
	response, err := m.Plan(ctx, v1.PlanRequest{MaxResponseBytes: 8192, MaxOutputTokens: 256})
	if err != nil || response.Identity != id || response.Usage.OutputBytes != int64(len(response.Plan)) {
		t.Fatal("invalid fake response")
	}
	if _, err := m.Plan(ctx, v1.PlanRequest{MaxResponseBytes: 1, MaxOutputTokens: 256}); err == nil {
		t.Fatal("response limit ignored")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Plan(canceled, v1.PlanRequest{MaxResponseBytes: 8192, MaxOutputTokens: 256}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, err := (FakeModel{Err: errors.New("unavailable")}).Health(ctx); err == nil {
		t.Fatal("unavailable model accepted")
	}
}

func TestSyntheticSignatureBindsEveryTaskField(t *testing.T) {
	task := v1.Task{Version: v1.TaskVersion, TaskID: "task", TenantID: "tenant", ProjectID: "project", SourceSHA: "sha", IdempotencyKey: "key"}
	task.Signature = Sign(task)
	if err := (EventVerifier{}).Verify(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*v1.Task){
		func(t *v1.Task) { t.TenantID = "other" },
		func(t *v1.Task) { t.ProjectID = "other" },
		func(t *v1.Task) { t.SourceSHA = "other" },
		func(t *v1.Task) { t.TaskID = "other" },
		func(t *v1.Task) { t.IdempotencyKey = "other" },
	} {
		changed := task
		change(&changed)
		if (EventVerifier{}).Verify(context.Background(), changed) == nil {
			t.Fatal("tampered event accepted")
		}
	}
}
