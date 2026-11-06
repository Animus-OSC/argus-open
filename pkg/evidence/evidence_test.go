package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func sample() v1.Receipt {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return v1.Receipt{Version: v1.ReceiptVersion, TaskID: "task", TenantID: "tenant", ProjectID: "project",
		SourceSHA: strings.Repeat("a", 40), IdempotencyKey: "key", EventSHA256: "sha256:" + strings.Repeat("c", 64), PolicyVersion: "policy/v1",
		Model: v1.ModelIdentity{Provider: "fake", Digest: "sha256:" + strings.Repeat("a", 64)},
		Observation: v1.Observation{Operation: v1.UnitOperation, Worker: "worker", ExitCode: 0, TestsRun: 2,
			StartedAt: now, FinishedAt: now.Add(time.Second), OutputSHA256: "sha256:" + strings.Repeat("b", 64)}, State: v1.Pass}
}

func TestVerifyDetectsTamperingAndRequiresExternalDigest(t *testing.T) {
	e, err := Seal(sample())
	if err != nil || Verify(e, e.SHA256) != nil {
		t.Fatal("valid evidence rejected", err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(b)
	if err != nil || Verify(decoded, e.SHA256) != nil {
		t.Fatal("valid canonical evidence could not be decoded")
	}
	caseAlias := strings.Replace(string(b), `"receipt":`, `"Receipt":`, 1)
	if _, err := Decode([]byte(caseAlias)); err == nil {
		t.Fatal("case alias accepted")
	}
	tampered := e
	tampered.Receipt.SourceSHA = strings.Repeat("b", 40)
	if Verify(tampered, e.SHA256) == nil {
		t.Fatal("source tampering accepted")
	}
	if Verify(e, "sha256:"+strings.Repeat("0", 64)) == nil {
		t.Fatal("wrong external digest accepted")
	}
	for _, mutate := range []func(*v1.Receipt){
		func(r *v1.Receipt) { r.Observation.ExitCode = 1 },
		func(r *v1.Receipt) { r.Observation.TestsRun = 0 },
		func(r *v1.Receipt) { r.Observation.FinishedAt = r.Observation.StartedAt.Add(-time.Second) },
		func(r *v1.Receipt) { r.State = v1.Uncertain },
	} {
		r := sample()
		mutate(&r)
		if _, err := Seal(r); err == nil {
			t.Fatal("invalid receipt sealed")
		}
	}
	failure := sample()
	failure.State, failure.Observation.ExitCode = v1.Fail, 1
	if _, err := Seal(failure); err != nil {
		t.Fatal("real failing test cannot be recorded", err)
	}
}
