package policy

import (
	"strings"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func TestPlanRequiresExactlyThePolicyOperation(t *testing.T) {
	valid := `{"version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"}]}`
	if _, err := ParsePlan([]byte(valid), v1.UnitOperation); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"shell field":        `{"version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1","shell":"touch /tmp/x"}]}`,
		"shell operation":    `{"version":"argus.plan/v1","operations":[{"id":"sh -c echo injected"}]}`,
		"path traversal":     `{"version":"argus.plan/v1","operations":[{"id":"../../etc/passwd"}]}`,
		"missing check":      `{"version":"argus.plan/v1","operations":[]}`,
		"duplicate check":    `{"version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"},{"id":"synthetic-python-unit/v1"}]}`,
		"duplicate field":    `{"version":"bad","version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"}]}`,
		"case alias":         `{"Version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"}]}`,
		"case duplicate":     `{"version":"bad","Version":"argus.plan/v1","operations":[{"id":"synthetic-python-unit/v1"}]}`,
		"duplicate nested":   `{"version":"argus.plan/v1","operations":[{"id":"bad","id":"synthetic-python-unit/v1"}]}`,
		"extra JSON":         valid + `{}`,
		"truncated JSON":     `{"version":`,
		"oversized response": strings.Repeat("x", 8193),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlan([]byte(raw), v1.UnitOperation); err == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}

func TestUniqueJSONRejectsInvalidUTF8(t *testing.T) {
	if UniqueJSON([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}) {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestTaskRejectsTraversalAndBadIdentity(t *testing.T) {
	task := v1.Task{Version: v1.TaskVersion, TaskID: "task-1", TenantID: "tenant-a", ProjectID: "project-a",
		SourceSHA: strings.Repeat("a", 40), IdempotencyKey: "key-1", Signature: strings.Repeat("a", 64)}
	if !ValidTask(task) {
		t.Fatal("valid task rejected")
	}
	for _, mutate := range []func(*v1.Task){
		func(t *v1.Task) { t.ProjectID = "../other" },
		func(t *v1.Task) { t.TenantID = "x/y" },
		func(t *v1.Task) { t.SourceSHA = "--upload-pack" },
		func(t *v1.Task) { t.IdempotencyKey = "" },
	} {
		bad := task
		mutate(&bad)
		if ValidTask(bad) {
			t.Fatalf("invalid identity accepted: %#v", bad)
		}
	}
}
