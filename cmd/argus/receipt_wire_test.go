package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

func TestCLIReceiptWireNullAndValidFail(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "pkg", "evidence", "testdata", "receipt-wire-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Bases map[string]v1.Envelope `json:"bases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pass", "fail", "null"} {
		t.Run(name, func(t *testing.T) {
			base := corpus.Bases["pass"]
			if name == "fail" {
				base = corpus.Bases["fail"]
			}
			raw, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if name == "null" {
				changed := bytes.Replace(raw, []byte(`"exit_code":0`), []byte(`"exit_code":null`), 1)
				if bytes.Equal(changed, raw) {
					t.Fatal("null mutation did not change fixture")
				}
				raw, want = changed, 2
			}
			path := filepath.Join(t.TempDir(), "receipt.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			got := run([]string{"verify", "--receipt", path, "--sha256", base.SHA256}, &stdout, &stderr)
			if got != want {
				t.Fatalf("verify exit=%d, want=%d; stdout=%s stderr=%s", got, want, stdout.String(), stderr.String())
			}
			if want == 0 && !bytes.Contains(stdout.Bytes(), []byte("VERIFIED")) {
				t.Fatal("valid receipt was not reported as verified")
			}
		})
	}
}
