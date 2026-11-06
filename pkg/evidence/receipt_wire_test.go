package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

type receiptWireCase struct {
	Name        string          `json:"name"`
	Base        string          `json:"base"`
	Operation   string          `json:"operation"`
	Path        []string        `json:"path"`
	Value       json.RawMessage `json:"value"`
	RenameTo    string          `json:"rename_to"`
	SchemaValid bool            `json:"schema_valid"`
	DecodeValid bool            `json:"decode_valid"`
	VerifyValid bool            `json:"verify_valid"`
}

type receiptWireCorpus struct {
	Version int                    `json:"version"`
	Bases   map[string]v1.Envelope `json:"bases"`
	Cases   []receiptWireCase      `json:"cases"`
}

func loadReceiptWireCorpus(t *testing.T) receiptWireCorpus {
	t.Helper()
	data, err := os.ReadFile("testdata/receipt-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus receiptWireCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != 1 || len(corpus.Bases) != 2 || len(corpus.Cases) < 60 {
		t.Fatal("incomplete receipt wire corpus")
	}
	return corpus
}

func renderReceiptWireCase(t *testing.T, corpus receiptWireCorpus, c receiptWireCase) []byte {
	t.Helper()
	base, ok := corpus.Bases[c.Base]
	if !ok {
		t.Fatal("unknown corpus base")
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Operation == "none" {
		return raw
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if len(c.Path) == 0 {
		t.Fatal("missing mutation path")
	}
	parent := object
	for _, key := range c.Path[:len(c.Path)-1] {
		next, ok := parent[key].(map[string]any)
		if !ok {
			t.Fatal("invalid corpus mutation path")
		}
		parent = next
	}
	field := c.Path[len(c.Path)-1]
	switch c.Operation {
	case "set":
		var value any
		if err := json.Unmarshal(c.Value, &value); err != nil {
			t.Fatal(err)
		}
		parent[field] = value
	case "delete":
		delete(parent, field)
	case "rename":
		parent[c.RenameTo] = parent[field]
		delete(parent, field)
	default:
		t.Fatal("unsupported corpus mutation")
	}
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReceiptWireCorpusDecodeAndVerify(t *testing.T) {
	corpus := loadReceiptWireCorpus(t)
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw := renderReceiptWireCase(t, corpus, c)
			envelope, err := Decode(raw)
			if (err == nil) != c.DecodeValid {
				t.Fatalf("Decode accepted=%v, want=%v; error=%v", err == nil, c.DecodeValid, err)
			}
			if err == nil {
				err = Verify(envelope, corpus.Bases[c.Base].SHA256)
			}
			if (err == nil) != c.VerifyValid {
				t.Fatalf("Decode+Verify accepted=%v, want=%v; error=%v", err == nil, c.VerifyValid, err)
			}
		})
	}
}

func TestCanonicalReceiptDigestsRemainStable(t *testing.T) {
	corpus := loadReceiptWireCorpus(t)
	for _, state := range []v1.State{v1.Pass, v1.Fail} {
		receipt := sample()
		key := "pass"
		if state == v1.Fail {
			key = "fail"
			receipt.State, receipt.Observation.ExitCode = v1.Fail, 1
		}
		envelope, err := Seal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.SHA256 != corpus.Bases[key].SHA256 {
			t.Fatalf("%s canonical digest changed: got %s, want %s", key, envelope.SHA256, corpus.Bases[key].SHA256)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(raw)
		if err != nil || Verify(decoded, envelope.SHA256) != nil {
			t.Fatalf("valid %s did not survive public Decode+Verify: %v", key, err)
		}
	}
}

func TestReceiptWireRejectsAmbiguousAndOversizeJSON(t *testing.T) {
	corpus := loadReceiptWireCorpus(t)
	valid, err := json.Marshal(corpus.Bases["pass"])
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"duplicate scalar":  []byte(strings.Replace(string(valid), `"exit_code":0`, `"exit_code":0,"exit_code":0`, 1)),
		"escaped duplicate": []byte(strings.Replace(string(valid), `"exit_code":0`, `"exit_code":0,"exit_\u0063ode":0`, 1)),
		"case duplicate":    []byte(strings.Replace(string(valid), `"exit_code":0`, `"exit_code":0,"EXIT_CODE":0`, 1)),
		"whitespace null":   []byte(strings.Replace(string(valid), `"exit_code":0`, "\"exit_code\": \n null \t", 1)),
		"trailing document": append(append([]byte(nil), valid...), []byte(" {}")...),
		"oversize":          bytes.Repeat([]byte(" "), (64<<10)+1),
		"invalid UTF-8":     []byte(strings.Replace(string(valid), `"worker":"worker"`, "\"worker\":\"\xff\"", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, valid) {
				t.Fatal("negative mutation did not change fixture")
			}
			if _, err := Decode(raw); err == nil {
				t.Fatal("ambiguous evidence accepted")
			}
		})
	}
}
