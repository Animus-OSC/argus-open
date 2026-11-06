// Package policy validates data before the model or worker can affect execution.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	v1 "github.com/Animus-OSC/argus-open/api/v1"
)

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func ValidDigest(s string) bool { return digestPattern.MatchString(s) }

func ValidIdentifier(s string) bool { return idPattern.MatchString(s) }

func ValidTask(t v1.Task) bool {
	return t.Version == v1.TaskVersion && idPattern.MatchString(t.TaskID) &&
		idPattern.MatchString(t.TenantID) && idPattern.MatchString(t.ProjectID) &&
		idPattern.MatchString(t.IdempotencyKey) && shaPattern.MatchString(t.SourceSHA) &&
		len(t.Signature) == 64
}

// ParsePlan rejects unknown fields, extra JSON, excess output, duplicate and
// omitted operations. The policy, not the model, supplies the required check.
func ParsePlan(raw []byte, required string) (v1.Operation, error) {
	var p v1.Plan
	if len(raw) == 0 || len(raw) > 8192 || required != v1.UnitOperation {
		return v1.Operation{}, errors.New("invalid plan")
	}
	if !UniqueJSON(raw) {
		return v1.Operation{}, errors.New("ambiguous plan")
	}
	if !ExactKeys(raw, "version", "operations") {
		return v1.Operation{}, errors.New("invalid plan keys")
	}
	var object map[string]json.RawMessage
	var operations []json.RawMessage
	if json.Unmarshal(raw, &object) != nil || json.Unmarshal(object["operations"], &operations) != nil || len(operations) != 1 || !ExactKeys(operations[0], "id") {
		return v1.Operation{}, errors.New("invalid operation keys")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return v1.Operation{}, errors.New("invalid plan")
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return v1.Operation{}, errors.New("invalid plan")
	}
	if p.Version != v1.PlanVersion || len(p.Operations) != 1 || p.Operations[0].ID != required {
		return v1.Operation{}, errors.New("operation denied")
	}
	return p.Operations[0], nil
}

// encoding/json accepts duplicate object names by default. Reject them before
// decoding so two consumers cannot interpret an attacker-controlled plan differently.
func UniqueJSON(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueValue(d, 0); err != nil {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// ExactKeys prevents encoding/json's case-insensitive field matching from
// accepting names that the versioned JSON schema does not recognize.
func ExactKeys(raw []byte, keys ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			name = strings.ToLower(name)
			if err != nil || !ok || seen[name] {
				return errors.New("duplicate or invalid key")
			}
			seen[name] = true
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}
