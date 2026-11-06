// Package profile runs a closed catalog of pinned public test profiles.
package profile

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"
)

// driverSource is trusted Argus code, not a project-provided command.
//
//go:embed unittest_driver.py
var driverSource []byte

const maxTestReportBytes = 64 << 10
const maxProfileTests = 256
const maxTestIDBytes = 512

type testRecord struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type testReport struct {
	Version       string       `json:"version"`
	PythonVersion string       `json:"python_version"`
	DiscoveredIDs []string     `json:"discovered_ids"`
	Records       []testRecord `json:"records"`
	Completed     bool         `json:"completed"`
}

var testIDPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
var pythonVersionPattern = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$`)

// uniqueReportJSON rejects duplicate keys at every level before decoding; Go's
// encoding/json otherwise accepts duplicate and case-aliased struct fields.
func uniqueReportJSON(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 8 {
			return false
		}
		token, err := dec.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := dec.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for dec.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := dec.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := dec.Token()
	return err == io.EOF
}

func reportObject(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, errors.New("invalid unittest report object")
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, errors.New("missing or null unittest report field")
		}
	}
	return fields, nil
}

// parseTestReport validates structure and internal consistency only. A caller
// must also check the process outcome, pinned source and exact expected IDs.
// This local JSON is not authenticated worker evidence.
func parseTestReport(raw []byte) (testReport, error) {
	var report testReport
	invalid := errors.New("invalid unittest report")
	if len(raw) == 0 || len(raw) > maxTestReportBytes || !uniqueReportJSON(raw) {
		return report, invalid
	}
	fields, err := reportObject(raw, "version", "python_version", "discovered_ids", "records", "completed")
	if err != nil {
		return report, err
	}
	var ids, records []json.RawMessage
	if json.Unmarshal(fields["discovered_ids"], &ids) != nil || len(ids) > maxProfileTests ||
		json.Unmarshal(fields["records"], &records) != nil || len(records) > maxProfileTests {
		return report, invalid
	}
	for _, id := range ids {
		if bytes.Equal(bytes.TrimSpace(id), []byte("null")) {
			return report, invalid
		}
	}
	for _, record := range records {
		if _, err := reportObject(record, "id", "status"); err != nil {
			return report, err
		}
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return testReport{}, invalid
	}
	if report.Version != "argus.unittest/v1" || !pythonVersionPattern.MatchString(report.PythonVersion) {
		return testReport{}, invalid
	}
	discovered := map[string]bool{}
	for _, id := range report.DiscoveredIDs {
		if len(id) == 0 || len(id) > maxTestIDBytes || !testIDPattern.MatchString(id) || discovered[id] {
			return testReport{}, invalid
		}
		discovered[id] = true
	}
	seen := map[string]bool{}
	for _, record := range report.Records {
		if !discovered[record.ID] || seen[record.ID] {
			return testReport{}, invalid
		}
		seen[record.ID] = true
		switch record.Status {
		case "PASS", "FAIL", "ERROR", "SKIP", "XFAIL", "XPASS":
		default:
			return testReport{}, invalid
		}
	}
	if report.Completed && len(report.Records) != len(report.DiscoveredIDs) {
		return testReport{}, invalid
	}
	return report, nil
}
