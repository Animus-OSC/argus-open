package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func validTestReport() testReport {
	return testReport{Version: "argus.unittest/v1", PythonVersion: "3.12.3",
		DiscoveredIDs: []string{"tests.test_fixture.T.test_ok"},
		Records:       []testRecord{{ID: "tests.test_fixture.T.test_ok", Status: "PASS"}}, Completed: true}
}
func reportJSON(t *testing.T, report testReport) []byte {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestParseTestReportValidOutcomes(t *testing.T) {
	for _, status := range []string{"PASS", "FAIL", "ERROR", "SKIP", "XFAIL", "XPASS"} {
		report := validTestReport()
		report.Records[0].Status = status
		got, err := parseTestReport(reportJSON(t, report))
		if err != nil || !got.Completed || got.Records[0].Status != status {
			t.Fatalf("%s: %+v %v", status, got, err)
		}
	}
	for _, report := range []testReport{
		{Version: "argus.unittest/v1", PythonVersion: "3.12.3", DiscoveredIDs: []string{}, Records: []testRecord{}, Completed: true},
		{Version: "argus.unittest/v1", PythonVersion: "3.12.3", DiscoveredIDs: []string{"tests.T.test_pending"}, Records: []testRecord{}, Completed: false},
	} {
		if _, err := parseTestReport(reportJSON(t, report)); err != nil {
			t.Fatalf("valid non-PASS report: %v", err)
		}
	}
}
func TestParseTestReportRejectsAmbiguousWire(t *testing.T) {
	raw := reportJSON(t, validTestReport())
	var base map[string]json.RawMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	for key := range base {
		for name, mutate := range map[string]func(map[string]json.RawMessage){
			"missing":    func(v map[string]json.RawMessage) { delete(v, key) },
			"null":       func(v map[string]json.RawMessage) { v[key] = json.RawMessage("null") },
			"wrong_type": func(v map[string]json.RawMessage) { v[key] = json.RawMessage("{}") },
			"case_alias": func(v map[string]json.RawMessage) { v[strings.ToUpper(key)] = v[key]; delete(v, key) },
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				v := map[string]json.RawMessage{}
				for k, b := range base {
					v[k] = b
				}
				mutate(v)
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parseTestReport(b); err == nil {
					t.Fatal("invalid wire accepted")
				}
			})
		}
	}
	for _, field := range []string{"id", "status"} {
		for _, value := range []string{"null", "0", "[]", "false"} {
			b := bytes.Replace(raw, []byte(fmt.Sprintf(`"%s":"%s"`, field, map[string]string{"id": "tests.test_fixture.T.test_ok", "status": "PASS"}[field])), []byte(fmt.Sprintf(`"%s":%s`, field, value)), 1)
			if bytes.Equal(b, raw) {
				t.Fatal("bad mutation")
			}
			if _, err := parseTestReport(b); err == nil {
				t.Fatalf("record %s=%s accepted", field, value)
			}
		}
	}
	invalid := [][]byte{
		nil, []byte("null"), []byte("[]"), append(append([]byte(nil), raw...), []byte(" {}")...),
		append([]byte{0xff}, raw...), append([]byte("noise\n"), raw...), bytes.Repeat([]byte(" "), maxTestReportBytes+1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"completed":true`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"comple\u0074ed":true`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"Completed":true`), 1),
		bytes.Replace(raw, []byte(`"status":"PASS"`), []byte(`"status":"FAIL","status":"PASS"`), 1),
		bytes.Replace(raw, []byte(`"status":"PASS"`), []byte(`"Status":"PASS"`), 1),
		bytes.Replace(raw, []byte(`"status":"PASS"`), []byte(`"status":"PASS","extra":true`), 1),
		bytes.Replace(raw, []byte(`"id":"tests.test_fixture.T.test_ok",`), nil, 1),
		bytes.Replace(raw, []byte(`"status":"PASS"`), []byte(`"status":"pass"`), 1),
		bytes.Replace(raw, []byte(`"discovered_ids":["tests.test_fixture.T.test_ok"]`), []byte(`"discovered_ids":[null]`), 1),
		bytes.Replace(raw, []byte(`"records":[{"id":"tests.test_fixture.T.test_ok","status":"PASS"}]`), []byte(`"records":[null]`), 1),
	}
	for i, b := range invalid {
		if _, err := parseTestReport(b); err == nil {
			t.Fatalf("case %d accepted: %q", i, b)
		}
	}
}
func TestParseTestReportRejectsInconsistentRecords(t *testing.T) {
	cases := map[string]func(*testReport){
		"version":              func(v *testReport) { v.Version = "argus.unittest/v2" },
		"python":               func(v *testReport) { v.PythonVersion = "3.12" },
		"duplicate_discovered": func(v *testReport) { v.DiscoveredIDs = append(v.DiscoveredIDs, v.DiscoveredIDs[0]) },
		"duplicate_record":     func(v *testReport) { v.Records = append(v.Records, v.Records[0]) },
		"unknown_record":       func(v *testReport) { v.Records[0].ID = "tests.other.test_forged" },
		"missing_record":       func(v *testReport) { v.Records = []testRecord{} },
		"bad_id":               func(v *testReport) { v.DiscoveredIDs[0] = "tests.test\nforged" },
		"long_id":              func(v *testReport) { v.DiscoveredIDs[0] = strings.Repeat("a", maxTestIDBytes+1) },
		"too_many": func(v *testReport) {
			for i := 0; i < maxProfileTests; i++ {
				v.DiscoveredIDs = append(v.DiscoveredIDs, fmt.Sprintf("tests.T.test_%d", i))
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := validTestReport()
			mutate(&v)
			if _, err := parseTestReport(reportJSON(t, v)); err == nil {
				t.Fatal("inconsistent report accepted")
			}
		})
	}
}

// Driver fixtures run in fresh network/process/user namespaces. No host home
// or credentials are mounted; writable temporary storage is tmpfs.
func runDriverFixture(t *testing.T, code string) ([]byte, string, int) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Linux amd64 profile prerequisite")
	}
	if os.Geteuid() == 0 {
		t.Fatal("driver sandbox tests require a non-root user")
	}
	for _, p := range []string{"/usr/bin/bwrap", "/usr/bin/prlimit", "/usr/bin/python3.12", "/usr/lib/python3.12", "/usr/lib/x86_64-linux-gnu", "/usr/lib64"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	for _, d := range []string{"python/src", "python/tests"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string][]byte{"python/tests/__init__.py": nil, "python/tests/test_fixture.py": []byte(code)} {
		if err := os.WriteFile(filepath.Join(work, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	driver := filepath.Join(root, "driver.py")
	if err := os.WriteFile(driver, driverSource, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--dir", "/usr", "--dir", "/usr/bin", "--dir", "/usr/lib",
		"--ro-bind", "/usr/bin/python3.12", "/usr/bin/python3.12", "--ro-bind", "/usr/bin/prlimit", "/usr/bin/prlimit",
		"--ro-bind", "/usr/lib/python3.12", "/usr/lib/python3.12", "--ro-bind", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"--ro-bind", "/usr/lib64", "/usr/lib64", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--size", "16777216", "--tmpfs", "/tmp", "--ro-bind", work, "/work",
		"--dir", "/runner", "--ro-bind", driver, "/runner/driver.py", "--chdir", "/work", "--clearenv", "--setenv", "HOME", "/tmp",
		"/usr/bin/prlimit", "--cpu=3", "--as=268435456", "--fsize=1048576", "--nofile=64", "--nproc=32", "--core=0", "--",
		"/usr/bin/python3.12", "-I", "-S", "-B", "/runner/driver.py"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "ARGUS_DRIVER_SECRET=must-not-leak"}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("driver fixture timeout: %s", stderr.String())
	}
	exit := 0
	if err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) {
			t.Fatal(err)
		}
		exit = e.ExitCode()
	}
	if len(out.Bytes()) > maxTestReportBytes {
		t.Fatal("fixture output exceeds report bound")
	}
	return out.Bytes(), stderr.String(), exit
}
func TestActualPythonDriverOutcomes(t *testing.T) {
	cases := []struct {
		name, code string
		exit       int
		completed  bool
		statuses   []string
	}{
		{"pass", `import os, sys, tempfile, unittest
print('import stdout must be redirected')
class T(unittest.TestCase):
 def test_ok(self):
  print('test stdout must be redirected')
  self.assertTrue(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)
  self.assertIsNone(os.getenv('ARGUS_DRIVER_SECRET'))
  self.assertFalse(os.path.exists('/home'))
  self.assertFalse(os.path.exists('/var/run/docker.sock'))
  with tempfile.TemporaryDirectory() as d: self.assertTrue(os.path.isdir(d))
`, 0, true, []string{"PASS"}},
		{"fail", "import unittest\nclass T(unittest.TestCase):\n def test_bad(self): self.fail('fixture')\n", 1, true, []string{"FAIL"}},
		{"error", "import unittest\nclass T(unittest.TestCase):\n def test_bad(self): raise ValueError('fixture')\n", 1, true, []string{"ERROR"}},
		{"mixed_skip", "import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n @unittest.skip('fixture')\n def test_skip(self): pass\n", 3, true, []string{"PASS", "SKIP"}},
		{"all_skip", "import unittest\nclass T(unittest.TestCase):\n @unittest.skip('fixture')\n def test_skip(self): pass\n", 3, true, []string{"SKIP"}},
		{"empty", "import unittest\n", 3, true, []string{}},
		{"import_error", "import argus_driver_missing_fixture_module\n", 1, true, []string{"ERROR"}},
		{"expected_failure", "import unittest\nclass T(unittest.TestCase):\n @unittest.expectedFailure\n def test_bad(self): self.fail('fixture')\n", 3, true, []string{"XFAIL"}},
		{"unexpected_success", "import unittest\nclass T(unittest.TestCase):\n @unittest.expectedFailure\n def test_ok(self): pass\n", 3, true, []string{"XPASS"}},
		{"subtest_failure", "import unittest\nclass T(unittest.TestCase):\n def test_sub(self):\n  for i in range(3):\n   with self.subTest(i=i): self.assertEqual(i,0)\n", 1, true, []string{"FAIL"}},
		{"subtest_error_priority", "import unittest\nclass T(unittest.TestCase):\n def test_sub(self):\n  with self.subTest(kind='fail'): self.fail('fixture')\n  with self.subTest(kind='error'): raise ValueError('fixture')\n", 1, true, []string{"ERROR"}},
		{"subtest_skip", "import unittest\nclass T(unittest.TestCase):\n def test_sub(self):\n  with self.subTest(i=1): self.skipTest('fixture')\n  with self.subTest(i=2): pass\n", 3, true, []string{"SKIP"}},
		{"setup_error", "import unittest\nclass T(unittest.TestCase):\n @classmethod\n def setUpClass(cls): raise ValueError('fixture')\n def test_ok(self): pass\n", 3, false, []string{}},
		{"stopped_suite", "import unittest\nclass T(unittest.TestCase):\n def test_a(self): self._outcome.result.stop()\n def test_b(self): pass\n", 3, false, []string{"PASS"}},
		{"import_interrupt", "raise KeyboardInterrupt()\n", 1, true, []string{"ERROR"}},
		{"discovery_interrupt", "def load_tests(loader, tests, pattern): raise KeyboardInterrupt()\n", 3, false, []string{}},
		{"test_interrupt", "import unittest\nclass T(unittest.TestCase):\n def test_bad(self): raise KeyboardInterrupt()\n", 3, false, []string{}},
		{"system_exit", "import unittest\nclass T(unittest.TestCase):\n def test_bad(self): raise SystemExit(0)\n", 1, true, []string{"ERROR"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, stderr, exit := runDriverFixture(t, tc.code)
			report, err := parseTestReport(raw)
			if err != nil || exit != tc.exit || report.Completed != tc.completed {
				t.Fatalf("exit=%d report=%+v err=%v stdout=%q stderr=%s", exit, report, err, raw, stderr)
			}
			statuses := make([]string, 0, len(report.Records))
			for _, r := range report.Records {
				statuses = append(statuses, r.Status)
			}
			sort.Strings(statuses)
			sort.Strings(tc.statuses)
			if strings.Join(statuses, ",") != strings.Join(tc.statuses, ",") {
				t.Fatalf("statuses=%v want=%v", statuses, tc.statuses)
			}
			if tc.name == "pass" && !strings.Contains(stderr, "test stdout must be redirected") {
				t.Fatal("test stdout was not redirected")
			}
			if tc.name == "fail" && !strings.Contains(stderr, "AssertionError: fixture") {
				t.Fatal("actual unittest failure traceback was not retained in stderr")
			}
			if tc.name == "error" && !strings.Contains(stderr, "ValueError: fixture") {
				t.Fatal("actual unittest error traceback was not retained in stderr")
			}
		})
	}
}
func TestActualPythonDriverEarlyExitHasNoReport(t *testing.T) {
	raw, stderr, exit := runDriverFixture(t, "import os, unittest\nclass T(unittest.TestCase):\n def test_exit(self): os._exit(0)\n")
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr)
	}
	if _, err := parseTestReport(raw); err == nil {
		t.Fatalf("early process exit accepted: %q", raw)
	}
}
