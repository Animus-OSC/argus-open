import json
import importlib.util
import io
import datetime
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import security

generator_path = Path(__file__).resolve().parent.parent / "docs/reviews/phase1.1/generate-sbom.py"
spec = importlib.util.spec_from_file_location("argus_sbom_generator", generator_path)
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


class SecurityGateTests(unittest.TestCase):
    def test_sbom_module_hash_vector_and_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "module.zip"
            name = "example.invalid/pkg@v1.0.0/a.txt"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, "hello\n")
            self.assertEqual(sbom.archive_h1(path), "h1:KqzVbSK4LgSzoM+IfizltmN2fHcdGFRPDVWP503tuc4=")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, "tampered\n")
            self.assertNotEqual(sbom.archive_h1(path), "h1:KqzVbSK4LgSzoM+IfizltmN2fHcdGFRPDVWP503tuc4=")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr(name, "duplicate\n")
            with self.assertRaises(ValueError):
                sbom.archive_h1(path)

    def test_snapshot_timestamp_rejects_old_and_future_files(self):
        security.validate_age(100000, 100000)
        for timestamp in (100000 - 86401, 100000 + 61):
            with self.assertRaises(security.GateError):
                security.validate_age(timestamp, 100000)

    def test_osv_requires_the_entire_exact_module_graph(self):
        manifest = Path("/tmp/example/go.mod")
        document = {"results": [{"source": {"path": str(manifest)}, "packages": [
            {"package": {"name": "example.invalid/a", "version": "1.2.3"}},
        ]}]}
        payload = json.dumps(document)
        self.assertEqual(security.osv_result(payload, {"example.invalid/a": "v1.2.3"}, manifest), (set(), 1))
        with self.assertRaises(security.GateError):
            security.osv_result(payload, {"example.invalid/a": "v1.2.4"}, manifest)
        with self.assertRaises(security.GateError):
            security.osv_result(payload, {"example.invalid/a": "v1.2.3", "example.invalid/b": "v1.0.0"}, manifest)
        document["results"][0]["packages"][0]["vulnerabilities"] = [{"id": security.NEGATIVE_ID}]
        self.assertIn(security.NEGATIVE_ID, security.osv_result(json.dumps(document),
                      {"example.invalid/a": "v1.2.3"}, manifest)[0])

    def test_govulncheck_requires_a_real_symbol_scan_and_sbom(self):
        config = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck",
                  "scanner_version": "v1.9.0", "db": security.GO_DB, "go_version": "go1.26.10",
                  "scan_level": "symbol", "scan_mode": "source", "db_last_modified": "2026-11-02T00:00:00Z"}
        expected = {"example.invalid/a": "v1.2.3"}
        sbom = {"go_version": "go1.26.10", "modules": [{"path": "stdlib", "version": "v1.26.10"},
                {"path": "github.com/Animus-OSC/argus-open"}, {"path": "example.invalid/a", "version": "v1.2.3"}],
                "roots": ["github.com/Animus-OSC/argus-open/cmd/argus"]}
        payload = json.dumps({"config": config}) + "\n" + json.dumps({"SBOM": sbom})
        roots = ["github.com/Animus-OSC/argus-open/cmd/argus"]
        self.assertEqual(security.govuln_result(payload, expected, roots)[1]["findings"], 0)
        with self.assertRaises(security.GateError):
            security.govuln_result(json.dumps({"config": config}), expected, roots)
        with self.assertRaises(security.GateError):
            security.govuln_result(payload, {"example.invalid/a": "v1.2.4"}, roots)
        config["scan_level"] = "module"
        with self.assertRaises(security.GateError):
            security.govuln_result(json.dumps({"config": config}) + json.dumps({"SBOM": sbom}), expected, roots)

    def test_online_query_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root) / "report"
            result = subprocess.run([sys.executable, "-B", str(Path(security.__file__)),
                                     "--go", sys.executable, "--tools", root, "--osv-cache", root,
                                     "--report-dir", str(report)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["status"], "BLOCKED")
            self.assertIn("explicitly enabled", summary["error"])

    def test_ignored_go_source_makes_tree_dirty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
            def git(*args):
                return subprocess.run(["/usr/bin/git", *args], cwd=root, env=env,
                                      capture_output=True, text=True, check=True)
            git("init", "-q")
            (root / ".gitignore").write_text("build/\n")
            git("add", ".gitignore")
            git("-c", "user.name=Argus Synthetic", "-c", "user.email=synthetic@example.invalid",
                "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "fixture")
            (root / "build").mkdir()
            (root / "build" / "ignored.go").write_text("package ignored\n")
            self.assertEqual(git("status", "--porcelain=v1", "-uall").stdout, "")
            checked = security.git_status(env, root)
            self.assertEqual(checked.returncode, 0)
            self.assertIn("!! build/", checked.stdout)

    def test_report_directory_cannot_resolve_inside_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            alias = Path(tmp) / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(security.GateError):
                security.report_path(alias / "report", root)
            self.assertFalse((root / "report").exists())
            self.assertEqual(security.report_path(Path(tmp) / "outside", root), Path(tmp) / "outside")

    def mock_govuln_stream(self, findings=(), mutate=None):
        roots = ["github.com/Animus-OSC/argus-open/cmd/argus",
                 "github.com/Animus-OSC/argus-open/internal/source",
                 "github.com/Animus-OSC/argus-open/internal/source",
                 "github.com/Animus-OSC/argus-open/internal/source.test"]
        config = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck",
                  "scanner_version": "v1.9.0", "db": security.GO_DB,
                  "db_last_modified": "2026-11-06T00:00:00Z", "go_version": "go1.26.10",
                  "scan_level": "symbol", "scan_mode": "source"}
        sbom = {"go_version": "go1.26.10", "modules": [
            {"path": "stdlib", "version": "v1.26.10"},
            {"path": "github.com/Animus-OSC/argus-open"},
            {"path": "example.invalid/a", "version": "v1.2.3"}],
            "roots": roots}
        items = [{"config": config}, {"SBOM": sbom}]
        for level in findings:
            frame = {"module": "stdlib", "version": "v1.26.10"}
            if level in ("package", "symbol"):
                frame["package"] = "net/http"
            if level == "symbol":
                frame["function"] = "Serve"
            identity = "GO-TEST-" + level.upper()
            items.extend(({"osv": {"id": identity}},
                          {"finding": {"osv": identity, "trace": [frame]}}))
        if mutate is not None:
            mutate(items)
        return "\n".join(json.dumps(item) for item in items) + "\n"

    def run_mocked_main(self, govuln_stream, govuln_rc=0, gosec_findings=False,
                        go_list_rc=0, duplicate_osv_results=False):
        """Exercise the real gate and aggregate; only scanner/process calls are mocked."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            (root / "go.mod").write_text("module github.com/Animus-OSC/argus-open\n", encoding="utf-8")
            tools = Path(tmp) / "tools"
            tools.mkdir()
            tool_hashes = {}
            for name in (*security.TOOL_HASHES, "govulncheck"):
                tool = tools / name
                tool.write_text("mock " + name, encoding="utf-8")
                if name in security.TOOL_HASHES:
                    tool_hashes[name] = security.digest(tool)
            go = Path(tmp) / "go"
            go.write_text("mock go", encoding="utf-8")
            cache = Path(tmp) / "cache"
            db = cache / "osv-scalibr" / "Go" / "all.zip"
            db.parent.mkdir(parents=True)
            db.write_bytes(b"mock OSV database")
            report = Path(tmp) / "report"

            def completed(command, rc=0, stdout="", stderr=""):
                return subprocess.CompletedProcess(command, rc, stdout, stderr)

            def fake_run(command, env, offline=True, cwd=root):
                executable = command[0]
                if executable == "/usr/bin/git":
                    return completed(command, stdout=("a" * 40 + "\n") if "rev-parse" in command else "")
                if executable == str(go):
                    if command[1:] == ["version"]:
                        return completed(command, stdout="go version go1.26.10 linux/amd64\n")
                    if command[1:3] == ["version", "-m"]:
                        return completed(command, stdout="dep\tgolang.org/x/vuln\tv1.9.0\th1:mock\n")
                    if command[1:] == ["mod", "edit", "-json"]:
                        return completed(command, stdout=json.dumps({"Require": [
                            {"Path": "example.invalid/a", "Version": "v1.2.3"}]}))
                    if command[1:5] == ["list", "-deps", "-test", "-buildvcs=false"]:
                        return completed(command, rc=go_list_rc, stdout="\n".join([
                            "github.com/Animus-OSC/argus-open/cmd/argus",
                            "github.com/Animus-OSC/argus-open/internal/source",
                            "github.com/Animus-OSC/argus-open/internal/source "
                            "[github.com/Animus-OSC/argus-open/internal/source.test]",
                            "github.com/Animus-OSC/argus-open/internal/source.test"]) + "\n")
                if executable == str(tools / "osv-scanner"):
                    lockfile = next(arg.removeprefix("--lockfile=") for arg in command
                                    if arg.startswith("--lockfile="))
                    negative = "vulnerable" in lockfile
                    package = {"name": "golang.org/x/net" if negative else "example.invalid/a",
                               "version": "0.58.0" if negative else "1.2.3"}
                    item = {"package": package}
                    if negative:
                        item["vulnerabilities"] = [{"id": security.NEGATIVE_ID}]
                    clean_result = {"source": {"path": lockfile}, "packages": [item]}
                    payload = json.dumps({"results": [clean_result]})
                    if duplicate_osv_results and not negative:
                        vulnerable = {"source": {"path": lockfile}, "packages": [{
                            "package": package, "vulnerabilities": [{"id": "GO-TEST-DUPLICATE"}]}]}
                        payload = '{"results":' + json.dumps([vulnerable]) + \
                                  ',"results":' + json.dumps([clean_result]) + '}'
                    return completed(command, rc=int(negative), stdout=payload)
                if executable == str(tools / "govulncheck"):
                    return completed(command, rc=govuln_rc, stdout=govuln_stream)
                if executable == str(tools / "gosec"):
                    external = cwd == root / "examples/external-adapter"
                    issues = [{"rule_id": "GTEST"}] if gosec_findings and not external else []
                    return completed(command, rc=int(bool(issues)), stdout=json.dumps({
                        "GosecVersion": "2.29.0", "Issues": issues,
                        "Stats": {"files": 1, "lines": 1, "found": len(issues),
                                  "nosec": 0 if external else 3}}))
                if executable == str(tools / "gitleaks"):
                    return completed(command, stdout="[]", stderr="scanned ~1 bytes")
                raise AssertionError("unexpected external call: " + repr(command))

            args = ["security.py", "--go", str(go), "--tools", str(tools),
                    "--osv-cache", str(cache), "--report-dir", str(report),
                    "--allow-online-go-db"]
            output = io.StringIO()
            with mock.patch.object(security, "ROOT", root), \
                    mock.patch.object(security, "TOOL_HASHES", tool_hashes), \
                    mock.patch.object(security, "run", side_effect=fake_run), \
                    mock.patch.object(sys, "argv", args), redirect_stdout(output):
                exit_code = security.main()
            summary = json.loads(output.getvalue())
            self.assertEqual(json.loads((report / "summary.json").read_text()), summary)
            return exit_code, summary

    def test_main_json_reachable_stdlib_finding_fails_despite_zero_scanner_exit(self):
        exit_code, summary = self.run_mocked_main(self.mock_govuln_stream(("symbol",)))
        self.assertEqual((exit_code, summary["status"]), (1, "FAIL"))
        self.assertEqual(summary["checks"]["govulncheck"]["status"], "FAIL")
        self.assertEqual(summary["checks"]["govulncheck"]["advisories"]["symbol"],
                         ["GO-TEST-SYMBOL"])
        self.assertEqual(set(summary["checks"]), security.REQUIRED_CHECKS)

    def test_main_json_clean_report_passes_and_all_scanners_aggregate(self):
        exit_code, summary = self.run_mocked_main(self.mock_govuln_stream())
        self.assertEqual((exit_code, summary["status"]), (0, "PASS"))
        self.assertEqual(set(summary["checks"]), security.REQUIRED_CHECKS)
        self.assertTrue(all(check["status"] == "PASS" for check in summary["checks"].values()))
        exit_code, summary = self.run_mocked_main(self.mock_govuln_stream(), gosec_findings=True)
        self.assertEqual((exit_code, summary["status"]), (1, "FAIL"))
        self.assertEqual(summary["checks"]["govulncheck"]["status"], "PASS")
        self.assertEqual(summary["checks"]["gosec"]["status"], "FAIL")

    def test_main_module_and_package_advisories_block_for_review(self):
        for levels in (("module",), ("package",), ("module", "package")):
            with self.subTest(levels=levels):
                exit_code, summary = self.run_mocked_main(self.mock_govuln_stream(levels))
                self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
                check = summary["checks"]["govulncheck"]
                self.assertEqual(check["status"], "BLOCKED")
                self.assertEqual(check["advisories"]["symbol"], [])
                self.assertIn("module_or_package_advisory_requires_review", check["blocking_reasons"])
        exit_code, summary = self.run_mocked_main(
            self.mock_govuln_stream(("module",)), gosec_findings=True)
        self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
        self.assertEqual(summary["checks"]["gosec"]["status"], "FAIL")

    def test_main_malformed_missing_metadata_and_incomplete_results_block(self):
        malformed = "{not-json\n"
        missing = self.mock_govuln_stream(mutate=lambda items: items[0]["config"].pop("protocol_version"))
        invalid_timestamp = self.mock_govuln_stream(mutate=lambda items: items[0]["config"].update(
            db_last_modified="not-a-date"))
        unsupported_protocol = self.mock_govuln_stream(mutate=lambda items: items[0]["config"].update(
            protocol_version="v9"))
        incomplete = self.mock_govuln_stream(mutate=lambda items: items.pop())
        missing_root = self.mock_govuln_stream(mutate=lambda items: items[1]["SBOM"].update(
            roots=["github.com/Animus-OSC/argus-open/cmd/argus"]))
        duplicate_module = self.mock_govuln_stream(mutate=lambda items: items[1]["SBOM"]["modules"].append(
            {"path": "stdlib", "version": "v1.26.10"}))
        unsupported = self.mock_govuln_stream() + '{"complete":true}\n'
        duplicate_key = '{"config":{"protocol_version":"v1.0.0","protocol_version":"v1.0.0"}}\n'
        for stream in (malformed, missing, invalid_timestamp, unsupported_protocol,
                       incomplete, missing_root, duplicate_module, unsupported, duplicate_key):
            with self.subTest(stream=stream[:60]):
                exit_code, summary = self.run_mocked_main(stream)
                self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
                self.assertIn("error", summary)

    def test_main_nonfinite_json_metadata_blocks(self):
        # These values are in ignored metadata: Python's default JSONDecoder
        # would accept them and the otherwise clean gate would report PASS.
        for value in (float("nan"), float("inf"), float("-inf")):
            stream = self.mock_govuln_stream(mutate=lambda items: items[0]["config"].update(
                ignored_number=value))
            with self.subTest(value=value):
                exit_code, summary = self.run_mocked_main(stream)
                self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
                self.assertIn("non-finite number", summary["error"])

    def test_main_duplicate_osv_results_block(self):
        # A permissive parser would retain the final clean results and PASS.
        exit_code, summary = self.run_mocked_main(
            self.mock_govuln_stream(), duplicate_osv_results=True)
        self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
        self.assertIn("duplicate key: results", summary["error"])

    def test_main_future_go_database_timestamp_blocks(self):
        future = (datetime.datetime.now(datetime.timezone.utc) +
                  datetime.timedelta(days=1)).isoformat()
        stream = self.mock_govuln_stream(mutate=lambda items: items[0]["config"].update(
            db_last_modified=future))
        exit_code, summary = self.run_mocked_main(stream)
        self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
        self.assertIn("timestamp is in the future", summary["error"])

    def test_main_scanner_execution_error_blocks(self):
        for rc in (1, 3):
            with self.subTest(returncode=rc):
                exit_code, summary = self.run_mocked_main(self.mock_govuln_stream(), govuln_rc=rc)
                self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
                self.assertIn("did not complete successfully", summary["error"])
        exit_code, summary = self.run_mocked_main(self.mock_govuln_stream(), go_list_rc=1)
        self.assertEqual((exit_code, summary["status"]), (2, "BLOCKED"))
        self.assertIn("enumerate all source and test roots", summary["error"])


if __name__ == "__main__":
    unittest.main()
