#!/usr/bin/env python3
"""Explicit security gate for this Go module; see docs/SECURITY-CHECKS.md.

OSV, SAST and secret scanning run in a network namespace. The separate Go
vulnerability DB query is performed only with --allow-online-go-db.
"""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
TOOL_HASHES = {
    "osv-scanner": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
    "gosec": "ffcab3fa1ae4c9909890bc9e12324926d71edc57e94e663deb989f2a866c13f2",
    "gitleaks": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
}
GO_DB = "https://vuln.go.dev"
NEGATIVE_ID = "GO-2026-6617"
REQUIRED_CHECKS = frozenset({"osv", "osv_negative_control", "govulncheck", "gosec",
                             "gosec_external_example", "gitleaks"})


class GateError(Exception):
    pass


def reject_nonfinite(value):
    raise GateError("scanner JSON contains a non-finite number: " + value)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateError("scanner JSON contains a duplicate key: " + key)
        result[key] = value
    return result


def strict_json_loads(data):
    return json.loads(data, object_pairs_hook=reject_duplicate_keys,
                      parse_constant=reject_nonfinite)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_age(mtime, now):
    # This checks the local file timestamp, not upstream publication time or
    # database authenticity; those limitations are explicit in the runbook.
    if mtime > now + 60 or now - mtime > 24 * 60 * 60:
        raise GateError("OSV Go snapshot timestamp is stale or in the future")


def parse_stream(data):
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicate_keys,
                               parse_constant=reject_nonfinite)
    out, pos = [], 0
    while pos < len(data):
        while pos < len(data) and data[pos].isspace():
            pos += 1
        if pos == len(data):
            break
        item, pos = decoder.raw_decode(data, pos)
        if not isinstance(item, dict) or len(item) != 1 or \
                next(iter(item)) not in ("config", "progress", "SBOM", "osv", "finding") or \
                not isinstance(next(iter(item.values())), dict):
            raise GateError("govulncheck JSON has an unsupported message")
        out.append(item)
    return out


def osv_result(data, expected, source):
    doc = strict_json_loads(data)
    results = doc.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise GateError("OSV did not report exactly one manifest")
    result = results[0]
    if Path(result.get("source", {}).get("path", "")).resolve() != source.resolve():
        raise GateError("OSV reported a different manifest")
    packages = result.get("packages")
    if not isinstance(packages, list) or not packages:
        raise GateError("OSV reported no packages")
    seen, ids = {}, set()
    for item in packages:
        p = item.get("package", {})
        name, version = p.get("name"), p.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or name in seen:
            raise GateError("OSV package data is incomplete or duplicated")
        seen[name] = version.removeprefix("v")
        for v in item.get("vulnerabilities", []):
            if not isinstance(v.get("id"), str):
                raise GateError("OSV vulnerability lacks identity")
            ids.add(v["id"])
    if seen != {name: version.removeprefix("v") for name, version in expected.items()}:
        raise GateError("OSV packages differ from the complete go.mod requirements")
    return ids, len(seen)


def govuln_result(data, expected, expected_roots):
    items = parse_stream(data)
    if not items or "config" not in items[0]:
        raise GateError("govulncheck JSON lacks its first config message")
    configs = [x["config"] for x in items if "config" in x]
    sboms = [x["SBOM"] for x in items if "SBOM" in x]
    if len(configs) != 1 or configs[0].get("protocol_version") != "v1.0.0" or \
            configs[0].get("scanner_name") != "govulncheck" or \
            configs[0].get("scanner_version") != "v1.9.0" or \
            configs[0].get("db") != GO_DB or configs[0].get("go_version") != "go1.26.10" or \
            configs[0].get("scan_level") != "symbol" or configs[0].get("scan_mode") != "source" or \
            len(sboms) != 1:
        raise GateError("govulncheck did not report the expected database, toolchain and source scan")
    modified = configs[0].get("db_last_modified")
    if not isinstance(modified, str):
        raise GateError("govulncheck database timestamp is missing or malformed")
    try:
        parsed = datetime.datetime.fromisoformat(modified.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError("govulncheck database timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise GateError("govulncheck database timestamp lacks a timezone")
    if parsed > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60):
        raise GateError("govulncheck database timestamp is in the future")
    sbom = sboms[0]
    modules, roots = sbom.get("modules"), sbom.get("roots")
    if not isinstance(modules, list) or not modules or not isinstance(roots, list) or \
            not roots or any(not isinstance(root, str) or not root for root in roots):
        raise GateError("govulncheck SBOM is missing modules or source roots")
    graph = {}
    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("path"), str) or \
                not module["path"] or module["path"] in graph or \
                ("version" in module and not isinstance(module["version"], str)):
            raise GateError("govulncheck SBOM has malformed or duplicate modules")
        graph[module["path"]] = module.get("version")
    actual = {k: v for k, v in graph.items() if k not in ("stdlib", "github.com/Animus-OSC/argus-open")}
    if sbom.get("go_version") != "go1.26.10" or graph.get("stdlib") != "v1.26.10" or \
            "github.com/Animus-OSC/argus-open" not in graph or actual != expected or \
            Counter(roots) != Counter(expected_roots):
        raise GateError("govulncheck reported an incomplete module graph, standard library or source roots")
    advisory_ids = set()
    for item in items:
        if "osv" in item:
            advisory = item["osv"]
            if not isinstance(advisory.get("id"), str) or not advisory["id"]:
                raise GateError("govulncheck OSV advisory identity is malformed")
            advisory_ids.add(advisory["id"])
        if "progress" in item and ("message" in item["progress"] and
                                   not isinstance(item["progress"]["message"], str)):
            raise GateError("govulncheck progress metadata is malformed")
    levels = {"symbol": set(), "package": set(), "module": set()}
    finding_count = 0
    for item in items:
        if "finding" not in item:
            continue
        finding = item["finding"]
        identity, trace = finding.get("osv"), finding.get("trace")
        if not isinstance(identity, str) or identity not in advisory_ids or \
                not isinstance(trace, list) or not trace:
            raise GateError("govulncheck finding lacks an advisory or trace")
        for frame in trace:
            if not isinstance(frame, dict) or not isinstance(frame.get("module"), str) or \
                    frame["module"] not in graph or \
                    ("package" in frame and not isinstance(frame["package"], str)) or \
                    ("function" in frame and not isinstance(frame["function"], str)) or \
                    ("receiver" in frame and not isinstance(frame["receiver"], str)):
                raise GateError("govulncheck finding trace is malformed")
        first = trace[0]
        if first.get("function"):
            if not first.get("package"):
                raise GateError("govulncheck symbol finding lacks a package")
            level = "symbol"
        elif first.get("package"):
            level = "package"
        else:
            level = "module"
        levels[level].add(identity)
        finding_count += 1
    return configs[0], {"findings": finding_count,
                        "advisories": {level: sorted(ids) for level, ids in levels.items()}}


def run(command, env, offline=True, cwd=ROOT):
    if offline:
        command = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--"] + command
    try:
        return subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError("required scanner or isolation unavailable") from exc


def git_status(env, cwd=ROOT):
    # Ignored source can still be compiled by Go or used by an embed directive.
    return run(["/usr/bin/git", "status", "--porcelain=v1", "-uall", "--ignored=matching"], env, cwd=cwd)


def report_path(path, root=ROOT):
    # Resolve symlinked ancestors before deciding whether the report is outside.
    report = Path(path).resolve(strict=False)
    root = root.resolve(strict=True)
    if root == report or root in report.parents:
        raise GateError("report directory must be outside the checkout")
    return report


def aggregate_status(checks):
    if set(checks) != REQUIRED_CHECKS or any(
            result.get("status") not in ("PASS", "FAIL", "BLOCKED") for result in checks.values()):
        return "BLOCKED"
    if any(result["status"] == "BLOCKED" for result in checks.values()):
        return "BLOCKED"
    if any(result["status"] == "FAIL" for result in checks.values()):
        return "FAIL"
    return "PASS"


def go_source_roots(output):
    # govulncheck -test uses go/packages, which obtains these roots from
    # `go list -deps -test`. Its PkgPath strips the bracketed test variant.
    roots = [line.split(" [", 1)[0] for line in output.splitlines() if line.strip()]
    if not roots or any(not root.startswith("github.com/Animus-OSC/argus-open/") for root in roots):
        raise GateError("pinned Go returned invalid source roots")
    return roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, help="absolute path to Go 1.26.10")
    parser.add_argument("--tools", required=True, help="directory containing the pinned tools")
    parser.add_argument("--osv-cache", required=True, help="directory holding the local OSV database")
    parser.add_argument("--report-dir", required=True, help="new private directory outside the checkout")
    parser.add_argument("--allow-online-go-db", action="store_true", help="explicitly query https://vuln.go.dev")
    parser.add_argument("--allow-dirty", action="store_true", help="development only; never exact-SHA evidence")
    args = parser.parse_args()
    os.umask(0o077)
    summary = {"version": "argus.security-report/v1", "status": "BLOCKED", "checks": {}}
    try:
        go = Path(args.go).resolve(strict=True)
        tools = Path(args.tools).resolve(strict=True)
        cache = Path(args.osv_cache).resolve(strict=True)
        report = report_path(args.report_dir)
        report.mkdir(mode=0o700, parents=False, exist_ok=False)
        summary_path = report / "summary.json"
        if not args.allow_online_go_db:
            raise GateError("Go vulnerability database network access was not explicitly enabled")
        db = cache / "osv-scalibr" / "Go" / "all.zip"
        validate_age(db.stat().st_mtime, time.time())
        summary["osv_snapshot"] = {"sha256": digest(db), "mtime_utc": datetime.datetime.fromtimestamp(
            db.stat().st_mtime, datetime.timezone.utc).isoformat(), "freshness_policy_hours": 24}
        hashes = {}
        for name, expected in TOOL_HASHES.items():
            hashes[name] = digest(tools / name)
            if hashes[name] != expected:
                raise GateError("pinned scanner binary hash mismatch: " + name)
        hashes["govulncheck"] = digest(tools / "govulncheck")
        summary["tool_sha256"] = hashes
        if (ROOT / ".gitleaks.toml").exists() or (ROOT / ".gitleaksignore").exists():
            raise GateError("local secret-scanner configuration requires explicit review")

        with tempfile.TemporaryDirectory(prefix="argus-security-") as temp:
            temp_path = Path(temp)
            (temp_path / "osv-empty.toml").write_text("", encoding="utf-8")
            env = {"PATH": str(go.parent) + ":/usr/bin:/bin", "HOME": temp, "TMPDIR": temp,
                   "GOCACHE": str(temp_path / "gocache"), "GOMODCACHE": str(temp_path / "modcache"),
                   "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "-mod=vendor",
                   "GOMAXPROCS": "2", "GOTELEMETRY": "off", "LANG": "C", "LC_ALL": "C",
                   "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache)}
            git = run(["/usr/bin/git", "rev-parse", "HEAD"], env)
            state = git_status(env)
            if git.returncode or state.returncode or len(git.stdout.strip()) != 40:
                raise GateError("source revision unavailable")
            summary["source_sha"] = git.stdout.strip()
            summary["dirty"] = bool(state.stdout)
            if summary["dirty"] and not args.allow_dirty:
                raise GateError("dirty or ignored files cannot be used for exact-SHA security evidence")
            goversion = run([str(go), "version"], env)
            metadata = run([str(go), "version", "-m", str(tools / "govulncheck")], env)
            if goversion.returncode or "go1.26.10 " not in goversion.stdout or metadata.returncode or \
                    "golang.org/x/vuln\tv1.9.0\t" not in metadata.stdout:
                raise GateError("Go or govulncheck version mismatch")
            mod = run([str(go), "mod", "edit", "-json"], env)
            if mod.returncode:
                raise GateError("cannot parse go.mod")
            moddoc = strict_json_loads(mod.stdout)
            if moddoc.get("Replace") or moddoc.get("Exclude") or not moddoc.get("Require"):
                raise GateError("go.mod replacements, exclusions or an empty graph require review")
            expected = {x["Path"]: x["Version"] for x in moddoc["Require"]}
            if len(expected) != len(moddoc["Require"]):
                raise GateError("duplicate module requirement")
            listed = run([str(go), "list", "-deps", "-test", "-buildvcs=false", "-f",
                          "{{if not .DepOnly}}{{.ImportPath}}{{end}}", "./..."], env)
            if listed.returncode:
                raise GateError("pinned Go could not enumerate all source and test roots")
            expected_roots = go_source_roots(listed.stdout)

            osv_base = [str(tools / "osv-scanner"), "scan", "source", "--offline", "--all-packages", "--all-vulns",
                        "--no-call-analysis=go", "--config=" + str(temp_path / "osv-empty.toml"), "--format=json"]
            for label, manifest, graph in (
                ("osv", ROOT / "go.mod", expected),
                ("osv_negative_control", ROOT / "testdata/security/vulnerable/go.mod", {"golang.org/x/net": "v0.58.0"}),
            ):
                result = run(osv_base + ["--lockfile=" + str(manifest)], env)
                (report / (label + ".json")).write_text(result.stdout, encoding="utf-8")
                ids, count = osv_result(result.stdout, graph, manifest)
                if label == "osv_negative_control":
                    if result.returncode != 1 or NEGATIVE_ID not in ids:
                        raise GateError("OSV negative control did not detect its known vulnerability")
                    summary["checks"][label] = {"status": "PASS", "detected": NEGATIVE_ID}
                else:
                    if result.returncode not in (0, 1) or bool(ids) != (result.returncode == 1):
                        raise GateError("OSV returned inconsistent results")
                    summary["checks"][label] = {"status": "FAIL" if ids else "PASS", "packages": count,
                                                 "advisories": sorted(ids)}

            vuln = run([str(tools / "govulncheck"), "-json", "-test", "-db", GO_DB, "./..."], env, offline=False)
            (report / "govulncheck.json").write_text(vuln.stdout, encoding="utf-8")
            config, result = govuln_result(vuln.stdout, expected, expected_roots)
            if vuln.returncode != 0:
                raise GateError("govulncheck JSON scan did not complete successfully")
            advisories = result["advisories"]
            reachable = bool(advisories["symbol"])
            other = bool(advisories["package"] or advisories["module"])
            reasons = []
            if reachable:
                reasons.append("reachable_symbol_finding")
            if other:
                reasons.append("module_or_package_advisory_requires_review")
            summary["checks"]["govulncheck"] = {
                "status": "FAIL" if reachable else "BLOCKED" if other else "PASS",
                "findings": result["findings"], "advisories": advisories,
                "blocking_reasons": reasons, "db_last_modified": config["db_last_modified"]}

            sast_args = [str(tools / "gosec"), "-fmt=json", "-concurrency=2",
                         "-nosec-require-justification", "-nosec-require-rules"]
            for label, cwd, scan_env, extra, exceptions in (
                ("gosec", ROOT, env, ["-exclude-dir=examples/external-adapter"], 2),
                ("gosec_external_example", ROOT / "examples/external-adapter",
                 dict(env, GOFLAGS="-mod=mod"), [], 0),
            ):
                sast = run(sast_args + extra + ["./..."], scan_env, cwd=cwd)
                (report / (label + ".json")).write_text(sast.stdout, encoding="utf-8")
                data = strict_json_loads(sast.stdout)
                stats, issues = data.get("Stats", {}), data.get("Issues", [])
                if data.get("GosecVersion") != "2.29.0" or data.get("Golang errors") or not stats.get("files") or \
                        not stats.get("lines") or stats.get("found") != len(issues) or \
                        stats.get("nosec") != exceptions or sast.returncode not in (0, 1) or \
                        bool(issues) != (sast.returncode == 1):
                    raise GateError("gosec result, coverage or exception count is inconsistent")
                summary["checks"][label] = {"status": "FAIL" if issues else "PASS", "files": stats["files"],
                                             "findings": len(issues), "scoped_suppressions": stats["nosec"]}

            secrets = run([str(tools / "gitleaks"), "dir", "--no-banner", "--no-color", "--redact=100",
                           "--ignore-gitleaks-allow", "--report-format=json", "--report-path=-", str(ROOT)], env)
            (report / "gitleaks-redacted.json").write_text(secrets.stdout, encoding="utf-8")
            leaks = strict_json_loads(secrets.stdout)
            scanned = re.search(r"scanned ~([0-9]+) bytes", secrets.stderr)
            if not isinstance(leaks, list) or not scanned or int(scanned.group(1)) < 1 or \
                    secrets.returncode not in (0, 1) or bool(leaks) != (secrets.returncode == 1):
                raise GateError("secret scanner result is incomplete or inconsistent")
            summary["checks"]["gitleaks"] = {"status": "FAIL" if leaks else "PASS", "findings": len(leaks),
                                             "scanned_bytes_approx": int(scanned.group(1))}
            after = run(["/usr/bin/git", "rev-parse", "HEAD"], env)
            after_state = git_status(env)
            if after.returncode or after.stdout != git.stdout or after_state.returncode or after_state.stdout != state.stdout:
                raise GateError("source changed during security scan")
            summary["status"] = aggregate_status(summary["checks"])
    except (GateError, OSError, ValueError, KeyError, TypeError, AttributeError,
            IndexError, json.JSONDecodeError) as exc:
        summary["error"] = str(exc)
    summary["completed_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if "summary_path" in locals():
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[summary["status"]]


if __name__ == "__main__":
    sys.exit(main())
