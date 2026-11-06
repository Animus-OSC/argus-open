#!/usr/bin/env python3
"""Explicit test-only receipt schema gate; never installs dependencies or uses network."""
import copy
import importlib.metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent


def blocked(reason):
    print(json.dumps({"status": "BLOCKED", "reason": reason}))
    return 2


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate corpus/schema key")
        result[key] = value
    return result


def materialize(corpus, case):
    value = copy.deepcopy(corpus["bases"][case["base"]])
    operation = case["operation"]
    if operation == "none":
        return value
    parent = value
    for key in case["path"][:-1]:
        parent = parent[key]
    key = case["path"][-1]
    if operation == "set":
        parent[key] = copy.deepcopy(case["value"])
    elif operation == "delete":
        del parent[key]
    elif operation == "rename":
        parent[case["rename_to"]] = parent.pop(key)
    else:
        raise ValueError("unsupported corpus mutation")
    return value


def main():
    try:
        import jsonschema
        requirements = (ROOT / "pkg/evidence/schema-requirements.txt").read_text()
        expected = dict(line.split("==", 1) for line in requirements.splitlines()
                        if line and not line.startswith("#"))
        versions = {name: importlib.metadata.version(name) for name in expected}
    except (ImportError, OSError, ValueError, importlib.metadata.PackageNotFoundError):
        return blocked("test-only schema dependencies unavailable; see pkg/evidence/SCHEMA-TESTS.md")
    if versions != expected:
        return blocked("schema tool version mismatch: " + repr(versions))

    checker = jsonschema.FormatChecker()
    if "date-time" not in checker.checkers or checker.conforms("not-a-date", "date-time") or checker.conforms("2026-02-30T00:00:00Z", "date-time"):
        return blocked("active RFC3339 date-time format checker is required")

    try:
        schema = json.loads((ROOT / "schemas/receipt-v1.schema.json").read_text(), object_pairs_hook=unique_object)
        corpus = json.loads((ROOT / "pkg/evidence/testdata/receipt-wire-v1.json").read_text(), object_pairs_hook=unique_object)
        pending = [schema]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if "$ref" in item and not item["$ref"].startswith("#"):
                    return blocked("receipt schema must use local references only")
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
        failures = []
        for case in corpus["cases"]:
            valid = validator.is_valid(materialize(corpus, case))
            if valid != case["schema_valid"]:
                failures.append({"case": case["name"], "accepted": valid, "expected": case["schema_valid"]})
    except (OSError, ValueError, KeyError, jsonschema.exceptions.SchemaError) as exc:
        return blocked("invalid schema/corpus input: " + str(exc))
    report = {
        "status": "FAIL" if failures else "PASS",
        "schema": "schemas/receipt-v1.schema.json",
        "corpus": "pkg/evidence/testdata/receipt-wire-v1.json",
        "cases": len(corpus["cases"]),
        "format_assertions": ["date-time"],
        "tool_versions": versions,
        "failures": failures,
        "scope": "real JSON Schema constraints on shared selected fixtures; Go tests separately enforce canonical digest and cross-field semantics",
    }
    print(json.dumps(report, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
