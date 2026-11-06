#!/usr/bin/env python3
"""Create the Go module inventory from a pre-populated, offline module cache.

This validates cached module and go.mod content against the committed go.sum.
It does not establish who published those checksums or verify tool signatures.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import quote
import zipfile

ROOT = Path(__file__).resolve().parents[3]


def escape(value):
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in value)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def h1(files):
    # Go's dirhash Hash1: sorted filenames, each file SHA-256, then SHA-256
    # of the canonical lines. ZIP metadata is intentionally not included.
    combined = hashlib.sha256()
    for name, digest in sorted(files):
        if "\n" in name:
            raise ValueError("invalid module filename")
        combined.update((digest + "  " + name + "\n").encode("utf-8"))
    return "h1:" + base64.b64encode(combined.digest()).decode("ascii")


def archive_h1(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 100000 or len({entry.filename for entry in entries}) != len(entries):
            raise ValueError("duplicate or excessive ZIP entries")
        if sum(entry.file_size for entry in entries) > 256 << 20:
            raise ValueError("module archive exceeds size limit")
        files = []
        for entry in entries:
            digest = hashlib.sha256()
            with archive.open(entry) as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            files.append((entry.filename, digest.hexdigest()))
        return h1(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, help="Go 1.26.10 binary")
    parser.add_argument("--module-cache", required=True, help="pre-populated GOMODCACHE")
    parser.add_argument("--output", required=True, help="CycloneDX JSON output")
    args = parser.parse_args()
    go, cache = Path(args.go).resolve(strict=True), Path(args.module_cache).resolve(strict=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GOTOOLCHAIN": "local",
           "GOPROXY": "off", "GOSUMDB": "off", "GOTELEMETRY": "off"}
    version = subprocess.check_output([str(go), "version"], cwd=ROOT, env=env, text=True)
    if "go1.26.10 " not in version:
        raise ValueError("Go 1.26.10 is required for the recorded inventory")
    mod = json.loads(subprocess.check_output([str(go), "mod", "edit", "-json"], cwd=ROOT, env=env, text=True))
    if not mod.get("Require") or mod.get("Replace") or mod.get("Exclude"):
        raise ValueError("empty, replaced or excluded module graph requires review")
    sums = {}
    for line in (ROOT / "go.sum").read_text(encoding="utf-8").splitlines():
        name, release, checksum = line.split()
        key = (name, release)
        if key in sums and sums[key] != checksum:
            raise ValueError("conflicting go.sum entries")
        sums[key] = checksum
    components = []
    for item in mod["Require"]:
        name, release = item["Path"], item["Version"]
        prefix = cache / "cache/download" / escape(name) / "@v" / escape(release)
        zip_path, mod_path = Path(str(prefix) + ".zip"), Path(str(prefix) + ".mod")
        module_h1, mod_h1 = sums[(name, release)], sums[(name, release + "/go.mod")]
        if mod_path.stat().st_size > 1 << 20:
            raise ValueError("go.mod exceeds size limit")
        mod_bytes = mod_path.read_bytes()
        if archive_h1(zip_path) != module_h1 or \
                h1([("go.mod", hashlib.sha256(mod_bytes).hexdigest())]) != mod_h1:
            raise ValueError("module content does not match committed go.sum: " + name)
        purl = "pkg:golang/" + quote(name, safe="/.-_~") + "@" + quote(release, safe=".-_~")
        components.append({"type": "library", "name": name, "version": release, "purl": purl,
                           "bom-ref": purl, "hashes": [{"alg": "SHA-256", "content": sha256_file(zip_path)}],
                           "properties": [{"name": "argus:go-module-content-h1", "value": module_h1},
                                          {"name": "argus:go-mod-h1", "value": mod_h1},
                                          {"name": "argus:source", "value": "pre-existing local module cache"}]})
    components.sort(key=lambda item: item["name"])
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": mod["Module"]["Path"],
                                      "version": "pinned-go-module-requirements"},
                        "properties": [{"name": "argus:go-mod-sha256", "value": sha256_file(ROOT / "go.mod")},
                                       {"name": "argus:go-sum-sha256", "value": sha256_file(ROOT / "go.sum")},
                                       {"name": "argus:vendor-modules-sha256", "value": sha256_file(ROOT / "vendor/modules.txt")},
                                       {"name": "argus:toolchain", "value": "go1.26.10"}]},
           "components": components}
    Path(args.output).write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print("Verified and inventoried", len(components), "pinned Go modules")


if __name__ == "__main__":
    main()
