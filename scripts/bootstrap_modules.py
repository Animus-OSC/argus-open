#!/usr/bin/env python3
"""Initialize only reviewed public modules by default; private modules are explicit."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-private", action="store_true", help="explicitly initialize private modules using your independently configured credentials")
    parser.add_argument("--check", action="store_true", help="verify configuration/gitlinks without network")
    args = parser.parse_args()
    modules = json.loads((ROOT / "modules.lock.json").read_text())["modules"]
    paths = []
    for module in modules:
        path, url = module["path"], module["url"]
        if git("config", "-f", ".gitmodules", "--get", "submodule." + path + ".path") != path:
            raise SystemExit("submodule path mismatch")
        if git("config", "-f", ".gitmodules", "--get", "submodule." + path + ".url") != url:
            raise SystemExit("submodule URL mismatch")
        entry = git("ls-files", "--stage", "--", path).split()
        if len(entry) < 4 or entry[0] != "160000" or entry[1] != module["sha"]:
            raise SystemExit("unpinned or mismatched gitlink: " + path)
        if module["visibility"] == "private":
            if git("config", "-f", ".gitmodules", "--get", "submodule." + path + ".update") != "none":
                raise SystemExit("private module must default to update=none")
            if not args.with_private:
                continue
        paths.append(path)
    if args.check:
        print(json.dumps({"configuration": "PASS", "selected_paths": paths, "private_opt_in": args.with_private}))
        return
    # No recursive private traversal: nested platform extensions have independent ownership.
    subprocess.run(["git", "-C", str(ROOT), "submodule", "update", "--init", "--checkout", "--", *paths], check=True)

if __name__ == "__main__":
    main()
