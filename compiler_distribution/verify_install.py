#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((Path(__file__).parent / "manifest.json").read_text(encoding="utf-8"))

def main() -> int:
    failed = False
    for entry in MANIFEST["files"]:
        path = ROOT / entry["path"]
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
        ok = actual == entry["sha256"] and path.stat().st_size == entry["bytes"] if path.is_file() else False
        print(("OK   " if ok else "FAIL ") + entry["path"] + " " + actual)
        failed = failed or not ok
    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
