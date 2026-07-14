#!/usr/bin/env python3
"""Verify every content-addressed file in the AGILANG compiler manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((Path(__file__).resolve().parent / "manifest.json").read_text(encoding="utf-8"))


def main() -> int:
    failed = False
    seen: set[str] = set()

    for entry in MANIFEST.get("files", []):
        name = entry.get("path")
        if not isinstance(name, str) or name in seen:
            print(f"FAIL invalid-or-duplicate-path {name!r}")
            failed = True
            continue
        seen.add(name)

        path = (ROOT / name).resolve()
        try:
            path.relative_to(ROOT)
        except ValueError:
            print(f"FAIL path-escape {name}")
            failed = True
            continue

        if not path.is_file():
            print(f"FAIL {name} missing")
            failed = True
            continue

        payload = path.read_bytes()
        actual_hash = hashlib.sha256(payload).hexdigest()
        expected_hash = entry.get("sha256")
        expected_size = entry.get("bytes")
        ok = actual_hash == expected_hash and len(payload) == expected_size
        print(("OK   " if ok else "FAIL ") + name + " " + actual_hash)
        failed = failed or not ok

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
