#!/usr/bin/env python3
"""Build a deterministic AGILANG compiler release archive."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = Path(__file__).resolve().parent
MANIFEST = json.loads((DIST / "manifest.json").read_text(encoding="utf-8"))
OUTPUT = DIST / "dist" / "agilang-native-evm-0.5.0.zip"


def _release_paths() -> list[str]:
    names = [entry["path"] for entry in MANIFEST.get("files", [])]
    names.append("compiler_distribution/manifest.json")

    if len(names) != len(set(names)):
        raise RuntimeError("manifest contains duplicate release paths")

    validated: list[str] = []
    for name in names:
        candidate = (ROOT / name).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError as exc:
            raise RuntimeError(f"release path escapes repository root: {name}") from exc
        if not candidate.is_file():
            raise RuntimeError(f"release file is missing: {name}")
        validated.append(name)
    return sorted(validated)


def main() -> None:
    OUTPUT.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(
        OUTPUT,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in _release_paths():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (ROOT / name).read_bytes())
    print(OUTPUT)


if __name__ == "__main__":
    main()
