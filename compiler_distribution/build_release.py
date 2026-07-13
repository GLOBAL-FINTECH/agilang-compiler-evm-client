#!/usr/bin/env python3
import json, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = Path(__file__).parent
MANIFEST = json.loads((DIST / "manifest.json").read_text(encoding="utf-8"))
OUTPUT = DIST / "dist" / "agilang-native-evm-0.5.0.zip"

def main() -> None:
    OUTPUT.parent.mkdir(exist_ok=True)
    paths = [entry["path"] for entry in MANIFEST["files"]] + [
        "compiler_distribution/manifest.json",
        "compiler_distribution/verify_install.py",
        "compiler_distribution/compiler_service.py",
        "compiler_distribution/Dockerfile",
        "compiler_distribution/requirements.txt",
    ]
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(paths):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (ROOT / name).read_bytes())
    print(OUTPUT)

if __name__ == "__main__":
    main()
