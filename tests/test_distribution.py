import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_matches_release_files():
    manifest = json.loads((ROOT / "compiler_distribution/manifest.json").read_text(encoding="utf-8"))
    assert manifest["compilerVersion"] == "AGILANG-NATIVE-EVM/0.5.0"
    for entry in manifest["files"]:
        payload = (ROOT / entry["path"]).read_bytes()
        assert len(payload) == entry["bytes"]
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"]


def test_service_has_compile_and_verification_endpoints():
    service = (ROOT / "compiler_distribution/compiler_service.py").read_text(encoding="utf-8")
    assert '"/v1/compile"' in service
    assert '"/api/contracts/verify"' in service
    assert "expected == submitted == observed" in service
