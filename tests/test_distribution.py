import hashlib
import json
from pathlib import Path

import pytest

from compiler_distribution import compiler_service as service

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_matches_release_files():
    manifest = json.loads(
        (ROOT / "compiler_distribution/manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["compilerVersion"] == "AGILANG-NATIVE-EVM/0.5.0"
    assert manifest["gatewayVersion"] == "0.9.1"

    seen = set()
    for entry in manifest["files"]:
        assert entry["path"] not in seen
        seen.add(entry["path"])
        path = (ROOT / entry["path"]).resolve()
        path.relative_to(ROOT)
        payload = path.read_bytes()
        assert len(payload) == entry["bytes"]
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"]


def test_verification_uses_server_side_chain_code():
    source = (
        ROOT / "compiler_distribution/compiler_service.py"
    ).read_text(encoding="utf-8")
    assert 'AGILANG_VERIFICATION_RPC_URL' in source
    assert '"eth_chainId"' in source
    assert '"eth_getCode"' in source
    assert 'data.get("observedCode")' not in source
    assert '"server_side_eth_getCode"' in source


def test_request_validation_helpers():
    assert service._parse_chain_id("0x783") == 1923
    assert service._parse_chain_id(1923) == 1923
    assert service._normalize_code("0x00ff", "runtime") == "0x00ff"

    with pytest.raises(service.RequestError):
        service._parse_chain_id(0)

    with pytest.raises(service.RequestError):
        service._normalize_code("not-hex", "runtime")


def test_compiler_service_security_controls_present():
    source = (
        ROOT / "compiler_distribution/compiler_service.py"
    ).read_text(encoding="utf-8")
    assert "MAX_CONCURRENT_COMPILATIONS" in source
    assert "Content-Security-Policy" in source
    assert "content_type_must_be_application_json" in source
    assert "compiler_integrity_failed" in source
    assert '"internal_error"' in source
