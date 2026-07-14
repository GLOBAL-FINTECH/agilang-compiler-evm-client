#!/usr/bin/env python3
"""Hardened AGILANG compile and on-chain exact-runtime verification service."""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor"))

from agilang.agilang_contract_compiler import (  # noqa: E402
    AgilangContractCompileError,
    COMPILER_VERSION,
    compile_agilang_contract,
)

DIST = Path(__file__).resolve().parent
MANIFEST_PATH = DIST / "manifest.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


MAX_BODY = _env_int("AGILANG_MAX_BODY_BYTES", 256 * 1024, 1_024, 2 * 1024 * 1024)
MAX_SOURCE = _env_int("AGILANG_MAX_SOURCE_BYTES", 128 * 1024, 256, MAX_BODY)
MAX_CONNECTIONS = _env_int("AGILANG_MAX_CONNECTIONS", 32, 1, 256)
MAX_COMPILATIONS = _env_int("AGILANG_MAX_CONCURRENT_COMPILATIONS", 2, 1, 32)
SOCKET_TIMEOUT = _env_int("AGILANG_SOCKET_TIMEOUT_SECONDS", 10, 1, 120)
RPC_TIMEOUT = _env_int("AGILANG_RPC_TIMEOUT_SECONDS", 5, 1, 60)
VERIFICATION_RPC_URL = os.getenv("AGILANG_VERIFICATION_RPC_URL", "").strip()
VERIFICATION_CHAIN_ID = os.getenv("AGILANG_VERIFICATION_CHAIN_ID", "").strip()

_COMPILE_SLOTS = threading.BoundedSemaphore(MAX_COMPILATIONS)


class RequestError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def _manifest_integrity() -> tuple[bool, list[str]]:
    errors: list[str] = []
    for entry in MANIFEST.get("files", []):
        relative = entry.get("path")
        if not isinstance(relative, str):
            errors.append("invalid_manifest_path")
            continue
        candidate = (ROOT / relative).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            errors.append(f"path_escape:{relative}")
            continue
        if not candidate.is_file():
            errors.append(f"missing:{relative}")
            continue
        payload = candidate.read_bytes()
        if len(payload) != entry.get("bytes"):
            errors.append(f"size_mismatch:{relative}")
        if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
            errors.append(f"hash_mismatch:{relative}")
    return not errors, errors


INTEGRITY_OK, INTEGRITY_ERRORS = _manifest_integrity()


def _parse_chain_id(value: Any) -> int:
    if isinstance(value, bool):
        raise RequestError(422, "invalid_chain_id")
    try:
        if isinstance(value, int):
            chain_id = value
        elif isinstance(value, str):
            chain_id = int(value, 16 if value.lower().startswith("0x") else 10)
        else:
            raise ValueError
    except (TypeError, ValueError):
        raise RequestError(422, "invalid_chain_id") from None
    if chain_id <= 0 or chain_id > (2**64 - 1):
        raise RequestError(422, "invalid_chain_id")
    return chain_id


def _validate_source(value: Any) -> str:
    if not isinstance(value, str):
        raise RequestError(422, "source_code_must_be_string")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > MAX_SOURCE:
        raise RequestError(413, "source_code_size_invalid")
    return value


def _normalize_code(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        raise RequestError(422, f"invalid_{field}")
    return "0x" + bytes.fromhex(value[2:]).hex()


def _code_hash(code: str) -> str:
    return hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()


def _configured_chain_id() -> int | None:
    if not VERIFICATION_CHAIN_ID:
        return None
    return _parse_chain_id(VERIFICATION_CHAIN_ID)


def _rpc_call(method: str, params: list[Any]) -> Any:
    if not VERIFICATION_RPC_URL:
        raise RequestError(503, "verification_rpc_not_configured")
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        VERIFICATION_RPC_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AGILANGVerifier/0.5.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=RPC_TIMEOUT) as response:
            if response.status != 200:
                raise RequestError(502, "verification_rpc_http_error")
            raw = response.read(512 * 1024 + 1)
    except RequestError:
        raise
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        raise RequestError(502, "verification_rpc_unavailable") from None
    if len(raw) > 512 * 1024:
        raise RequestError(502, "verification_rpc_response_too_large")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        raise RequestError(502, "verification_rpc_invalid_json") from None
    if not isinstance(decoded, dict) or decoded.get("error") is not None or "result" not in decoded:
        raise RequestError(502, "verification_rpc_error")
    return decoded["result"]


def _compile(source: str, chain_id: int) -> dict[str, Any]:
    if not INTEGRITY_OK:
        raise RequestError(503, "compiler_integrity_failed")
    if not _COMPILE_SLOTS.acquire(blocking=False):
        raise RequestError(429, "compiler_busy")
    try:
        return compile_agilang_contract(source, chain_id=chain_id)
    except AgilangContractCompileError:
        raise RequestError(422, "compile_error") from None
    except (TypeError, ValueError, OverflowError):
        raise RequestError(422, "compile_error") from None
    finally:
        _COMPILE_SLOTS.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "AGILANGCompiler"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT)

    def version_string(self) -> str:
        return "AGILANGCompiler"

    def log_message(self, format: str, *args: Any) -> None:
        # Never log request bodies or contract source.
        sys.stderr.write(
            '%s - - [%s] %s\n'
            % (self.address_string(), self.log_date_time_string(), format % args)
        )

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def reply(self, status: int, value: dict[str, Any]) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(raw)

    def body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(400, "transfer_encoding_not_supported")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "content_type_must_be_application_json")
        raw_size = self.headers.get("Content-Length")
        if raw_size is None:
            raise RequestError(411, "content_length_required")
        try:
            size = int(raw_size)
        except ValueError:
            raise RequestError(400, "invalid_content_length") from None
        if size < 1 or size > MAX_BODY:
            raise RequestError(413, "invalid_body_size")
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise RequestError(400, "incomplete_body")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise RequestError(400, "invalid_json") from None
        if not isinstance(data, dict):
            raise RequestError(422, "json_object_required")
        return data

    def do_OPTIONS(self) -> None:
        self.reply(405, {"ok": False, "error": "method_not_allowed"})

    def do_GET(self) -> None:
        if self.path == "/health":
            status = 200 if INTEGRITY_OK else 503
            self.reply(
                status,
                {
                    "ok": INTEGRITY_OK,
                    "compilerVersion": COMPILER_VERSION,
                    "integrityOk": INTEGRITY_OK,
                },
            )
            return
        if self.path == "/v1/manifest":
            self.reply(200, MANIFEST)
            return
        self.reply(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        if self.path not in {"/v1/compile", "/api/contracts/verify"}:
            self.reply(404, {"ok": False, "error": "not_found"})
            return
        try:
            data = self.body()
            source = _validate_source(data.get("sourceCode"))
            chain_id = _parse_chain_id(data.get("chainId", 1))

            if self.path == "/v1/compile":
                compiled = _compile(source, chain_id)
                self.reply(
                    200,
                    {
                        "ok": True,
                        "compilerVersion": COMPILER_VERSION,
                        "result": compiled,
                    },
                )
                return

            address = data.get("contractAddress")
            if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address):
                raise RequestError(422, "invalid_contract_address")
            if address.lower() == "0x" + ("0" * 40):
                raise RequestError(422, "invalid_contract_address")

            configured_chain = _configured_chain_id()
            if configured_chain is not None and chain_id != configured_chain:
                raise RequestError(409, "configured_chain_id_mismatch")

            rpc_chain_raw = _rpc_call("eth_chainId", [])
            rpc_chain_id = _parse_chain_id(rpc_chain_raw)
            if rpc_chain_id != chain_id:
                raise RequestError(409, "rpc_chain_id_mismatch")

            compiled = _compile(source, chain_id)
            expected = _normalize_code(compiled.get("runtimeBytecode"), "compiled_runtime_bytecode")
            observed = _normalize_code(
                _rpc_call("eth_getCode", [address.lower(), "latest"]),
                "observed_runtime_bytecode",
            )
            if observed == "0x":
                self.reply(
                    200,
                    {
                        "ok": True,
                        "verified": False,
                        "reason": "contract_not_deployed",
                        "chainId": chain_id,
                        "contractAddress": address.lower(),
                        "compilerVersion": COMPILER_VERSION,
                        "verificationType": "exact-runtime",
                        "verificationSource": "server_side_eth_getCode",
                        "expectedCodeHash": _code_hash(expected),
                        "observedCodeHash": _code_hash(observed),
                    },
                )
                return

            verified = expected == observed
            self.reply(
                200,
                {
                    "ok": True,
                    "verified": verified,
                    "reason": "exact_runtime_match" if verified else "runtime_bytecode_mismatch",
                    "chainId": chain_id,
                    "contractAddress": address.lower(),
                    "compilerVersion": COMPILER_VERSION,
                    "verificationType": "exact-runtime",
                    "verificationSource": "server_side_eth_getCode",
                    "expectedCodeHash": _code_hash(expected),
                    "observedCodeHash": _code_hash(observed),
                },
            )
        except RequestError as exc:
            self.reply(exc.status, {"ok": False, "error": exc.code})
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return
        except Exception:
            # Do not expose stack traces, filesystem paths, RPC URLs, or source text.
            self.reply(500, {"ok": False, "error": "internal_error"})


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, server_address: tuple[str, int], handler: type[Handler]):
        self._connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(server_address, handler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


def main() -> None:
    host = os.getenv("AGILANG_COMPILER_HOST", "127.0.0.1")
    port = _env_int("AGILANG_COMPILER_PORT", 8090, 1, 65535)
    if not INTEGRITY_OK:
        sys.stderr.write("compiler integrity check failed\n")
    LimitedThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
