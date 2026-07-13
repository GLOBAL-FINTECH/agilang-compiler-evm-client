#!/usr/bin/env python3
"""Portable AGILANG compile and exact-runtime verification HTTP service."""
import hashlib, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor"))
from agilang.agilang_contract_compiler import COMPILER_VERSION, compile_agilang_contract

MANIFEST = json.loads((Path(__file__).parent / "manifest.json").read_text(encoding="utf-8"))
MAX_BODY = 2 * 1024 * 1024

def code_hash(code: str) -> str:
    return hashlib.sha256(bytes.fromhex(str(code).removeprefix("0x"))).hexdigest()

class Handler(BaseHTTPRequestHandler):
    server_version = "AGILANGCompiler/0.5.0"
    def reply(self, status, value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size < 1 or size > MAX_BODY: raise ValueError("invalid_body_size")
        return json.loads(self.rfile.read(size))
    def do_GET(self):
        if self.path == "/health": return self.reply(200, {"ok": True, "compilerVersion": COMPILER_VERSION})
        if self.path == "/v1/manifest": return self.reply(200, MANIFEST)
        return self.reply(404, {"ok": False, "error": "not_found"})
    def do_POST(self):
        try:
            data = self.body()
            if self.path == "/v1/compile":
                compiled = compile_agilang_contract(str(data.get("sourceCode", "")), chain_id=int(data.get("chainId", 1)))
                return self.reply(200, {"ok": True, "compilerVersion": COMPILER_VERSION, "result": compiled})
            if self.path == "/api/contracts/verify":
                compiled = compile_agilang_contract(str(data.get("sourceCode", "")), chain_id=int(data.get("chainId", 1)))
                expected = str(compiled["runtimeBytecode"]).lower()
                submitted = str(data.get("runtimeBytecode", "")).lower()
                observed = str(data.get("observedCode", "")).lower()
                verified = expected == submitted == observed
                reason = "exact_runtime_match" if verified else "runtime_bytecode_mismatch"
                return self.reply(200, {"ok": True, "verified": verified, "reason": reason,
                    "compilerVersion": COMPILER_VERSION, "verificationType": "exact-runtime",
                    "verificationSource": "reproducible_agilang_compiler", "expectedCodeHash": code_hash(expected),
                    "observedCodeHash": code_hash(observed) if observed.startswith("0x") else ""})
            return self.reply(404, {"ok": False, "error": "not_found"})
        except Exception as exc:
            return self.reply(422, {"ok": False, "error": type(exc).__name__, "detail": str(exc)})

if __name__ == "__main__":
    ThreadingHTTPServer((os.getenv("AGILANG_COMPILER_HOST", "127.0.0.1"), int(os.getenv("AGILANG_COMPILER_PORT", "8090"))), Handler).serve_forever()
