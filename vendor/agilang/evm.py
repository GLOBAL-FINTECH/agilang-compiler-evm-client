"""AGILANG v1.8 production-usable EVM toolkit.

This module moves AGILANG beyond selector/ABI helper stubs.  It provides a
real executable EVM engine for deterministic local execution, application-level
simulation, contract bytecode tests, calldata/ABI workflows, JSON-RPC access,
tracing, and world-state storage.  It is intentionally dependency-light and
safe-by-default.

Scope note: this is an EVM execution toolkit and simulator, not a full Ethereum
node.  It does not implement peer-to-peer sync, consensus validation, fork-choice
rules, block production, or canonical chain storage.  For chain correctness in a
financial production system, pair this module with an audited Ethereum client or
precompiled EVM engine through AGILANG's interop layer.
"""
from __future__ import annotations

import binascii
import copy
import hashlib
import json
import math
import re
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple
from .ethereum_forks import OPCODE_FORK, fork_at_least

try:
    from Crypto.Hash import keccak as _native_keccak  # type: ignore  # nosec B413
except Exception:  # Optional native accelerator may be absent or ABI-incompatible.
    _native_keccak = None

EVM_VERSION = "1.8.0"
WORD_BITS = 256
WORD_MOD = 2 ** WORD_BITS
WORD_MASK = WORD_MOD - 1
ADDRESS_MOD = 2 ** 160
MAX_STACK = 1024
DEFAULT_GAS = 10_000_000
MAX_CALL_DEPTH = 1024

# Opcode table includes recent general-purpose bytecode operations such as PUSH0.
OPCODES: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
    0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "SHA3",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST", 0x5F: "PUSH0",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for i in range(1, 33):
    OPCODES[0x5F + i] = f"PUSH{i}"
for i in range(1, 17):
    OPCODES[0x7F + i] = f"DUP{i}"
    OPCODES[0x8F + i] = f"SWAP{i}"
for i in range(0, 5):
    OPCODES[0xA0 + i] = f"LOG{i}"

NAME_TO_OPCODE = {v: k for k, v in OPCODES.items()}

# Practical gas schedule.  It is deterministic and conservative, but should not
# be treated as a consensus fork schedule for validating mainnet blocks.
GAS_COSTS: dict[str, int] = {
    "STOP": 0, "ADD": 3, "MUL": 5, "SUB": 3, "DIV": 5, "SDIV": 5, "MOD": 5, "SMOD": 5,
    "ADDMOD": 8, "MULMOD": 8, "EXP": 10, "SIGNEXTEND": 5,
    "LT": 3, "GT": 3, "SLT": 3, "SGT": 3, "EQ": 3, "ISZERO": 3, "AND": 3, "OR": 3, "XOR": 3, "NOT": 3, "BYTE": 3, "SHL": 3, "SHR": 3, "SAR": 3,
    "SHA3": 30,
    "ADDRESS": 2, "BALANCE": 100, "ORIGIN": 2, "CALLER": 2, "CALLVALUE": 2, "CALLDATALOAD": 3, "CALLDATASIZE": 2, "CALLDATACOPY": 3, "CODESIZE": 2, "CODECOPY": 3, "GASPRICE": 2, "EXTCODESIZE": 100, "EXTCODECOPY": 100, "RETURNDATASIZE": 2, "RETURNDATACOPY": 3, "EXTCODEHASH": 100,
    "BLOCKHASH": 20, "COINBASE": 2, "TIMESTAMP": 2, "NUMBER": 2, "PREVRANDAO": 2, "DIFFICULTY": 2, "GASLIMIT": 2, "CHAINID": 2, "SELFBALANCE": 5, "BASEFEE": 2, "BLOBHASH": 3, "BLOBBASEFEE": 2,
    "POP": 2, "MLOAD": 3, "MSTORE": 3, "MSTORE8": 3, "SLOAD": 100, "SSTORE": 20_000, "JUMP": 8, "JUMPI": 10, "PC": 2, "MSIZE": 2, "GAS": 2, "JUMPDEST": 1, "PUSH0": 2,
    "CREATE": 32_000, "CALL": 700, "CALLCODE": 700, "RETURN": 0, "DELEGATECALL": 700, "CREATE2": 32_000, "STATICCALL": 700, "REVERT": 0, "INVALID": 0, "SELFDESTRUCT": 5_000,
}
for i in range(1, 33):
    GAS_COSTS[f"PUSH{i}"] = 3
for i in range(1, 17):
    GAS_COSTS[f"DUP{i}"] = 3
    GAS_COSTS[f"SWAP{i}"] = 3
for i in range(0, 5):
    GAS_COSTS[f"LOG{i}"] = 375 + i * 375

# Pure-Python Keccak-256 fallback.  This is the Ethereum legacy Keccak padding
# variant, not NIST SHA3 padding.
_MASK64 = (1 << 64) - 1
_KECCAKF_ROUNDS = 24
_KECCAKF_RNDC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAKF_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_KECCAKF_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]


def _rotl64(x: int, y: int) -> int:
    return ((x << y) | (x >> (64 - y))) & _MASK64


def _keccak_f1600(st: list[int]) -> None:
    bc = [0] * 5
    for rnd in range(_KECCAKF_ROUNDS):
        for i in range(5):
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rotl64(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
                st[j + i] &= _MASK64
        t = st[1]
        for i in range(24):
            j = _KECCAKF_PILN[i]
            bc[0] = st[j]
            st[j] = _rotl64(t, _KECCAKF_ROTC[i])
            t = bc[0]
        for j in range(0, 25, 5):
            row = st[j:j + 5]
            for i in range(5):
                st[j + i] = (row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5])) & _MASK64
        st[0] ^= _KECCAKF_RNDC[rnd]
        st[0] &= _MASK64


def _keccak_256_pure(data: bytes) -> bytes:
    rate = 136
    st = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            st[i] &= _MASK64
        _keccak_f1600(st)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(st[i].to_bytes(8, "little"))
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f1600(st)
    return bytes(out[:32])


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


def _hex(data: bytes | bytearray | int) -> str:
    if isinstance(data, int):
        return "0x" + data.to_bytes(32, "big").hex()
    return "0x" + bytes(data).hex()


def _bytes(value: bytes | bytearray | str | int | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, int):
        if value < 0:
            raise ValueError("cannot convert negative integer to bytes")
        return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    s = str(value).strip()
    if s.startswith(("0x", "0X")):
        h = _strip_0x(s)
        if len(h) % 2:
            h = "0" + h
        return bytes.fromhex(h)
    return s.encode("utf-8")


def _word(value: int) -> int:
    return int(value) & WORD_MASK


def _signed(value: int) -> int:
    value &= WORD_MASK
    return value - WORD_MOD if value >= 2 ** 255 else value


def _unsigned_from_signed(value: int) -> int:
    return value & WORD_MASK


def _ceil32(n: int) -> int:
    return ((int(n) + 31) // 32) * 32


def _normalize_address(value: str | int | bytes | bytearray) -> str:
    if isinstance(value, str):
        s = value.lower()
        if not s.startswith("0x"):
            s = "0x" + s
        h = _strip_0x(s)
        if len(h) > 40:
            h = h[-40:]
        return "0x" + h.rjust(40, "0")
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)[-20:]
        return "0x" + raw.hex().rjust(40, "0")
    return "0x" + (int(value) % ADDRESS_MOD).to_bytes(20, "big").hex()


def evm_keccak(data: bytes | str) -> str:
    raw = _bytes(data)
    if _native_keccak is not None:
        h = _native_keccak.new(digest_bits=256)
        h.update(raw)
        return "0x" + h.hexdigest()
    return "0x" + _keccak_256_pure(raw).hex()


def _evm_keccak_bytes(data: bytes) -> bytes:
    return bytes.fromhex(_strip_0x(evm_keccak(data)))


def evm_has_exact_keccak() -> bool:
    return _native_keccak is not None


def evm_function_selector(signature: str) -> str:
    return "0x" + _strip_0x(evm_keccak(signature))[:8]


def evm_is_address(address: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", address or ""))


def evm_abi_encode_uint256(value: int) -> str:
    if int(value) < 0:
        raise ValueError("uint256 cannot be negative")
    if int(value) >= 2 ** 256:
        raise ValueError("uint256 overflow")
    return f"{int(value):064x}"


def evm_abi_encode_int256(value: int) -> str:
    return f"{int(value) & WORD_MASK:064x}"


def evm_abi_encode_bool(value: bool) -> str:
    return evm_abi_encode_uint256(1 if bool(value) else 0)


def evm_abi_encode_address(address: str) -> str:
    norm = _normalize_address(address)
    if not evm_is_address(norm):
        raise ValueError(f"invalid EVM address: {address}")
    return "0" * 24 + _strip_0x(norm).lower()


def evm_abi_encode_bytes32(value: bytes | str) -> str:
    raw = _bytes(value)
    if len(raw) > 32:
        raise ValueError("bytes32 value is longer than 32 bytes")
    return raw.hex().ljust(64, "0")


def _is_dynamic_type(typ: str) -> bool:
    t = typ.strip().lower()
    return t in {"string", "bytes"} or t.endswith("[]")


def _parse_array_value(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        if s.startswith("["):
            return json.loads(s)
        return [part.strip() for part in s.split("|")]
    raise ValueError("array ABI value must be list, tuple, JSON array, or pipe-separated string")


def _abi_encode_static_no_prefix(typ: str, value: Any) -> str:
    t = typ.strip().lower()
    if t in {"uint", "uint256", "uint64", "uint32", "uint16", "uint8"}:
        return evm_abi_encode_uint256(int(value))
    if t in {"int", "int256", "int64", "int32", "int16", "int8"}:
        return evm_abi_encode_int256(int(value))
    if t == "bool":
        return evm_abi_encode_bool(bool(value))
    if t == "address":
        return evm_abi_encode_address(str(value))
    if t == "bytes32":
        return evm_abi_encode_bytes32(value)
    if re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", t):
        size = int(t[5:])
        raw = _bytes(value)
        if len(raw) != size:
            raise ValueError(f"{t} requires exactly {size} bytes")
        return raw.hex().ljust(64, "0")
    raise NotImplementedError(f"ABI type not implemented: {typ}")


def _abi_encode_dynamic_no_prefix(typ: str, value: Any) -> str:
    t = typ.strip().lower()
    if t == "string":
        raw = str(value).encode("utf-8")
        return evm_abi_encode_uint256(len(raw)) + raw.hex().ljust(_ceil32(len(raw)) * 2, "0")
    if t == "bytes":
        raw = _bytes(value)
        return evm_abi_encode_uint256(len(raw)) + raw.hex().ljust(_ceil32(len(raw)) * 2, "0")
    if t.endswith("[]"):
        base = t[:-2]
        arr = _parse_array_value(value)
        if _is_dynamic_type(base):
            head: list[str] = [evm_abi_encode_uint256(len(arr))]
            tail = ""
            offset = 32 * len(arr)
            encoded_items: list[str] = []
            for item in arr:
                enc = _abi_encode_dynamic_no_prefix(base, item)
                encoded_items.append(enc)
                head.append(evm_abi_encode_uint256(offset))
                offset += len(enc) // 2
            return "".join(head) + "".join(encoded_items)
        return evm_abi_encode_uint256(len(arr)) + "".join(_abi_encode_static_no_prefix(base, item) for item in arr)
    raise NotImplementedError(f"dynamic ABI type not implemented: {typ}")


def evm_abi_encode(types: Sequence[str], values: Sequence[Any]) -> str:
    if isinstance(types, str):
        types = [t.strip() for t in types.split(",") if t.strip()]
    if isinstance(values, str):
        # Comma splitting is retained for CLI compatibility.  Dynamic values can
        # be expressed as JSON arrays or pipe-separated arrays.
        values = [v.strip() for v in values.split(",")] if values else []
    if len(types) != len(values):
        raise ValueError("types and values must have the same length")
    head: list[str] = []
    tail: list[str] = []
    offset = 32 * len(types)
    for typ, value in zip(types, values):
        if _is_dynamic_type(typ):
            encoded = _abi_encode_dynamic_no_prefix(typ, value)
            head.append(evm_abi_encode_uint256(offset))
            tail.append(encoded)
            offset += len(encoded) // 2
        else:
            head.append(_abi_encode_static_no_prefix(typ, value))
    return "0x" + "".join(head + tail)


def evm_abi_decode(types: Sequence[str], data: bytes | str) -> list[Any]:
    if isinstance(types, str):
        types = [t.strip() for t in types.split(",") if t.strip()]
    raw = _bytes(data)
    if len(raw) % 32 != 0 and len(raw) < 32 * len(types):
        raise ValueError("ABI data length is not word-aligned or too short")

    def word_at(offset: int) -> int:
        return int.from_bytes(raw[offset:offset + 32].ljust(32, b"\x00"), "big")

    out: list[Any] = []
    for idx, typ in enumerate(types):
        t = typ.strip().lower()
        head_offset = idx * 32
        if _is_dynamic_type(t):
            dyn_offset = word_at(head_offset)
            size = word_at(dyn_offset)
            payload = raw[dyn_offset + 32: dyn_offset + 32 + size]
            if t == "string":
                out.append(payload.decode("utf-8"))
            elif t == "bytes":
                out.append("0x" + payload.hex())
            elif t.endswith("[]"):
                base = t[:-2]
                vals: list[Any] = []
                arr_start = dyn_offset + 32
                for i in range(size):
                    chunk = raw[arr_start + i * 32: arr_start + (i + 1) * 32]
                    vals.append(evm_abi_decode([base], chunk)[0])
                out.append(vals)
            else:
                raise NotImplementedError(t)
        else:
            word = raw[head_offset:head_offset + 32]
            val = int.from_bytes(word, "big")
            if t.startswith("uint"):
                out.append(val)
            elif t.startswith("int"):
                out.append(_signed(val))
            elif t == "bool":
                out.append(bool(val))
            elif t == "address":
                out.append("0x" + word[-20:].hex())
            elif t.startswith("bytes"):
                if t == "bytes32":
                    out.append("0x" + word.hex())
                else:
                    n = int(t[5:])
                    out.append("0x" + word[:n].hex())
            else:
                raise NotImplementedError(f"ABI decode type not implemented: {typ}")
    return out


def evm_contract_call_data(signature: str, types: Sequence[str] | None = None, values: Sequence[Any] | None = None) -> str:
    encoded = ""
    if types or values:
        encoded = _strip_0x(evm_abi_encode(types or [], values or []))
    return evm_function_selector(signature) + encoded


@dataclass
class EVMBytecodeBuilder:
    code: bytearray = field(default_factory=bytearray)

    def op(self, name: str) -> "EVMBytecodeBuilder":
        opcode = NAME_TO_OPCODE.get(name.upper())
        if opcode is None:
            raise ValueError(f"unknown EVM opcode: {name}")
        self.code.append(opcode)
        return self

    def push0(self) -> "EVMBytecodeBuilder":
        self.code.append(0x5F)
        return self

    def push(self, value: int | bytes | str) -> "EVMBytecodeBuilder":
        if isinstance(value, int):
            if value < 0:
                raise ValueError("cannot PUSH negative integer")
            if value == 0:
                return self.push0()
            raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        else:
            raw = _bytes(value)
        if len(raw) < 1 or len(raw) > 32:
            raise ValueError("PUSH payload must be 1..32 bytes")
        self.code.append(0x5F + len(raw))
        self.code.extend(raw)
        return self

    def stop(self) -> "EVMBytecodeBuilder": return self.op("STOP")
    def add(self) -> "EVMBytecodeBuilder": return self.op("ADD")
    def mul(self) -> "EVMBytecodeBuilder": return self.op("MUL")
    def sub(self) -> "EVMBytecodeBuilder": return self.op("SUB")
    def mstore(self) -> "EVMBytecodeBuilder": return self.op("MSTORE")
    def mload(self) -> "EVMBytecodeBuilder": return self.op("MLOAD")
    def sstore(self) -> "EVMBytecodeBuilder": return self.op("SSTORE")
    def sload(self) -> "EVMBytecodeBuilder": return self.op("SLOAD")
    def ret(self) -> "EVMBytecodeBuilder": return self.op("RETURN")
    def revert(self) -> "EVMBytecodeBuilder": return self.op("REVERT")

    def hex(self) -> str:
        return "0x" + self.code.hex()

    def bytes(self) -> bytes:
        return bytes(self.code)


def evm_bytecode_builder() -> EVMBytecodeBuilder:
    return EVMBytecodeBuilder()


def evm_disassemble(bytecode: bytes | str) -> list[dict[str, Any]]:
    raw = _bytes(bytecode)
    out: list[dict[str, Any]] = []
    pc = 0
    while pc < len(raw):
        opcode = raw[pc]
        name = OPCODES.get(opcode, f"UNKNOWN_0x{opcode:02x}")
        item: dict[str, Any] = {"pc": pc, "opcode": opcode, "name": name}
        pc += 1
        if opcode == 0x5F:
            item["push_data"] = "0x"
        elif 0x60 <= opcode <= 0x7F:
            n = opcode - 0x5F
            data = raw[pc: pc + n]
            item["push_data"] = "0x" + data.hex()
            item["value"] = int.from_bytes(data, "big")
            pc += n
        out.append(item)
    return out


@dataclass
class EVMLog:
    address: str
    topics: list[str]
    data: str


@dataclass
class EVMAccount:
    address: str
    balance: int = 0
    nonce: int = 0
    code: bytes = b""
    storage: dict[int, int] = field(default_factory=dict)

    def code_hash(self) -> str:
        return evm_keccak(self.code)


class EVMWorldState:
    def __init__(self, accounts: Mapping[str, Mapping[str, Any] | EVMAccount] | None = None) -> None:
        self.accounts: dict[str, EVMAccount] = {}
        if accounts:
            for addr, account in accounts.items():
                if isinstance(account, EVMAccount):
                    self.accounts[_normalize_address(addr)] = copy.deepcopy(account)
                else:
                    self.create_account(addr, **dict(account))

    def create_account(self, address: str | int, *, balance: int = 0, nonce: int = 0, code: bytes | str = b"", storage: Mapping[int | str, int | str] | None = None) -> EVMAccount:
        norm = _normalize_address(address)
        st: dict[int, int] = {}
        if storage:
            for k, v in storage.items():
                st[int(k, 0) if isinstance(k, str) else int(k)] = int(v, 0) if isinstance(v, str) else int(v)
        acc = EVMAccount(norm, int(balance), int(nonce), _bytes(code), st)
        self.accounts[norm] = acc
        return acc

    def get_account(self, address: str | int) -> EVMAccount:
        norm = _normalize_address(address)
        if norm not in self.accounts:
            self.accounts[norm] = EVMAccount(norm)
        return self.accounts[norm]

    def balance(self, address: str | int) -> int:
        return self.get_account(address).balance

    def transfer(self, sender: str | int, receiver: str | int, value: int) -> bool:
        if value < 0:
            return False
        src = self.get_account(sender)
        dst = self.get_account(receiver)
        if src.balance < value:
            return False
        src.balance -= value
        dst.balance += value
        return True

    def snapshot(self) -> dict[str, Any]:
        return {
            addr: {
                "balance": acc.balance,
                "nonce": acc.nonce,
                "code": "0x" + acc.code.hex(),
                "storage": {str(k): v for k, v in sorted(acc.storage.items())},
            }
            for addr, acc in sorted(self.accounts.items())
        }


@dataclass
class EVMExecutionContext:
    address: str = "0x0000000000000000000000000000000000000000"
    caller: str = "0x0000000000000000000000000000000000000000"
    origin: str = "0x0000000000000000000000000000000000000000"
    value: int = 0
    calldata: bytes = b""
    code: bytes = b""
    gas_price: int = 0
    chain_id: int = 1
    coinbase: str = "0x0000000000000000000000000000000000000000"
    timestamp: int = field(default_factory=lambda: int(time.time()))
    block_number: int = 0
    prev_randao: int = 0
    gas_limit: int = DEFAULT_GAS
    basefee: int = 0
    blobbasefee: int = 0
    static: bool = False
    depth: int = 0
    world: EVMWorldState = field(default_factory=EVMWorldState)
    return_data: bytes = b""
    fork: str = "cancun"


@dataclass
class EVMResult:
    ok: bool
    halted: bool
    reverted: bool
    gas_used: int
    gas_remaining: int
    output: str
    stack: list[int]
    memory: str
    storage: dict[str, int]
    logs: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    error: str | None = None
    world: dict[str, Any] | None = None


class EVMExecutionError(RuntimeError):
    pass


class EVMRevert(EVMExecutionError):
    def __init__(self, output: bytes) -> None:
        super().__init__("execution reverted")
        self.output = output


class EVMOutOfGas(EVMExecutionError):
    pass


class EVMMemory:
    def __init__(self) -> None:
        self.data = bytearray()
        self.last_cost = 0

    def _cost_for_size(self, size: int) -> int:
        words = _ceil32(size) // 32
        return 3 * words + (words * words) // 512

    def expand(self, end: int) -> int:
        if end <= len(self.data):
            return 0
        new_size = _ceil32(end)
        new_cost = self._cost_for_size(new_size)
        delta = new_cost - self.last_cost
        self.last_cost = new_cost
        self.data.extend(b"\x00" * (new_size - len(self.data)))
        return max(0, delta)

    def read(self, offset: int, size: int) -> bytes:
        if size <= 0:
            return b""
        self.expand(offset + size)
        return bytes(self.data[offset:offset + size])

    def write(self, offset: int, value: bytes) -> int:
        if not value:
            return 0
        cost = self.expand(offset + len(value))
        self.data[offset:offset + len(value)] = value
        return cost

    def word(self, offset: int) -> int:
        return int.from_bytes(self.read(offset, 32), "big")

    def write_word(self, offset: int, value: int) -> int:
        return self.write(offset, _word(value).to_bytes(32, "big"))


def _valid_jumpdests(code: bytes) -> set[int]:
    dests: set[int] = set()
    pc = 0
    while pc < len(code):
        op = code[pc]
        if op == 0x5B:
            dests.add(pc)
            pc += 1
        elif 0x60 <= op <= 0x7F:
            pc += 1 + (op - 0x5F)
        else:
            pc += 1
    return dests


class EVMInterpreter:
    def __init__(self, *, world: EVMWorldState | None = None, strict: bool = True, trace: bool = False) -> None:
        self.world = world or EVMWorldState()
        self.strict = strict
        self.trace_enabled = trace

    def execute(self, bytecode: bytes | str, *, calldata: bytes | str = b"", gas: int = DEFAULT_GAS, context: EVMExecutionContext | Mapping[str, Any] | None = None, trace: bool | None = None) -> EVMResult:
        code = _bytes(bytecode)
        if isinstance(context, Mapping):
            ctx = EVMExecutionContext(**dict(context))
        elif context is None:
            ctx = EVMExecutionContext()
        else:
            ctx = context
        ctx.world = self.world if ctx.world is None else ctx.world
        self.world = ctx.world
        ctx.code = code
        ctx.calldata = _bytes(calldata)
        account = self.world.get_account(ctx.address)
        if not account.code:
            account.code = code
        try:
            return self._run(code, gas, ctx, trace=self.trace_enabled if trace is None else trace)
        except EVMRevert as exc:
            gas_used = max(0, gas - getattr(exc, "gas_remaining", 0))
            return EVMResult(False, True, True, gas_used, getattr(exc, "gas_remaining", 0), _hex(exc.output), [], "0x", {str(k): v for k, v in account.storage.items()}, [], [], "execution reverted", self.world.snapshot())
        except EVMExecutionError as exc:
            return EVMResult(False, True, False, gas, 0, "0x", [], "0x", {str(k): v for k, v in account.storage.items()}, [], [], str(exc), self.world.snapshot())

    def _run(self, code: bytes, gas: int, ctx: EVMExecutionContext, *, trace: bool) -> EVMResult:
        pc = 0
        stack: list[int] = []
        memory = EVMMemory()
        logs: list[EVMLog] = []
        trace_out: list[dict[str, Any]] = []
        jumpdests = _valid_jumpdests(code)
        gas_remaining = int(gas)
        return_data = ctx.return_data
        output = b""
        halted = False
        reverted = False
        account = ctx.world.get_account(ctx.address)
        storage = account.storage

        def charge(amount: int) -> None:
            nonlocal gas_remaining
            amount = max(0, int(amount))
            if gas_remaining < amount:
                raise EVMOutOfGas("out of gas")
            gas_remaining -= amount

        def push(value: int) -> None:
            if len(stack) >= MAX_STACK:
                raise EVMExecutionError("stack overflow")
            stack.append(_word(value))

        def pop() -> int:
            if not stack:
                raise EVMExecutionError("stack underflow")
            return stack.pop()

        def mem_charge(end: int) -> None:
            charge(memory.expand(end))

        while pc < len(code) and not halted:
            op_pc = pc
            opcode = code[pc]
            name = OPCODES.get(opcode)
            if name is None:
                raise EVMExecutionError(f"invalid opcode 0x{opcode:02x} at pc {pc}")
            required_fork = OPCODE_FORK.get(opcode)
            if required_fork and not fork_at_least(ctx.fork, required_fork):
                raise EVMExecutionError(f"opcode {name} is not active in fork {ctx.fork}")
            pc += 1
            charge(GAS_COSTS.get(name, 3))
            if trace:
                trace_out.append({"pc": op_pc, "op": name, "gas_before": gas_remaining + GAS_COSTS.get(name, 3), "stack": [hex(x) for x in stack]})

            if opcode == 0x00:  # STOP
                halted = True
            elif opcode == 0x5F:  # PUSH0
                push(0)
            elif 0x60 <= opcode <= 0x7F:
                n = opcode - 0x5F
                if pc + n > len(code):
                    raw = code[pc:] + b"\x00" * (pc + n - len(code))
                else:
                    raw = code[pc:pc + n]
                pc += n
                push(int.from_bytes(raw, "big"))
            elif name.startswith("DUP"):
                idx = int(name[3:])
                if len(stack) < idx:
                    raise EVMExecutionError("stack underflow")
                push(stack[-idx])
            elif name.startswith("SWAP"):
                idx = int(name[4:])
                if len(stack) < idx + 1:
                    raise EVMExecutionError("stack underflow")
                stack[-1], stack[-idx - 1] = stack[-idx - 1], stack[-1]
            elif name == "POP":
                pop()
            elif name in {"ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND"}:
                if name == "ADD": push(pop() + pop())
                elif name == "MUL": push(pop() * pop())
                elif name == "SUB":
                    a, b = pop(), pop(); push(a - b)
                elif name == "DIV":
                    a, b = pop(), pop(); push(0 if b == 0 else a // b)
                elif name == "SDIV":
                    a, b = _signed(pop()), _signed(pop()); push(0 if b == 0 else _unsigned_from_signed(abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)))
                elif name == "MOD":
                    a, b = pop(), pop(); push(0 if b == 0 else a % b)
                elif name == "SMOD":
                    a, b = _signed(pop()), _signed(pop()); push(0 if b == 0 else _unsigned_from_signed((abs(a) % abs(b)) * (-1 if a < 0 else 1)))
                elif name == "ADDMOD":
                    a, b, n = pop(), pop(), pop(); push(0 if n == 0 else (a + b) % n)
                elif name == "MULMOD":
                    a, b, n = pop(), pop(), pop(); push(0 if n == 0 else (a * b) % n)
                elif name == "EXP":
                    base, exponent = pop(), pop(); charge(50 * max(1, (exponent.bit_length() + 7) // 8) if exponent else 0); push(pow(base, exponent, WORD_MOD))
                elif name == "SIGNEXTEND":
                    k, x = pop(), pop()
                    if k >= 32: push(x)
                    else:
                        bit = 8 * k + 7
                        mask = (1 << (bit + 1)) - 1
                        sign = 1 << bit
                        push(x | (WORD_MASK ^ mask) if x & sign else x & mask)
            elif name in {"LT", "GT", "SLT", "SGT", "EQ", "ISZERO", "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR", "SAR"}:
                if name == "LT": a, b = pop(), pop(); push(1 if a < b else 0)
                elif name == "GT": a, b = pop(), pop(); push(1 if a > b else 0)
                elif name == "SLT": a, b = _signed(pop()), _signed(pop()); push(1 if a < b else 0)
                elif name == "SGT": a, b = _signed(pop()), _signed(pop()); push(1 if a > b else 0)
                elif name == "EQ": push(1 if pop() == pop() else 0)
                elif name == "ISZERO": push(1 if pop() == 0 else 0)
                elif name == "AND": push(pop() & pop())
                elif name == "OR": push(pop() | pop())
                elif name == "XOR": push(pop() ^ pop())
                elif name == "NOT": push(WORD_MASK ^ pop())
                elif name == "BYTE": i, x = pop(), pop(); push(0 if i >= 32 else (x >> (8 * (31 - i))) & 0xFF)
                elif name == "SHL": shift, value = pop(), pop(); push(0 if shift >= 256 else value << shift)
                elif name == "SHR": shift, value = pop(), pop(); push(0 if shift >= 256 else value >> shift)
                elif name == "SAR":
                    shift, value = pop(), _signed(pop())
                    push(WORD_MASK if shift >= 256 and value < 0 else (0 if shift >= 256 else _unsigned_from_signed(value >> shift)))
            elif name == "SHA3":
                offset, size = pop(), pop()
                mem_charge(offset + size)
                charge(6 * (_ceil32(size) // 32))
                push(int.from_bytes(_evm_keccak_bytes(memory.read(offset, size)), "big"))
            elif name == "ADDRESS": push(int(_normalize_address(ctx.address), 16))
            elif name == "BALANCE": push(ctx.world.balance(_normalize_address(pop())))
            elif name == "ORIGIN": push(int(_normalize_address(ctx.origin), 16))
            elif name == "CALLER": push(int(_normalize_address(ctx.caller), 16))
            elif name == "CALLVALUE": push(ctx.value)
            elif name == "CALLDATALOAD":
                offset = pop(); data = ctx.calldata[offset:offset + 32].ljust(32, b"\x00"); push(int.from_bytes(data, "big"))
            elif name == "CALLDATASIZE": push(len(ctx.calldata))
            elif name == "CALLDATACOPY":
                dest, offset, size = pop(), pop(), pop(); mem_charge(dest + size); memory.write(dest, ctx.calldata[offset:offset + size].ljust(size, b"\x00")); charge(3 * (_ceil32(size) // 32))
            elif name == "CODESIZE": push(len(code))
            elif name == "CODECOPY":
                dest, offset, size = pop(), pop(), pop(); mem_charge(dest + size); memory.write(dest, code[offset:offset + size].ljust(size, b"\x00")); charge(3 * (_ceil32(size) // 32))
            elif name == "GASPRICE": push(ctx.gas_price)
            elif name == "EXTCODESIZE": push(len(ctx.world.get_account(_normalize_address(pop())).code))
            elif name == "EXTCODECOPY":
                address, dest, offset, size = _normalize_address(pop()), pop(), pop(), pop()
                ext_code = ctx.world.get_account(address).code; mem_charge(dest + size); memory.write(dest, ext_code[offset:offset + size].ljust(size, b"\x00")); charge(3 * (_ceil32(size) // 32))
            elif name == "RETURNDATASIZE": push(len(return_data))
            elif name == "RETURNDATACOPY":
                dest, offset, size = pop(), pop(), pop()
                if offset + size > len(return_data): raise EVMExecutionError("RETURNDATACOPY out of bounds")
                mem_charge(dest + size); memory.write(dest, return_data[offset:offset + size]); charge(3 * (_ceil32(size) // 32))
            elif name == "EXTCODEHASH": push(int.from_bytes(_evm_keccak_bytes(ctx.world.get_account(_normalize_address(pop())).code), "big"))
            elif name == "BLOCKHASH": pop(); push(0)
            elif name == "COINBASE": push(int(_normalize_address(ctx.coinbase), 16))
            elif name == "TIMESTAMP": push(ctx.timestamp)
            elif name == "NUMBER": push(ctx.block_number)
            elif name in {"DIFFICULTY", "PREVRANDAO"}: push(ctx.prev_randao)
            elif name == "GASLIMIT": push(ctx.gas_limit)
            elif name == "CHAINID": push(ctx.chain_id)
            elif name == "SELFBALANCE": push(ctx.world.balance(ctx.address))
            elif name == "BASEFEE": push(ctx.basefee)
            elif name == "BLOBHASH": pop(); push(0)
            elif name == "BLOBBASEFEE": push(ctx.blobbasefee)
            elif name == "MLOAD": push(memory.word(pop()))
            elif name == "MSTORE": offset, value = pop(), pop(); charge(memory.write_word(offset, value))
            elif name == "MSTORE8": offset, value = pop(), pop(); charge(memory.write(offset, bytes([value & 0xFF])))
            elif name == "SLOAD": push(storage.get(pop(), 0))
            elif name == "SSTORE":
                key, value = pop(), pop()
                if ctx.static: raise EVMExecutionError("SSTORE is not allowed in static context")
                storage[key] = _word(value)
            elif name == "JUMP":
                dest = pop()
                if dest not in jumpdests: raise EVMExecutionError(f"bad jump destination {dest}")
                pc = dest
            elif name == "JUMPI":
                dest, cond = pop(), pop()
                if cond != 0:
                    if dest not in jumpdests: raise EVMExecutionError(f"bad jump destination {dest}")
                    pc = dest
            elif name == "PC": push(op_pc)
            elif name == "MSIZE": push(len(memory.data))
            elif name == "GAS": push(gas_remaining)
            elif name == "JUMPDEST": pass
            elif name.startswith("LOG"):
                count = int(name[3:])
                offset, size = pop(), pop()
                topics = ["0x" + pop().to_bytes(32, "big").hex() for _ in range(count)]
                mem_charge(offset + size)
                data = memory.read(offset, size)
                logs.append(EVMLog(_normalize_address(ctx.address), topics, "0x" + data.hex()))
                charge(8 * size)
            elif name in {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}:
                call_gas = pop(); to_addr = _normalize_address(pop())
                if name in {"CALL", "CALLCODE"}:
                    call_value = pop()
                else:
                    call_value = ctx.value
                in_offset, in_size, out_offset, out_size = pop(), pop(), pop(), pop()
                calldata = memory.read(in_offset, in_size)
                callee = ctx.world.get_account(to_addr)
                if ctx.depth + 1 > MAX_CALL_DEPTH:
                    push(0); return_data = b""; continue
                if name == "CALL" and call_value and not ctx.world.transfer(ctx.address, to_addr, call_value):
                    push(0); return_data = b""; continue
                child_ctx = EVMExecutionContext(
                    address=ctx.address if name in {"CALLCODE", "DELEGATECALL"} else to_addr,
                    caller=ctx.caller if name == "DELEGATECALL" else ctx.address,
                    origin=ctx.origin,
                    value=ctx.value if name == "DELEGATECALL" else call_value,
                    calldata=calldata,
                    code=callee.code,
                    gas_price=ctx.gas_price,
                    chain_id=ctx.chain_id,
                    coinbase=ctx.coinbase,
                    timestamp=ctx.timestamp,
                    block_number=ctx.block_number,
                    prev_randao=ctx.prev_randao,
                    gas_limit=ctx.gas_limit,
                    basefee=ctx.basefee,
                    static=ctx.static or name == "STATICCALL",
                    depth=ctx.depth + 1,
                    world=ctx.world,
                    return_data=return_data,
                )
                result = self._run(callee.code, min(call_gas, gas_remaining), child_ctx, trace=False) if callee.code else EVMResult(True, True, False, 0, call_gas, "0x", [], "0x", {}, [], [], None, ctx.world.snapshot())
                return_data = _bytes(result.output)
                memory.write(out_offset, return_data[:out_size].ljust(out_size, b"\x00"))
                push(1 if result.ok else 0)
            elif name in {"CREATE", "CREATE2"}:
                if ctx.static: raise EVMExecutionError("CREATE is not allowed in static context")
                value, offset, size = pop(), pop(), pop()
                salt = pop() if name == "CREATE2" else 0
                init_code = memory.read(offset, size)
                creator = ctx.world.get_account(ctx.address)
                creator.nonce += 1
                seed = _bytes(ctx.address) + creator.nonce.to_bytes(32, "big") + salt.to_bytes(32, "big") + init_code
                new_addr = _normalize_address(int.from_bytes(_evm_keccak_bytes(seed)[-20:], "big"))
                ctx.world.create_account(new_addr, balance=value, code=init_code)
                push(int(new_addr, 16))
            elif name == "RETURN":
                offset, size = pop(), pop(); output = memory.read(offset, size); halted = True
            elif name == "REVERT":
                offset, size = pop(), pop(); output = memory.read(offset, size); reverted = True; halted = True
            elif name == "INVALID":
                raise EVMExecutionError("invalid opcode")
            elif name == "SELFDESTRUCT":
                if ctx.static: raise EVMExecutionError("SELFDESTRUCT is not allowed in static context")
                beneficiary = _normalize_address(pop())
                acc = ctx.world.get_account(ctx.address)
                ctx.world.get_account(beneficiary).balance += acc.balance
                acc.balance = 0
                acc.code = b""
                halted = True
            else:
                raise EVMExecutionError(f"opcode not implemented: {name}")

        if reverted:
            res = EVMResult(False, True, True, gas - gas_remaining, gas_remaining, _hex(output), stack[:], _hex(memory.data), {str(k): v for k, v in sorted(storage.items())}, [log.__dict__ for log in logs], trace_out, "execution reverted", ctx.world.snapshot())
            return res
        return EVMResult(True, halted or pc >= len(code), False, gas - gas_remaining, gas_remaining, _hex(output), stack[:], _hex(memory.data), {str(k): v for k, v in sorted(storage.items())}, [log.__dict__ for log in logs], trace_out, None, ctx.world.snapshot())


def evm_world_state(accounts: Mapping[str, Mapping[str, Any] | EVMAccount] | None = None) -> EVMWorldState:
    return EVMWorldState(accounts)


def evm_interpreter(world: EVMWorldState | None = None, *, trace: bool = False, strict: bool = True) -> EVMInterpreter:
    return EVMInterpreter(world=world, trace=trace, strict=strict)


def evm_execute(bytecode: bytes | str, calldata: bytes | str = b"", gas: int = DEFAULT_GAS, context: Mapping[str, Any] | EVMExecutionContext | None = None, trace: bool = False) -> dict[str, Any]:
    interp = EVMInterpreter(trace=trace)
    result = interp.execute(bytecode, calldata=calldata, gas=gas, context=context, trace=trace)
    return result.__dict__


def evm_simulate_call(code: bytes | str, calldata: bytes | str = b"", *, storage: Mapping[int | str, int | str] | None = None, address: str = "0x0000000000000000000000000000000000001000", caller: str = "0x0000000000000000000000000000000000002000", value: int = 0, gas: int = DEFAULT_GAS, trace: bool = False) -> dict[str, Any]:
    world = EVMWorldState()
    world.create_account(address, code=code, storage=storage or {})
    ctx = EVMExecutionContext(address=address, caller=caller, origin=caller, value=value, calldata=_bytes(calldata), world=world)
    return EVMInterpreter(world=world, trace=trace).execute(code, calldata=calldata, gas=gas, context=ctx, trace=trace).__dict__


def evm_estimate_gas(bytecode: bytes | str, calldata: bytes | str = b"", *, gas_limit: int = DEFAULT_GAS) -> int:
    result = evm_execute(bytecode, calldata, gas_limit)
    if not result["ok"]:
        raise EVMExecutionError(result.get("error") or "execution failed")
    return int(result["gas_used"])


def evm_trace(bytecode: bytes | str, calldata: bytes | str = b"", gas: int = DEFAULT_GAS) -> list[dict[str, Any]]:
    return evm_execute(bytecode, calldata, gas, trace=True)["trace"]


# Minimal RLP support for transaction tooling.
def _rlp_encode(item: Any) -> bytes:
    if isinstance(item, int):
        if item == 0:
            return bytes([0x80])
        return _rlp_encode(_bytes(item))
    if isinstance(item, str):
        return _rlp_encode(_bytes(item) if item.startswith("0x") else item.encode())
    if isinstance(item, (bytes, bytearray)):
        raw = bytes(item)
        if len(raw) == 1 and raw[0] < 0x80:
            return raw
        if len(raw) <= 55:
            return bytes([0x80 + len(raw)]) + raw
        n = _bytes(len(raw))
        return bytes([0xB7 + len(n)]) + n + raw
    if isinstance(item, (list, tuple)):
        payload = b"".join(_rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xC0 + len(payload)]) + payload
        n = _bytes(len(payload))
        return bytes([0xF7 + len(n)]) + n + payload
    raise TypeError(f"cannot RLP encode {type(item).__name__}")


def evm_rlp_encode(value: Any) -> str:
    return "0x" + _rlp_encode(value).hex()


def evm_legacy_unsigned_tx(nonce: int, gas_price: int, gas_limit: int, to: str, value: int, data: bytes | str = b"", chain_id: int | None = None) -> dict[str, Any]:
    fields: list[Any] = [nonce, gas_price, gas_limit, _normalize_address(to), value, _bytes(data)]
    if chain_id is not None:
        fields.extend([chain_id, 0, 0])
    raw = _rlp_encode(fields)
    return {"rlp": "0x" + raw.hex(), "signing_hash": evm_keccak(raw), "fields": [str(x) if not isinstance(x, bytes) else "0x" + x.hex() for x in fields]}


class EVMJsonRpc:
    def __init__(self, url: str, *, timeout: float = 10.0, headers: Mapping[str, str] | None = None) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self._id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as response:  # noqa: S310 - endpoint is user supplied by design.
            data = json.loads(response.read().decode("utf-8"))
        if "error" in data:
            raise RuntimeError(data["error"])
        return data.get("result")

    def batch(self, calls: Sequence[tuple[str, list[Any] | None]]) -> list[Any]:
        batch_payload = []
        ids = []
        for method, params in calls:
            self._id += 1
            ids.append(self._id)
            batch_payload.append({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []})
        req = urllib.request.Request(self.url, data=json.dumps(batch_payload).encode(), headers={"Content-Type": "application/json", **self.headers}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as response:  # noqa: S310
            data = json.loads(response.read().decode("utf-8"))
        by_id = {item["id"]: item for item in data}
        out = []
        for call_id in ids:
            item = by_id[call_id]
            if "error" in item:
                raise RuntimeError(item["error"])
            out.append(item.get("result"))
        return out

    def chain_id(self) -> int: return int(self.call("eth_chainId"), 16)
    def block_number(self) -> int: return int(self.call("eth_blockNumber"), 16)
    def gas_price(self) -> int: return int(self.call("eth_gasPrice"), 16)
    def get_balance(self, address: str, block: str = "latest") -> int: return int(self.call("eth_getBalance", [_normalize_address(address), block]), 16)
    def get_code(self, address: str, block: str = "latest") -> str: return self.call("eth_getCode", [_normalize_address(address), block])
    def call_contract(self, to: str, data: str, block: str = "latest", value: int = 0) -> str: return self.call("eth_call", [{"to": _normalize_address(to), "data": data, "value": hex(value)}, block])
    def estimate_gas(self, tx: Mapping[str, Any]) -> int: return int(self.call("eth_estimateGas", [dict(tx)]), 16)
    def send_raw_transaction(self, raw_tx: str) -> str: return self.call("eth_sendRawTransaction", [raw_tx])
    def get_transaction_receipt(self, tx_hash: str) -> Any: return self.call("eth_getTransactionReceipt", [tx_hash])


def evm_rpc(url: str, timeout: float = 10.0) -> EVMJsonRpc:
    return EVMJsonRpc(url, timeout=timeout)


def evm_external_engine(name: str = "auto") -> dict[str, Any]:
    engines = {
        "py_evm": "eth.vm",
        "ethereum": "ethereum",
        "ethereumjs": None,
        "revm": None,
    }
    status: dict[str, Any] = {"requested": name, "available": {}, "selected": None}
    for engine, module in engines.items():
        if module is None:
            status["available"][engine] = {"installed": False, "kind": "external_cli_or_native_bridge"}
            continue
        try:
            __import__(module)
            status["available"][engine] = {"installed": True, "module": module}
            if status["selected"] is None and name in {"auto", engine}:
                status["selected"] = engine
        except Exception as exc:
            status["available"][engine] = {"installed": False, "module": module, "error": str(exc)}
    return status


def evm_capabilities() -> dict[str, Any]:
    return {
        "version": EVM_VERSION,
        "production_usable_evm_toolkit": True,
        "function_selector": True,
        "abi_static_types": ["uint256", "uint", "int256", "address", "bool", "bytes1..bytes32", "bytes32"],
        "abi_dynamic_types": ["string", "bytes", "uint256[]", "address[]", "bool[]"],
        "abi_decode": True,
        "bytecode_builder": True,
        "disassembler": True,
        "json_rpc_client": True,
        "rlp_transaction_tooling": True,
        "executable_interpreter": True,
        "gas_accounting": True,
        "memory_model": True,
        "storage_model": True,
        "world_state": True,
        "logs": True,
        "trace": True,
        "call_simulation": True,
        "supported_opcode_count": len(OPCODES),
        "unsupported_full_node_features": ["p2p_sync", "consensus_validation", "fork_choice", "block_production", "canonical_chain_database"],
        "exact_keccak_available": evm_has_exact_keccak(),
        "fallback_hash": None if evm_has_exact_keccak() else "pure_python_keccak256",
        "external_engine_bridge": True,
    }
