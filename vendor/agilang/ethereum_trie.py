"""Dependency-free Ethereum RLP, hexary MPT roots, receipts and log bloom."""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .evm import evm_keccak


def keccak(data: bytes) -> bytes:
    return bytes.fromhex(evm_keccak(data)[2:])


def int_bytes(value: int) -> bytes:
    value = int(value)
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def rlp(value: Any) -> bytes:
    if isinstance(value, int):
        return rlp(int_bytes(value))
    if isinstance(value, str):
        raw = bytes.fromhex(value[2:]) if value.startswith("0x") else value.encode()
        return rlp(raw)
    if isinstance(value, (list, tuple)):
        payload = b"".join(rlp(item) for item in value)
        return bytes([0xC0 + len(payload)]) + payload if len(payload) <= 55 else bytes([0xF7 + len(int_bytes(len(payload)))]) + int_bytes(len(payload)) + payload
    raw = bytes(value)
    if len(raw) == 1 and raw[0] < 0x80:
        return raw
    return bytes([0x80 + len(raw)]) + raw if len(raw) <= 55 else bytes([0xB7 + len(int_bytes(len(raw)))]) + int_bytes(len(raw)) + raw


def _nibbles(raw: bytes) -> tuple[int, ...]:
    return tuple(n for b in raw for n in (b >> 4, b & 15))


def _compact(path: Sequence[int], leaf: bool) -> bytes:
    odd = len(path) % 2
    first = 2 * int(leaf) + odd
    nibbles = ([first] + list(path)) if odd else ([first, 0] + list(path))
    return bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))


def _common(items: Sequence[tuple[tuple[int, ...], bytes]]) -> int:
    size = min(len(k) for k, _ in items)
    i = 0
    while i < size and len({k[i] for k, _ in items}) == 1:
        i += 1
    return i


def _node(items: Sequence[tuple[tuple[int, ...], bytes]]) -> bytes:
    if len(items) == 1:
        key, value = items[0]
        return rlp([_compact(key, True), value])
    common = _common(items)
    if common:
        child = _node([(key[common:], value) for key, value in items])
        return rlp([_compact(items[0][0][:common], False), child if len(child) < 32 else keccak(child)])
    branch: list[bytes] = [b""] * 17
    for nibble in range(16):
        subset = [(key[1:], value) for key, value in items if key and key[0] == nibble]
        if subset:
            child = _node(subset)
            branch[nibble] = child if len(child) < 32 else keccak(child)
    terminal = [value for key, value in items if not key]
    branch[16] = terminal[0] if terminal else b""
    return rlp(branch)


EMPTY_TRIE_ROOT = "0x" + keccak(rlp(b"")).hex()
EMPTY_UNCLE_HASH = "0x" + keccak(rlp([])).hex()
EMPTY_CODE_HASH = "0x" + keccak(b"").hex()


def trie_root(entries: Iterable[tuple[bytes, bytes]]) -> str:
    normalized = sorted(((_nibbles(key), value) for key, value in entries), key=lambda item: item[0])
    return EMPTY_TRIE_ROOT if not normalized else "0x" + keccak(_node(normalized)).hex()


def _address_bytes(address: Any) -> bytes:
    text = str(address or "").lower()
    if text.startswith("0x") and len(text) == 42:
        try:
            return bytes.fromhex(text[2:])
        except ValueError:
            pass
    return keccak(text.encode())[-20:]


def _contract(contract: Any) -> tuple[str, Mapping[str, Any]]:
    if isinstance(contract, Mapping):
        return str(contract.get("code", "0x")), dict(contract.get("storage", {}) or {})
    return str(contract or "0x"), {}


def storage_root(storage: Mapping[str, Any]) -> str:
    entries = []
    for slot, value in storage.items():
        number = int(value)
        if number:
            slot_int = int(str(slot), 0) if str(slot).startswith("0x") else int(slot)
            entries.append((keccak(slot_int.to_bytes(32, "big")), rlp(number)))
    return trie_root(entries)


def state_root(state: Mapping[str, Any]) -> str:
    balances = dict(state.get("balances", {}) or {})
    nonces = dict(state.get("nonces", {}) or {})
    contracts = dict(state.get("contracts", {}) or {})
    addresses = set(balances) | set(nonces) | set(contracts)
    entries = []
    for address in addresses:
        code, storage = _contract(contracts.get(address, "0x"))
        code_bytes = bytes.fromhex(code[2:] if code.startswith("0x") else code)
        account = rlp([int(nonces.get(address, 0)), int(balances.get(address, 0)), bytes.fromhex(storage_root(storage)[2:]), keccak(code_bytes)])
        entries.append((keccak(_address_bytes(address)), account))
    return trie_root(entries)


def logs_bloom(logs: Iterable[Mapping[str, Any]]) -> str:
    bloom = bytearray(256)
    for log in logs:
        values = [_address_bytes(log.get("address"))]
        values.extend(bytes.fromhex(str(topic)[2:].rjust(64, "0")) for topic in list(log.get("topics", []) or []))
        for value in values:
            digest = keccak(value)
            for offset in (0, 2, 4):
                bit = ((digest[offset] << 8) | digest[offset + 1]) & 2047
                bloom[255 - bit // 8] |= 1 << (bit % 8)
    return "0x" + bytes(bloom).hex()


def receipts_root(receipts: Iterable[Mapping[str, Any]]) -> str:
    entries = []
    cumulative = 0
    for index, receipt in enumerate(receipts):
        cumulative = int(receipt.get("cumulative_gas_used", cumulative + int(receipt.get("gas_used", 0))))
        logs = list(receipt.get("logs", []) or [])
        encoded_logs = []
        for log in logs:
            encoded_logs.append([_address_bytes(log.get("address")), [bytes.fromhex(str(t)[2:].rjust(64, "0")) for t in log.get("topics", [])], bytes.fromhex(str(log.get("data", "0x"))[2:])])
        payload = rlp([1 if receipt.get("ok", receipt.get("status", 0)) else 0, cumulative, bytes.fromhex(logs_bloom(logs)[2:]), encoded_logs])
        tx_type = int(receipt.get("type", 0) or 0)
        if tx_type in (1, 2, 3):
            payload = bytes([tx_type]) + payload
        entries.append((rlp(index), payload))
    return trie_root(entries)
