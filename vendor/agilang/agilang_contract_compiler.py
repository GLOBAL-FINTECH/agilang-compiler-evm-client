"""Native AGILANG smart-contract compiler for Smart Chain.

AGILANG contract source is parsed into ABI metadata and compact
EVM-compatible bytecode that Smart Chain's native execution client can deploy
and execute. This compiler intentionally does not call Solidity or solc.

Compiler slices currently supported:
- Legacy counter/chain-proof contracts for backward verification compatibility.
- Secure ERC20 profiles: fixed supply, mintable, burnable, capped, and pausable.
- Secure ERC721 NFT profiles with approvals, minting, burning, pausing, and safe transfers.
- ERC3156-compatible guarded flash-loan lender profiles.

The compiler emits EVM bytecode directly and does not invoke Solidity or solc.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .evm import evm_function_selector, evm_keccak


COMPILER_VERSION = "AGILANG-NATIVE-EVM/0.5.0"


class AgilangContractCompileError(ValueError):
    """Raised when AGILANG contract source cannot be compiled."""


_OP = {
    "STOP": 0x00,
    "ADD": 0x01,
    "MUL": 0x02,
    "SUB": 0x03,
    "DIV": 0x04,
    "MOD": 0x06,
    "LT": 0x10,
    "GT": 0x11,
    "EQ": 0x14,
    "ISZERO": 0x15,
    "AND": 0x16,
    "OR": 0x17,
    "XOR": 0x18,
    "NOT": 0x19,
    "SHL": 0x1B,
    "SHR": 0x1C,
    "SHA3": 0x20,
    "ADDRESS": 0x30,
    "ORIGIN": 0x32,
    "CALLER": 0x33,
    "CALLVALUE": 0x34,
    "CALLDATALOAD": 0x35,
    "CALLDATASIZE": 0x36,
    "CALLDATACOPY": 0x37,
    "CODECOPY": 0x39,
    "EXTCODESIZE": 0x3B,
    "RETURNDATASIZE": 0x3D,
    "RETURNDATACOPY": 0x3E,
    "POP": 0x50,
    "MLOAD": 0x51,
    "MSTORE": 0x52,
    "MSTORE8": 0x53,
    "SLOAD": 0x54,
    "SSTORE": 0x55,
    "JUMP": 0x56,
    "JUMPI": 0x57,
    "JUMPDEST": 0x5B,
    "GAS": 0x5A,
    "PUSH0": 0x5F,
    "DUP1": 0x80,
    "DUP2": 0x81,
    "DUP3": 0x82,
    "DUP4": 0x83,
    "DUP5": 0x84,
    "SWAP1": 0x90,
    "SWAP2": 0x91,
    "LOG1": 0xA1,
    "LOG2": 0xA2,
    "LOG3": 0xA3,
    "LOG4": 0xA4,
    "CALL": 0xF1,
    "RETURN": 0xF3,
    "STATICCALL": 0xFA,
    "REVERT": 0xFD,
}


@dataclass
class _Assembler:
    code: bytearray = field(default_factory=bytearray)
    labels: Dict[str, int] = field(default_factory=dict)
    fixups: List[tuple[int, str]] = field(default_factory=list)

    def op(self, name: str) -> "_Assembler":
        self.code.append(_OP[name])
        return self

    def push(self, value: int | bytes | str) -> "_Assembler":
        if isinstance(value, str):
            raw = bytes.fromhex(value.removeprefix("0x"))
        elif isinstance(value, bytes):
            raw = value
        else:
            if int(value) == 0:
                self.code.append(_OP["PUSH0"])
                return self
            raw = int(value).to_bytes(max(1, (int(value).bit_length() + 7) // 8), "big")
        if not 1 <= len(raw) <= 32:
            raise AgilangContractCompileError("PUSH payload must be 1..32 bytes")
        self.code.append(0x5F + len(raw))
        self.code.extend(raw)
        return self

    def push_label(self, name: str) -> "_Assembler":
        self.code.append(0x61)  # PUSH2 keeps the compiler compact and deterministic.
        pos = len(self.code)
        self.code.extend(b"\x00\x00")
        self.fixups.append((pos, name))
        return self

    def label(self, name: str) -> "_Assembler":
        self.labels[name] = len(self.code)
        self.op("JUMPDEST")
        return self

    def finish(self) -> bytes:
        for pos, name in self.fixups:
            if name not in self.labels:
                raise AgilangContractCompileError(f"unknown compiler label: {name}")
            self.code[pos:pos + 2] = int(self.labels[name]).to_bytes(2, "big")
        return bytes(self.code)


def _selector(signature: str) -> int:
    return int(evm_function_selector(signature), 16)


def _topic(signature: str) -> int:
    return int(evm_keccak(signature), 16)


def _mstore_word(asm: _Assembler, offset: int, value: int | bytes | str) -> None:
    asm.push(value).push(offset).op("MSTORE")


def _emit_return_uint_slot(asm: _Assembler, slot: int) -> None:
    asm.push(slot).op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")


def _emit_return_uint_const(asm: _Assembler, value: int) -> None:
    asm.push(value).push(0).op("MSTORE").push(32).push(0).op("RETURN")


def _emit_return_bool_true(asm: _Assembler) -> None:
    _emit_return_uint_const(asm, 1)


def _emit_return_string(asm: _Assembler, text: str) -> None:
    raw = text.encode("utf-8")
    if len(raw) > 32:
        raise AgilangContractCompileError("native compiler supports return strings up to 32 bytes in this compiler slice")
    _mstore_word(asm, 0, 32)
    _mstore_word(asm, 32, len(raw))
    _mstore_word(asm, 64, raw.ljust(32, b"\x00"))
    asm.push(96).push(0).op("RETURN")


def _emit_revert(asm: _Assembler) -> None:
    asm.push(0).push(0).op("REVERT")


def _emit_mapping_slot_from_stack_word(asm: _Assembler, base_slot: int) -> None:
    """Stack in: key_word. Stack out: keccak256(abi.encode(key_word, base_slot))."""
    asm.push(0).op("MSTORE")
    asm.push(base_slot).push(32).op("MSTORE")
    asm.push(64).push(0).op("SHA3")


def _emit_mapping_slot_from_calldata(asm: _Assembler, calldata_offset: int, base_slot: int) -> None:
    asm.push(calldata_offset).op("CALLDATALOAD")
    _emit_mapping_slot_from_stack_word(asm, base_slot)


def _emit_mapping_slot_from_caller(asm: _Assembler, base_slot: int) -> None:
    asm.op("CALLER")
    _emit_mapping_slot_from_stack_word(asm, base_slot)


def _emit_nested_allowance_slot(asm: _Assembler, owner_source: str, spender_source: str) -> None:
    """Stack out: allowances[owner][spender] slot.

    owner_source/spender_source: "caller" or calldata offset integer as str.
    Layout follows Solidity-style nested mapping:
        inner = keccak256(abi.encode(owner, allowance_base_slot))
        slot  = keccak256(abi.encode(spender, inner))
    """
    if owner_source == "caller":
        asm.op("CALLER")
    else:
        asm.push(int(owner_source)).op("CALLDATALOAD")
    _emit_mapping_slot_from_stack_word(asm, 6)
    # store inner at memory[32]
    asm.push(32).op("MSTORE")
    if spender_source == "caller":
        asm.op("CALLER")
    else:
        asm.push(int(spender_source)).op("CALLDATALOAD")
    asm.push(0).op("MSTORE")
    asm.push(64).push(0).op("SHA3")


def _emit_copy_runtime_return_prefix(runtime: bytes, prefix: bytearray) -> bytes:
    def push_into(buf: bytearray, value: int) -> None:
        if value == 0:
            buf.append(_OP["PUSH0"])
            return
        raw = int(value).to_bytes(max(1, (int(value).bit_length() + 7) // 8), "big")
        buf.append(0x5F + len(raw))
        buf.extend(raw)

    while True:
        probe = bytearray(prefix)
        push_into(probe, len(runtime))
        push_into(probe, len(probe) + 4)
        push_into(probe, 0)
        probe.append(_OP["CODECOPY"])
        push_into(probe, len(runtime))
        push_into(probe, 0)
        probe.append(_OP["RETURN"])
        offset = len(probe)
        final = bytearray(prefix)
        push_into(final, len(runtime))
        push_into(final, offset)
        push_into(final, 0)
        final.append(_OP["CODECOPY"])
        push_into(final, len(runtime))
        push_into(final, 0)
        final.append(_OP["RETURN"])
        if len(final) == offset:
            return bytes(final) + runtime


# ---------------------------------------------------------------------------
# Counter compiler slice
# ---------------------------------------------------------------------------


def _counter_runtime_bytecode(version_text: str) -> bytes:
    increment_topic = _topic("CounterIncremented(address,uint256)")
    asm = _Assembler()
    _emit_revert_if_callvalue(asm)
    _emit_revert_if_calldata_shorter_than(asm, 4)
    asm.push(0).op("CALLDATALOAD").push(224).op("SHR")
    for signature, label in (
        ("counter()", "counter"),
        ("increment()", "increment"),
        ("owner()", "owner"),
        ("version()", "version"),
    ):
        asm.op("DUP1").push(_selector(signature)).op("EQ").push_label(label).op("JUMPI")
    asm.op("POP")
    _emit_revert(asm)

    asm.label("counter")
    _emit_return_uint_slot(asm, 0)

    asm.label("owner")
    _emit_return_uint_slot(asm, 1)

    asm.label("version")
    _emit_return_string(asm, version_text)

    asm.label("increment")
    asm.push(0).op("SLOAD").push(1).op("ADD").op("DUP1").push(0).op("SSTORE")
    asm.op("DUP1").push(0).op("MSTORE")
    asm.op("CALLER").push(increment_topic).push(32).push(0).op("LOG2")
    asm.push(32).push(0).op("RETURN")

    asm.label("revert")
    _emit_revert(asm)
    return asm.finish()


def _counter_creation_bytecode(runtime: bytes) -> bytes:
    # Constructor: owner = msg.sender (slot 1), counter remains zero, then return runtime bytecode.
    prefix = bytearray()
    asm = _Assembler(code=prefix)
    _emit_revert_if_callvalue(asm)
    asm.op("CALLER").push(1).op("SSTORE")
    return _emit_copy_runtime_return_prefix(runtime, bytearray(asm.finish()))


# ---------------------------------------------------------------------------
# ERC20-style token compiler slice
# ---------------------------------------------------------------------------


_TOKEN_SUPPLY = 500_000_000 * 10**18
_TOKEN_NAME = "Smart Chain Token"
_TOKEN_SYMBOL = "ZMK"
_TOKEN_DECIMALS = 18
_TOKEN_VERSION = "SmartChainToken v1.0"
_ZERO_ADDRESS = 0
_ADDRESS_MASK = (1 << 160) - 1


def _emit_revert_if_callvalue(asm: _Assembler) -> None:
    ok = f"nonpayable_ok_{len(asm.fixups)}"
    asm.op("CALLVALUE").op("ISZERO").push_label(ok).op("JUMPI")
    _emit_revert(asm)
    asm.label(ok)


def _emit_revert_if_calldata_shorter_than(asm: _Assembler, size: int) -> None:
    asm.push(size).op("CALLDATASIZE").op("LT").push_label("revert").op("JUMPI")


def _emit_revert_if_noncanonical_address_at(asm: _Assembler, calldata_offset: int) -> None:
    asm.push(calldata_offset).op("CALLDATALOAD").op("DUP1").push(_ADDRESS_MASK).op("AND").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")


def _token_runtime_bytecode(*, name_text: str, symbol_text: str, version_text: str, decimals: int) -> bytes:
    transfer_topic = _topic("Transfer(address,address,uint256)")
    approval_topic = _topic("Approval(address,address,uint256)")
    asm = _Assembler()
    _emit_revert_if_callvalue(asm)
    _emit_revert_if_calldata_shorter_than(asm, 4)
    asm.push(0).op("CALLDATALOAD").push(224).op("SHR")
    for signature, label in (
        ("name()", "name"),
        ("symbol()", "symbol"),
        ("decimals()", "decimals"),
        ("totalSupply()", "totalSupply"),
        ("owner()", "owner"),
        ("balanceOf(address)", "balanceOf"),
        ("allowance(address,address)", "allowance"),
        ("transfer(address,uint256)", "transfer"),
        ("approve(address,uint256)", "approve"),
        ("transferFrom(address,address,uint256)", "transferFrom"),
        ("version()", "version"),
    ):
        asm.op("DUP1").push(_selector(signature)).op("EQ").push_label(label).op("JUMPI")
    asm.op("POP")
    _emit_revert(asm)

    asm.label("name")
    _emit_return_string(asm, name_text)

    asm.label("symbol")
    _emit_return_string(asm, symbol_text)

    asm.label("decimals")
    _emit_return_uint_const(asm, decimals)

    asm.label("totalSupply")
    _emit_return_uint_slot(asm, 0)

    asm.label("owner")
    _emit_return_uint_slot(asm, 1)

    asm.label("version")
    _emit_return_string(asm, version_text)

    asm.label("balanceOf")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 4, 5)
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("allowance")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_revert_if_noncanonical_address_at(asm, 36)
    _emit_nested_allowance_slot(asm, "4", "36")
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    # transfer(to, amount)
    asm.label("transfer")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    # to != zero
    asm.push(4).op("CALLDATALOAD").op("ISZERO").push_label("revert").op("JUMPI")
    # amount -> mem[0xa0]
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    # sender balance slot -> mem[0x80], balance -> mem[0xC0]
    _emit_mapping_slot_from_caller(asm, 5)
    asm.op("DUP1").push(0x80).op("MSTORE")
    asm.op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    # if balance < amount revert. For this interpreter LT computes top < next.
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    # sender balance = balance - amount
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
    # recipient slot -> mem[0xE0], recipient balance -> add amount
    _emit_mapping_slot_from_calldata(asm, 4, 5)
    asm.op("DUP1").push(0xE0).op("MSTORE")
    asm.op("SLOAD").push(0xA0).op("MLOAD").op("ADD").push(0xE0).op("MLOAD").op("SSTORE")
    # log Transfer(msg.sender, to, amount): data = amount at mem[0]
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(transfer_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    # approve(spender, amount)
    asm.label("approve")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    asm.push(4).op("CALLDATALOAD").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_nested_allowance_slot(asm, "caller", "4")
    asm.push(0xA0).op("MLOAD").op("SWAP1").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(approval_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    # transferFrom(from, to, amount)
    asm.label("transferFrom")
    _emit_revert_if_calldata_shorter_than(asm, 100)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_revert_if_noncanonical_address_at(asm, 36)
    asm.push(4).op("CALLDATALOAD").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(36).op("CALLDATALOAD").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(68).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    # from balance slot/balance
    _emit_mapping_slot_from_calldata(asm, 4, 5)
    asm.op("DUP1").push(0x80).op("MSTORE")
    asm.op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    # allowance[from][msg.sender] slot/balance
    _emit_nested_allowance_slot(asm, "4", "caller")
    asm.op("DUP1").push(0x120).op("MSTORE")
    asm.op("SLOAD").op("DUP1").push(0x140).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    # allowance -= amount
    asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("SUB").push(0x120).op("MLOAD").op("SSTORE")
    # from balance -= amount
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
    # to balance += amount
    _emit_mapping_slot_from_calldata(asm, 36, 5)
    asm.op("DUP1").push(0xE0).op("MSTORE")
    asm.op("SLOAD").push(0xA0).op("MLOAD").op("ADD").push(0xE0).op("MLOAD").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(36).op("CALLDATALOAD").push(4).op("CALLDATALOAD").push(transfer_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("revert")
    _emit_revert(asm)
    return asm.finish()


def _token_creation_bytecode(runtime: bytes, *, total_supply: int) -> bytes:
    prefix = bytearray()
    asm = _Assembler(code=prefix)
    _emit_revert_if_callvalue(asm)
    # totalSupply = total_supply at slot 0
    asm.push(total_supply).push(0).op("SSTORE")
    # owner = msg.sender at slot 1
    asm.op("CALLER").push(1).op("SSTORE")
    # balances[msg.sender] = totalSupply at mapping slot 5
    asm.op("CALLER")
    _emit_mapping_slot_from_stack_word(asm, 5)
    asm.push(total_supply).op("SWAP1").op("SSTORE")
    # emit Transfer(0x0, msg.sender, totalSupply)
    asm.push(total_supply).push(0).op("MSTORE")
    asm.op("CALLER").push(0).push(_topic("Transfer(address,address,uint256)")).push(32).push(0).op("LOG3")
    return _emit_copy_runtime_return_prefix(runtime, bytearray(asm.finish()))


def _contract_name(source: str) -> str:
    match = re.search(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", source)
    return match.group(1) if match else "SmartChainProof"


def _parse_token_constant(source: str, key: str, default: str | int) -> str | int:
    # Accept explicit assignment forms such as name = "..." or decimals = 18.
    if isinstance(default, str):
        m = re.search(rf"\b{re.escape(key)}\s*=\s*\"([^\"]+)\"", source)
        return m.group(1) if m else default
    m = re.search(rf"\b{re.escape(key)}\s*=\s*([0-9_]+)", source)
    return int(m.group(1).replace("_", "")) if m else int(default)


def _looks_like_token_contract(source: str) -> bool:
    lower = source.lower()
    return (
        "totalsupply" in lower
        and "balanceof" in lower
        and "transfer(" in lower
        and "mapping" in lower
    )


def _compile_token_contract(source: str, *, chain_id: int, name: str) -> Dict[str, Any]:
    token_name = str(_parse_token_constant(source, "name", _TOKEN_NAME))[:32]
    token_symbol = str(_parse_token_constant(source, "symbol", _TOKEN_SYMBOL))[:32]
    decimals = int(_parse_token_constant(source, "decimals", _TOKEN_DECIMALS))
    total_supply = int(_parse_token_constant(source, "totalSupply", _TOKEN_SUPPLY))
    if decimals < 0 or decimals > 255:
        raise AgilangContractCompileError("token decimals must fit uint8")
    runtime = _token_runtime_bytecode(name_text=token_name, symbol_text=token_symbol, version_text=f"{name} v1.0"[:32], decimals=decimals)
    creation = _token_creation_bytecode(runtime, total_supply=total_supply)
    abi = [
        {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "name", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "symbol", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "decimals", "inputs": [], "outputs": [{"name": "", "type": "uint8"}], "stateMutability": "view"},
        {"type": "function", "name": "totalSupply", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "allowance", "inputs": [{"name": "tokenOwner", "type": "address"}, {"name": "spender", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "transfer", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "approve", "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "transferFrom", "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "version", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "pure"},
        {"type": "event", "name": "Transfer", "inputs": [{"name": "from", "type": "address", "indexed": True}, {"name": "to", "type": "address", "indexed": True}, {"name": "value", "type": "uint256", "indexed": False}], "anonymous": False},
        {"type": "event", "name": "Approval", "inputs": [{"name": "owner", "type": "address", "indexed": True}, {"name": "spender", "type": "address", "indexed": True}, {"name": "value", "type": "uint256", "indexed": False}], "anonymous": False},
    ]
    selectors = {sig: evm_function_selector(sig) for sig in (
        "name()", "symbol()", "decimals()", "totalSupply()", "owner()", "balanceOf(address)",
        "allowance(address,address)", "transfer(address,uint256)", "approve(address,uint256)",
        "transferFrom(address,address,uint256)", "version()",
    )}
    generated_source = f"""// Generated by {COMPILER_VERSION}
// Target EVM fork: shanghai
// This generated representation is the verified token semantics emitted by
// the AGILANG native compiler, not only the compact template source.
contract {name} {{
  string public name = "{token_name}";
  string public symbol = "{token_symbol}";
  uint8 public decimals = {decimals};
  uint256 public totalSupply = {total_supply};
  address public owner = msg.sender;
  mapping(address => uint256) balances;
  mapping(address => mapping(address => uint256)) allowances;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  constructor() nonpayable {{
    balances[msg.sender] = totalSupply;
    emit Transfer(address(0), msg.sender, totalSupply);
  }}

  function balanceOf(address account) public view returns (uint256) {{
    require(account == address(uint160(account)));
    return balances[account];
  }}

  function allowance(address tokenOwner, address spender) public view returns (uint256) {{
    require(tokenOwner == address(uint160(tokenOwner)));
    require(spender == address(uint160(spender)));
    return allowances[tokenOwner][spender];
  }}

  function transfer(address to, uint256 amount) public nonpayable returns (bool) {{
    require(to != address(0));
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
    emit Transfer(msg.sender, to, amount);
    return true;
  }}

  function approve(address spender, uint256 amount) public nonpayable returns (bool) {{
    require(spender != address(0));
    allowances[msg.sender][spender] = amount;
    emit Approval(msg.sender, spender, amount);
    return true;
  }}

  function transferFrom(address from, address to, uint256 amount) public nonpayable returns (bool) {{
    require(from != address(0));
    require(to != address(0));
    require(balances[from] >= amount);
    require(allowances[from][msg.sender] >= amount);
    allowances[from][msg.sender] -= amount;
    balances[from] -= amount;
    balances[to] += amount;
    emit Transfer(from, to, amount);
    return true;
  }}

  function version() public pure returns (string memory) {{
    return "{name} v1.0";
  }}
}}"""
    return {
        "ok": True,
        "language": "AGILANG",
        "target": "evm",
        "chainId": int(chain_id),
        "contractName": name,
        "contractKind": "erc20-token",
        "compilerVersion": COMPILER_VERSION,
        "compiler": COMPILER_VERSION,
        "evmVersion": "shanghai",
        "optimization": False,
        "abi": abi,
        "bytecode": "0x" + creation.hex(),
        "runtimeBytecode": "0x" + runtime.hex(),
        "sourceCode": source,
        "generatedSource": generated_source,
        "token": {
            "name": token_name,
            "symbol": token_symbol,
            "decimals": decimals,
            "totalSupply": str(total_supply),
        },
        "storageLayout": {"totalSupply": 0, "owner": 1, "balances": 5, "allowances": 6},
        "functionSelectors": selectors,
        "events": {
            "Transfer(address,address,uint256)": evm_keccak("Transfer(address,address,uint256)"),
            "Approval(address,address,uint256)": evm_keccak("Approval(address,address,uint256)"),
        },
        "crossChain": {
            "compatibleTarget": "EVM",
            "deploymentMode": "signed-raw-transaction",
            "testnets": [
                {"name": "Smart Chain", "chainId": 1923},
                {"name": "Ethereum Sepolia", "chainId": 11155111},
                {"name": "Polygon Amoy", "chainId": 80002},
                {"name": "Base Sepolia", "chainId": 84532},
                {"name": "BNB Smart Chain Testnet", "chainId": 97},
            ],
        },
    }


def _compile_counter_contract(source: str, *, chain_id: int, name: str) -> Dict[str, Any]:
    if "increment" not in source or "counter" not in source:
        raise AgilangContractCompileError("native compiler expects a supported AGILANG contract shape")
    version_text = f"{name} v1.0"
    runtime = _counter_runtime_bytecode(version_text[:32])
    creation = _counter_creation_bytecode(runtime)
    abi = [
        {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "counter", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "version", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "pure"},
        {"type": "function", "name": "increment", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "nonpayable"},
        {"type": "event", "name": "CounterIncremented", "inputs": [{"name": "sender", "type": "address", "indexed": True}, {"name": "newCounter", "type": "uint256", "indexed": False}], "anonymous": False},
    ]
    return {
        "ok": True,
        "language": "AGILANG",
        "target": "evm",
        "chainId": int(chain_id),
        "contractName": name,
        "contractKind": "counter-proof",
        "compilerVersion": COMPILER_VERSION,
        "compiler": COMPILER_VERSION,
        "evmVersion": "shanghai",
        "optimization": False,
        "abi": abi,
        "bytecode": "0x" + creation.hex(),
        "runtimeBytecode": "0x" + runtime.hex(),
        "sourceCode": source,
        "generatedSource": f"""// Generated by {COMPILER_VERSION}
// Target EVM fork: shanghai
contract {name} {{
  uint256 public counter;
  address public owner = msg.sender;
  event CounterIncremented(address indexed sender, uint256 newCounter);

  function increment() public nonpayable returns (uint256) {{
    counter = counter + 1;
    emit CounterIncremented(msg.sender, counter);
    return counter;
  }}
}}""",
        "storageLayout": {"counter": 0, "owner": 1},
        "functionSelectors": {
            "counter()": evm_function_selector("counter()"),
            "increment()": evm_function_selector("increment()"),
            "owner()": evm_function_selector("owner()"),
            "version()": evm_function_selector("version()"),
        },
        "events": {"CounterIncremented(address,uint256)": evm_keccak("CounterIncremented(address,uint256)")},
    }


def compile_agilang_contract(source: str, *, chain_id: int = 1923) -> Dict[str, Any]:
    """Compile AGILANG contract source into ABI and EVM-compatible bytecode."""

    if "pragma solidity" in source.lower():
        raise AgilangContractCompileError(
            "This builder uses the native AGILANG compiler. Use AGILANG contract syntax, not Solidity pragma syntax."
        )

    from .agilang_advanced_contract_compiler import (
        compile_advanced_agilang_contract,
        detect_advanced_contract_kind,
    )
    from .agilang_secure_contract_compiler import (
        compile_secure_agilang_contract,
        detect_secure_contract_kind,
    )

    advanced_kind = detect_advanced_contract_kind(source)
    if advanced_kind:
        return compile_advanced_agilang_contract(source, chain_id=chain_id, kind=advanced_kind)

    secure_kind = detect_secure_contract_kind(source)
    if secure_kind:
        return compile_secure_agilang_contract(source, chain_id=chain_id, kind=secure_kind)

    name = _contract_name(source)
    if _looks_like_token_contract(source):
        # Legacy unmarked ERC20 source remains on the original compiler slice
        # so previously deployed contracts can be reproduced byte-for-byte.
        return _compile_token_contract(source, chain_id=chain_id, name=name)
    return _compile_counter_contract(source, chain_id=chain_id, name=name)


def contract_template_catalog() -> List[Dict[str, Any]]:
    from .agilang_advanced_contract_compiler import advanced_contract_template_catalog
    from .agilang_secure_contract_compiler import secure_contract_template_catalog
    return secure_contract_template_catalog() + advanced_contract_template_catalog()


__all__ = [
    "AgilangContractCompileError",
    "compile_agilang_contract",
    "contract_template_catalog",
]
