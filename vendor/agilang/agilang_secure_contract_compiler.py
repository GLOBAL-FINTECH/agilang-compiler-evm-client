"""Secure AGILANG contract templates compiled directly to EVM bytecode.

This module adds production-oriented, template-driven contract profiles to the
native AGILANG compiler. It never invokes Solidity or solc. The templates are
conservative by design: ownership is two-step, state-changing entry points are
non-payable, zero-address inputs are checked, and the flash-loan profile uses a
reentrancy guard plus post-callback balance accounting.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .evm import evm_function_selector, evm_keccak
from .agilang_contract_compiler import (
    AgilangContractCompileError,
    COMPILER_VERSION,
    _ADDRESS_MASK,
    _Assembler,
    _contract_name,
    _emit_copy_runtime_return_prefix,
    _emit_mapping_slot_from_caller,
    _emit_mapping_slot_from_calldata,
    _emit_mapping_slot_from_stack_word,
    _emit_nested_allowance_slot,
    _emit_revert,
    _emit_revert_if_calldata_shorter_than,
    _emit_revert_if_callvalue,
    _emit_revert_if_noncanonical_address_at,
    _emit_return_bool_true,
    _emit_return_string,
    _emit_return_uint_const,
    _emit_return_uint_slot,
    _parse_token_constant,
    _selector,
    _topic,
)

WORD_MASK = (1 << 256) - 1
ZERO_ADDRESS = 0

# Storage slots used by secure ERC20 profiles.
ERC20_TOTAL_SUPPLY = 0
ERC20_OWNER = 1
ERC20_CAP = 2
ERC20_PENDING_OWNER = 3
ERC20_PAUSED = 4
ERC20_BALANCES = 5
ERC20_ALLOWANCES = 6

# Storage slots used by secure ERC721 profiles.
ERC721_OWNER = 0
ERC721_PENDING_OWNER = 1
ERC721_PAUSED = 2
ERC721_NEXT_TOKEN_ID = 3
ERC721_BALANCES = 4
ERC721_OWNERS = 5
ERC721_APPROVALS = 6
ERC721_OPERATORS = 7

# Storage slots used by the ERC3156 lender.
FLASH_OWNER = 0
FLASH_PENDING_OWNER = 1
FLASH_TOKEN = 2
FLASH_FEE_BPS = 3
FLASH_PAUSED = 4
FLASH_REENTRANCY = 5


def _unique(asm: _Assembler, prefix: str) -> str:
    return f"{prefix}_{len(asm.code)}_{len(asm.fixups)}"


def _require_owner(asm: _Assembler, slot: int) -> None:
    asm.push(slot).op("SLOAD").op("CALLER").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")


def _require_not_paused(asm: _Assembler, slot: int) -> None:
    asm.push(slot).op("SLOAD").push_label("revert").op("JUMPI")


def _require_address_nonzero_at(asm: _Assembler, calldata_offset: int) -> None:
    _emit_revert_if_noncanonical_address_at(asm, calldata_offset)
    asm.push(calldata_offset).op("CALLDATALOAD").op("ISZERO").push_label("revert").op("JUMPI")


def _emit_return_address_slot(asm: _Assembler, slot: int) -> None:
    _emit_return_uint_slot(asm, slot)


def _emit_nested_mapping_slot(asm: _Assembler, first_source: str, second_source: str, base_slot: int) -> None:
    if first_source == "caller":
        asm.op("CALLER")
    elif first_source == "address":
        asm.op("ADDRESS")
    else:
        asm.push(int(first_source)).op("CALLDATALOAD")
    _emit_mapping_slot_from_stack_word(asm, base_slot)
    asm.push(32).op("MSTORE")
    if second_source == "caller":
        asm.op("CALLER")
    elif second_source == "address":
        asm.op("ADDRESS")
    else:
        asm.push(int(second_source)).op("CALLDATALOAD")
    asm.push(0).op("MSTORE")
    asm.push(64).push(0).op("SHA3")


def _emit_two_step_ownership_handlers(asm: _Assembler, owner_slot: int, pending_slot: int) -> None:
    asm.label("transferOwnership")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    _require_owner(asm, owner_slot)
    _require_address_nonzero_at(asm, 4)
    asm.push(4).op("CALLDATALOAD").push(pending_slot).op("SSTORE")
    _emit_return_bool_true(asm)

    asm.label("acceptOwnership")
    asm.push(pending_slot).op("SLOAD").op("CALLER").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    asm.op("CALLER").push(owner_slot).op("SSTORE")
    asm.push(0).push(pending_slot).op("SSTORE")
    _emit_return_bool_true(asm)


def _parse_marker(source: str) -> str:
    patterns = [
        r"@secure_template\s+([A-Za-z0-9_\-]+)",
        r"@contract_type\s+([A-Za-z0-9_\-]+)",
        r"@template\s+([A-Za-z0-9_\-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, source, re.IGNORECASE)
        if match:
            return match.group(1).strip().lower().replace("_", "-")
    return ""


def detect_secure_contract_kind(source: str) -> str:
    marker = _parse_marker(source)
    aliases = {
        "erc20": "erc20-fixed",
        "erc20-fixed": "erc20-fixed",
        "erc20-mintable": "erc20-mintable",
        "erc20-burnable": "erc20-burnable",
        "erc20-mintable-burnable": "erc20-mintable-burnable",
        "erc20-secure": "erc20-secure",
        "erc20-capped-pausable": "erc20-secure",
        "nft": "erc721-secure",
        "erc721": "erc721-secure",
        "erc721-secure": "erc721-secure",
        "erc721-mintable-burnable": "erc721-secure",
        "flash-loan": "erc3156-flash-lender",
        "erc3156": "erc3156-flash-lender",
        "erc3156-flash-lender": "erc3156-flash-lender",
    }
    if marker in aliases:
        return aliases[marker]

    lower = source.lower()
    if "flashloan(" in lower and "maxflashloan" in lower:
        return "erc3156-flash-lender"
    if "ownerof(" in lower and "setapprovalforall" in lower:
        return "erc721-secure"
    if "totalsupply" in lower and "balanceof" in lower and "transfer(" in lower:
        mintable = "function mint(" in lower
        burnable = "function burn(" in lower
        pausable = "function pause(" in lower or "paused:" in lower
        capped = "cap:" in lower or "function cap(" in lower
        if pausable or capped:
            return "erc20-secure"
        if mintable and burnable:
            return "erc20-mintable-burnable"
        if mintable:
            return "erc20-mintable"
        if burnable:
            return "erc20-burnable"
        # Unmarked plain ERC20 source is intentionally left to the legacy
        # compiler slice so previously deployed contracts remain exactly
        # reproducible. New secure fixed-supply contracts use the explicit
        # @secure_template ERC20_FIXED marker.
        return ""
    return ""


def _parse_address_constant(source: str, key: str) -> int:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*(0x[0-9a-fA-F]{{40}})", source)
    if not match:
        raise AgilangContractCompileError(f"{key} must be assigned a 20-byte EVM address")
    value = int(match.group(1), 16)
    if value == 0:
        raise AgilangContractCompileError(f"{key} cannot be the zero address")
    return value


def _template_sources() -> Dict[str, Dict[str, Any]]:
    return {
        "erc20-fixed": {
            "title": "ERC20 fixed supply",
            "category": "Fungible tokens",
            "standard": "ERC-20",
            "risk": "standard",
            "description": "Fixed supply token with two-step ownership and safer allowance helpers.",
            "source": '''// @secure_template ERC20_FIXED
contract SecureFixedToken {
    name: string
    symbol: string
    decimals: uint8
    totalSupply: uint256
    owner: address
    balances: mapping(address => uint256)
    allowances: mapping(address => mapping(address => uint256))

    constructor() {
        name = "Secure Fixed Token"
        symbol = "SFT"
        decimals = 18
        totalSupply = 1000000000000000000000000
        owner = msg.sender
        balances[msg.sender] = totalSupply
    }

    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function allowance(tokenOwner: address, spender: address) returns uint256 { return allowances[tokenOwner][spender] }
    public function transfer(to: address, amount: uint256) returns bool { return true }
    public function approve(spender: address, amount: uint256) returns bool { return true }
    public function transferFrom(from: address, to: address, amount: uint256) returns bool { return true }
}
''',
        },
        "erc20-mintable": {
            "title": "ERC20 mintable",
            "category": "Fungible tokens",
            "standard": "ERC-20 + owner minting",
            "risk": "privileged",
            "description": "Owner-controlled minting with a supply cap and two-step ownership.",
            "source": '''// @secure_template ERC20_MINTABLE
contract MintableToken {
    name: string
    symbol: string
    decimals: uint8
    totalSupply: uint256
    cap: uint256
    owner: address
    balances: mapping(address => uint256)
    allowances: mapping(address => mapping(address => uint256))

    constructor() {
        name = "Mintable Token"
        symbol = "MINT"
        decimals = 18
        totalSupply = 100000000000000000000000
        cap = 1000000000000000000000000
        owner = msg.sender
        balances[msg.sender] = totalSupply
    }

    public function mint(to: address, amount: uint256) returns bool { return true }
    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function allowance(tokenOwner: address, spender: address) returns uint256 { return allowances[tokenOwner][spender] }
    public function transfer(to: address, amount: uint256) returns bool { return true }
    public function approve(spender: address, amount: uint256) returns bool { return true }
    public function transferFrom(from: address, to: address, amount: uint256) returns bool { return true }
}
''',
        },
        "erc20-burnable": {
            "title": "ERC20 burnable",
            "category": "Fungible tokens",
            "standard": "ERC-20 + burn",
            "risk": "standard",
            "description": "Fixed supply ERC20 with holder burn and allowance-based burnFrom.",
            "source": '''// @secure_template ERC20_BURNABLE
contract BurnableToken {
    name: string
    symbol: string
    decimals: uint8
    totalSupply: uint256
    owner: address
    balances: mapping(address => uint256)
    allowances: mapping(address => mapping(address => uint256))

    constructor() {
        name = "Burnable Token"
        symbol = "BURN"
        decimals = 18
        totalSupply = 1000000000000000000000000
        owner = msg.sender
        balances[msg.sender] = totalSupply
    }

    public function burn(amount: uint256) returns bool { return true }
    public function burnFrom(account: address, amount: uint256) returns bool { return true }
    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function allowance(tokenOwner: address, spender: address) returns uint256 { return allowances[tokenOwner][spender] }
    public function transfer(to: address, amount: uint256) returns bool { return true }
    public function approve(spender: address, amount: uint256) returns bool { return true }
    public function transferFrom(from: address, to: address, amount: uint256) returns bool { return true }
}
''',
        },
        "erc20-mintable-burnable": {
            "title": "ERC20 mintable and burnable",
            "category": "Fungible tokens",
            "standard": "ERC-20 + mint + burn",
            "risk": "privileged",
            "description": "Capped owner minting plus holder burning and two-step ownership.",
            "source": '''// @secure_template ERC20_MINTABLE_BURNABLE
contract MintBurnToken {
    name: string
    symbol: string
    decimals: uint8
    totalSupply: uint256
    cap: uint256
    owner: address
    balances: mapping(address => uint256)
    allowances: mapping(address => mapping(address => uint256))

    constructor() {
        name = "Mint Burn Token"
        symbol = "MBT"
        decimals = 18
        totalSupply = 100000000000000000000000
        cap = 1000000000000000000000000
        owner = msg.sender
        balances[msg.sender] = totalSupply
    }

    public function mint(to: address, amount: uint256) returns bool { return true }
    public function burn(amount: uint256) returns bool { return true }
    public function burnFrom(account: address, amount: uint256) returns bool { return true }
    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function allowance(tokenOwner: address, spender: address) returns uint256 { return allowances[tokenOwner][spender] }
    public function transfer(to: address, amount: uint256) returns bool { return true }
    public function approve(spender: address, amount: uint256) returns bool { return true }
    public function transferFrom(from: address, to: address, amount: uint256) returns bool { return true }
}
''',
        },
        "erc20-secure": {
            "title": "ERC20 capped, mintable, burnable and pausable",
            "category": "Fungible tokens",
            "standard": "ERC-20 secure profile",
            "risk": "privileged",
            "description": "Full secure token profile with capped minting, burning, pausing, and two-step ownership.",
            "source": '''// @secure_template ERC20_SECURE
contract SecureManagedToken {
    name: string
    symbol: string
    decimals: uint8
    totalSupply: uint256
    cap: uint256
    owner: address
    paused: bool
    balances: mapping(address => uint256)
    allowances: mapping(address => mapping(address => uint256))

    constructor() {
        name = "Secure Managed Token"
        symbol = "SMT"
        decimals = 18
        totalSupply = 100000000000000000000000
        cap = 1000000000000000000000000
        owner = msg.sender
        paused = false
        balances[msg.sender] = totalSupply
    }

    public function mint(to: address, amount: uint256) returns bool { return true }
    public function burn(amount: uint256) returns bool { return true }
    public function burnFrom(account: address, amount: uint256) returns bool { return true }
    public function pause() returns bool { return true }
    public function unpause() returns bool { return true }
    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function allowance(tokenOwner: address, spender: address) returns uint256 { return allowances[tokenOwner][spender] }
    public function transfer(to: address, amount: uint256) returns bool { return true }
    public function approve(spender: address, amount: uint256) returns bool { return true }
    public function transferFrom(from: address, to: address, amount: uint256) returns bool { return true }
}
''',
        },
        "erc721-secure": {
            "title": "ERC721 NFT mintable and burnable",
            "category": "Non-fungible tokens",
            "standard": "ERC-721 core + ERC-165",
            "risk": "privileged",
            "description": "NFT ownership, approvals, safe transfers, owner minting, holder burning, and pausing.",
            "source": '''// @secure_template ERC721_SECURE
contract SecureNFT {
    name: string
    symbol: string
    owner: address
    paused: bool
    balances: mapping(address => uint256)
    owners: mapping(uint256 => address)
    approvals: mapping(uint256 => address)
    operators: mapping(address => mapping(address => bool))

    constructor() {
        name = "Secure NFT"
        symbol = "SNFT"
        owner = msg.sender
        paused = false
    }

    public view function supportsInterface(interfaceId: bytes4) returns bool { return true }
    public view function balanceOf(account: address) returns uint256 { return balances[account] }
    public view function ownerOf(tokenId: uint256) returns address { return owners[tokenId] }
    public function approve(to: address, tokenId: uint256) returns bool { return true }
    public function setApprovalForAll(operator: address, approved: bool) returns bool { return true }
    public function transferFrom(from: address, to: address, tokenId: uint256) returns bool { return true }
    public function safeTransferFrom(from: address, to: address, tokenId: uint256) returns bool { return true }
    public function mint(to: address, tokenId: uint256) returns bool { return true }
    public function burn(tokenId: uint256) returns bool { return true }
    public function pause() returns bool { return true }
    public function unpause() returns bool { return true }
}
''',
        },
        "erc3156-flash-lender": {
            "title": "ERC3156 guarded flash-loan lender",
            "category": "DeFi infrastructure",
            "standard": "ERC-3156",
            "risk": "advanced",
            "description": "Single-asset lender with callback validation, fee accounting, post-loan balance checks, pausing, and reentrancy protection.",
            "source": '''// @secure_template ERC3156_FLASH_LENDER
contract GuardedFlashLender {
    owner: address
    pendingOwner: address
    assetToken: address
    feeBps: uint256
    paused: bool
    reentrancyLock: uint256

    constructor() {
        owner = msg.sender
        assetToken = 0x1111111111111111111111111111111111111111
        feeBps = 5
        paused = false
        reentrancyLock = 1
    }

    public view function maxFlashLoan(token: address) returns uint256 { return 0 }
    public view function flashFee(token: address, amount: uint256) returns uint256 { return 0 }
    public function flashLoan(receiver: address, token: address, amount: uint256, data: bytes) returns bool { return true }
    public function pause() returns bool { return true }
    public function unpause() returns bool { return true }
    public function setFeeBps(newFeeBps: uint256) returns bool { return true }
    public function withdraw(to: address, amount: uint256) returns bool { return true }
}
''',
        },
    }


def secure_contract_template_catalog() -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for kind, item in _template_sources().items():
        row = dict(item)
        row["kind"] = kind
        row["source"] = item["source"]
        row["maturity"] = "reference-core" if row.get("risk") != "advanced" else "experimental"
        output.append(row)
    return output


def _erc20_features(kind: str) -> Dict[str, bool]:
    return {
        "mintable": kind in {"erc20-mintable", "erc20-mintable-burnable", "erc20-secure"},
        "burnable": kind in {"erc20-burnable", "erc20-mintable-burnable", "erc20-secure"},
        "pausable": kind == "erc20-secure",
        "capped": kind in {"erc20-mintable", "erc20-mintable-burnable", "erc20-secure"},
    }


def _erc20_abi(features: Dict[str, bool]) -> List[Dict[str, Any]]:
    abi: List[Dict[str, Any]] = [
        {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "name", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "symbol", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "decimals", "inputs": [], "outputs": [{"name": "", "type": "uint8"}], "stateMutability": "view"},
        {"type": "function", "name": "totalSupply", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "pendingOwner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "transferOwnership", "inputs": [{"name": "newOwner", "type": "address"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "acceptOwnership", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "allowance", "inputs": [{"name": "tokenOwner", "type": "address"}, {"name": "spender", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "transfer", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "approve", "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "increaseAllowance", "inputs": [{"name": "spender", "type": "address"}, {"name": "addedValue", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "decreaseAllowance", "inputs": [{"name": "spender", "type": "address"}, {"name": "subtractedValue", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "transferFrom", "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "event", "name": "Transfer", "inputs": [{"name": "from", "type": "address", "indexed": True}, {"name": "to", "type": "address", "indexed": True}, {"name": "value", "type": "uint256", "indexed": False}], "anonymous": False},
        {"type": "event", "name": "Approval", "inputs": [{"name": "owner", "type": "address", "indexed": True}, {"name": "spender", "type": "address", "indexed": True}, {"name": "value", "type": "uint256", "indexed": False}], "anonymous": False},
    ]
    if features["capped"]:
        abi.append({"type": "function", "name": "cap", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"})
    if features["pausable"]:
        abi.extend([
            {"type": "function", "name": "paused", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view"},
            {"type": "function", "name": "pause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "function", "name": "unpause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        ])
    if features["mintable"]:
        abi.append({"type": "function", "name": "mint", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"})
    if features["burnable"]:
        abi.extend([
            {"type": "function", "name": "burn", "inputs": [{"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "function", "name": "burnFrom", "inputs": [{"name": "account", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        ])
    return abi


def _erc20_runtime(name_text: str, symbol_text: str, decimals: int, features: Dict[str, bool], contract_name: str) -> bytes:
    transfer_topic = _topic("Transfer(address,address,uint256)")
    approval_topic = _topic("Approval(address,address,uint256)")
    asm = _Assembler()
    _emit_revert_if_callvalue(asm)
    _emit_revert_if_calldata_shorter_than(asm, 4)
    asm.push(0).op("CALLDATALOAD").push(224).op("SHR")

    handlers: List[Tuple[str, str]] = [
        ("name()", "name"), ("symbol()", "symbol"), ("decimals()", "decimals"),
        ("totalSupply()", "totalSupply"), ("owner()", "owner"),
        ("pendingOwner()", "pendingOwner"), ("transferOwnership(address)", "transferOwnership"),
        ("acceptOwnership()", "acceptOwnership"), ("balanceOf(address)", "balanceOf"),
        ("allowance(address,address)", "allowance"), ("transfer(address,uint256)", "transfer"),
        ("approve(address,uint256)", "approve"), ("increaseAllowance(address,uint256)", "increaseAllowance"),
        ("decreaseAllowance(address,uint256)", "decreaseAllowance"),
        ("transferFrom(address,address,uint256)", "transferFrom"), ("version()", "version"),
    ]
    if features["capped"]:
        handlers.append(("cap()", "cap"))
    if features["pausable"]:
        handlers.extend([("paused()", "paused"), ("pause()", "pause"), ("unpause()", "unpause")])
    if features["mintable"]:
        handlers.append(("mint(address,uint256)", "mint"))
    if features["burnable"]:
        handlers.extend([("burn(uint256)", "burn"), ("burnFrom(address,uint256)", "burnFrom")])

    for signature, label in handlers:
        asm.op("DUP1").push(_selector(signature)).op("EQ").push_label(label).op("JUMPI")
    asm.op("POP")
    _emit_revert(asm)

    asm.label("name"); _emit_return_string(asm, name_text)
    asm.label("symbol"); _emit_return_string(asm, symbol_text)
    asm.label("decimals"); _emit_return_uint_const(asm, decimals)
    asm.label("totalSupply"); _emit_return_uint_slot(asm, ERC20_TOTAL_SUPPLY)
    asm.label("owner"); _emit_return_address_slot(asm, ERC20_OWNER)
    asm.label("pendingOwner"); _emit_return_address_slot(asm, ERC20_PENDING_OWNER)
    asm.label("version"); _emit_return_string(asm, f"{contract_name} v1.0"[:32])
    if features["capped"]:
        asm.label("cap"); _emit_return_uint_slot(asm, ERC20_CAP)
    if features["pausable"]:
        asm.label("paused"); _emit_return_uint_slot(asm, ERC20_PAUSED)

    asm.label("balanceOf")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 4, ERC20_BALANCES)
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("allowance")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_revert_if_noncanonical_address_at(asm, 36)
    _emit_nested_allowance_slot(asm, "4", "36")
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    _emit_two_step_ownership_handlers(asm, ERC20_OWNER, ERC20_PENDING_OWNER)

    asm.label("transfer")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    if features["pausable"]: _require_not_paused(asm, ERC20_PAUSED)
    _require_address_nonzero_at(asm, 4)
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_mapping_slot_from_caller(asm, ERC20_BALANCES)
    asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
    _emit_mapping_slot_from_calldata(asm, 4, ERC20_BALANCES)
    asm.op("DUP1").push(0xE0).op("MSTORE").op("SLOAD").op("DUP1").push(0x100).op("MSTORE")
    asm.push(0xA0).op("MLOAD").op("ADD").op("DUP1").push(0x120).op("MSTORE")
    asm.push(0x100).op("MLOAD").push(0x120).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0x120).op("MLOAD").push(0xE0).op("MLOAD").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(transfer_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("approve")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _require_address_nonzero_at(asm, 4)
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_nested_allowance_slot(asm, "caller", "4")
    asm.push(0xA0).op("MLOAD").op("SWAP1").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(approval_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("increaseAllowance")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _require_address_nonzero_at(asm, 4)
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_nested_allowance_slot(asm, "caller", "4")
    asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    asm.push(0xA0).op("MLOAD").op("ADD").op("DUP1").push(0xE0).op("MSTORE")
    asm.push(0xC0).op("MLOAD").push(0xE0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0xE0).op("MLOAD").push(0x80).op("MLOAD").op("SSTORE")
    asm.push(0xE0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(approval_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("decreaseAllowance")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _require_address_nonzero_at(asm, 4)
    asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_nested_allowance_slot(asm, "caller", "4")
    asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").op("DUP1").push(0xE0).op("MSTORE")
    asm.push(0x80).op("MLOAD").op("SSTORE")
    asm.push(0xE0).op("MLOAD").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(approval_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("transferFrom")
    _emit_revert_if_calldata_shorter_than(asm, 100)
    if features["pausable"]: _require_not_paused(asm, ERC20_PAUSED)
    _require_address_nonzero_at(asm, 4)
    _require_address_nonzero_at(asm, 36)
    asm.push(68).op("CALLDATALOAD").push(0xA0).op("MSTORE")
    _emit_mapping_slot_from_calldata(asm, 4, ERC20_BALANCES)
    asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    _emit_nested_mapping_slot(asm, "4", "caller", ERC20_ALLOWANCES)
    asm.op("DUP1").push(0x120).op("MSTORE").op("SLOAD").op("DUP1").push(0x140).op("MSTORE")
    asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("SUB").push(0x120).op("MLOAD").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
    _emit_mapping_slot_from_calldata(asm, 36, ERC20_BALANCES)
    asm.op("DUP1").push(0xE0).op("MSTORE").op("SLOAD").op("DUP1").push(0x100).op("MSTORE")
    asm.push(0xA0).op("MLOAD").op("ADD").op("DUP1").push(0x160).op("MSTORE")
    asm.push(0x100).op("MLOAD").push(0x160).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0x160).op("MLOAD").push(0xE0).op("MLOAD").op("SSTORE")
    asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
    asm.push(36).op("CALLDATALOAD").push(4).op("CALLDATALOAD").push(transfer_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    if features["mintable"]:
        asm.label("mint")
        _emit_revert_if_calldata_shorter_than(asm, 68)
        _require_owner(asm, ERC20_OWNER)
        if features["pausable"]: _require_not_paused(asm, ERC20_PAUSED)
        _require_address_nonzero_at(asm, 4)
        asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
        asm.push(ERC20_TOTAL_SUPPLY).op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
        asm.push(0xA0).op("MLOAD").op("ADD").op("DUP1").push(0xE0).op("MSTORE")
        asm.push(0xC0).op("MLOAD").push(0xE0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
        if features["capped"]:
            asm.push(0xE0).op("MLOAD").push(ERC20_CAP).op("SLOAD").op("LT").push_label("revert").op("JUMPI")
        asm.push(0xE0).op("MLOAD").push(ERC20_TOTAL_SUPPLY).op("SSTORE")
        _emit_mapping_slot_from_calldata(asm, 4, ERC20_BALANCES)
        asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").push(0xA0).op("MLOAD").op("ADD")
        asm.push(0x80).op("MLOAD").op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
        asm.push(4).op("CALLDATALOAD").push(0).push(transfer_topic).push(32).push(0).op("LOG3")
        _emit_return_bool_true(asm)

    if features["burnable"]:
        asm.label("burn")
        _emit_revert_if_calldata_shorter_than(asm, 36)
        if features["pausable"]: _require_not_paused(asm, ERC20_PAUSED)
        asm.push(4).op("CALLDATALOAD").push(0xA0).op("MSTORE")
        _emit_mapping_slot_from_caller(asm, ERC20_BALANCES)
        asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
        asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
        asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(ERC20_TOTAL_SUPPLY).op("SLOAD").op("SUB").push(ERC20_TOTAL_SUPPLY).op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
        asm.push(0).op("CALLER").push(transfer_topic).push(32).push(0).op("LOG3")
        _emit_return_bool_true(asm)

        asm.label("burnFrom")
        _emit_revert_if_calldata_shorter_than(asm, 68)
        if features["pausable"]: _require_not_paused(asm, ERC20_PAUSED)
        _require_address_nonzero_at(asm, 4)
        asm.push(36).op("CALLDATALOAD").push(0xA0).op("MSTORE")
        _emit_mapping_slot_from_calldata(asm, 4, ERC20_BALANCES)
        asm.op("DUP1").push(0x80).op("MSTORE").op("SLOAD").op("DUP1").push(0xC0).op("MSTORE")
        asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
        _emit_nested_mapping_slot(asm, "4", "caller", ERC20_ALLOWANCES)
        asm.op("DUP1").push(0x120).op("MSTORE").op("SLOAD").op("DUP1").push(0x140).op("MSTORE")
        asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
        asm.push(0xA0).op("MLOAD").push(0x140).op("MLOAD").op("SUB").push(0x120).op("MLOAD").op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(0xC0).op("MLOAD").op("SUB").push(0x80).op("MLOAD").op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(ERC20_TOTAL_SUPPLY).op("SLOAD").op("SUB").push(ERC20_TOTAL_SUPPLY).op("SSTORE")
        asm.push(0xA0).op("MLOAD").push(0).op("MSTORE")
        asm.push(0).push(4).op("CALLDATALOAD").push(transfer_topic).push(32).push(0).op("LOG3")
        _emit_return_bool_true(asm)

    if features["pausable"]:
        asm.label("pause")
        _require_owner(asm, ERC20_OWNER)
        asm.push(ERC20_PAUSED).op("SLOAD").push_label("revert").op("JUMPI")
        asm.push(1).push(ERC20_PAUSED).op("SSTORE")
        _emit_return_bool_true(asm)

        asm.label("unpause")
        _require_owner(asm, ERC20_OWNER)
        asm.push(ERC20_PAUSED).op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI")
        asm.push(0).push(ERC20_PAUSED).op("SSTORE")
        _emit_return_bool_true(asm)

    asm.label("revert")
    _emit_revert(asm)
    return asm.finish()


def _erc20_creation(runtime: bytes, total_supply: int, cap: int) -> bytes:
    asm = _Assembler()
    _emit_revert_if_callvalue(asm)
    asm.push(total_supply).push(ERC20_TOTAL_SUPPLY).op("SSTORE")
    asm.op("CALLER").push(ERC20_OWNER).op("SSTORE")
    asm.push(cap).push(ERC20_CAP).op("SSTORE")
    asm.push(0).push(ERC20_PENDING_OWNER).op("SSTORE")
    asm.push(0).push(ERC20_PAUSED).op("SSTORE")
    asm.op("CALLER")
    _emit_mapping_slot_from_stack_word(asm, ERC20_BALANCES)
    asm.push(total_supply).op("SWAP1").op("SSTORE")
    asm.push(total_supply).push(0).op("MSTORE")
    asm.op("CALLER").push(0).push(_topic("Transfer(address,address,uint256)")).push(32).push(0).op("LOG3")
    return _emit_copy_runtime_return_prefix(runtime, bytearray(asm.finish()))


def _compile_erc20(source: str, chain_id: int, kind: str) -> Dict[str, Any]:
    name = _contract_name(source)
    features = _erc20_features(kind)
    token_name = str(_parse_token_constant(source, "name", "AGILANG Secure Token"))[:32]
    symbol = str(_parse_token_constant(source, "symbol", "AGT"))[:32]
    decimals = int(_parse_token_constant(source, "decimals", 18))
    total_supply = int(_parse_token_constant(source, "totalSupply", 1_000_000 * 10**18))
    cap = int(_parse_token_constant(source, "cap", total_supply if not features["capped"] else max(total_supply, 10_000_000 * 10**18)))
    if not 0 <= decimals <= 255:
        raise AgilangContractCompileError("token decimals must fit uint8")
    if total_supply < 0 or cap < total_supply:
        raise AgilangContractCompileError("token cap must be greater than or equal to initial supply")

    runtime = _erc20_runtime(token_name, symbol, decimals, features, name)
    creation = _erc20_creation(runtime, total_supply, cap)
    abi = _erc20_abi(features)
    selectors = {}
    for item in abi:
        if item.get("type") == "function":
            signature = item["name"] + "(" + ",".join(arg["type"] for arg in item.get("inputs", [])) + ")"
            selectors[signature] = evm_function_selector(signature)
    security = {
        "profile": "AGILANG-SECURE-ERC20/1.0",
        "risk": "privileged" if features["mintable"] or features["pausable"] else "standard",
        "controls": [
            "two-step ownership", "zero-address validation", "canonical address-word validation",
            "non-payable state changes", "checked balance and supply arithmetic",
            "increase/decrease allowance helpers",
        ] + (["supply cap"] if features["capped"] else []) + (["owner pause control"] if features["pausable"] else []),
        "privileged_functions": (["mint"] if features["mintable"] else []) + (["pause", "unpause"] if features["pausable"] else []),
        "warnings": ["Privileged owner keys should be controlled by a multisig or hardware-backed signer."],
    }
    generated = f"// Generated by {COMPILER_VERSION}\n// Secure profile: {security['profile']}\n// Contract kind: {kind}\ncontract {name} {{ /* Direct EVM implementation; see ABI and security metadata. */ }}"
    return {
        "ok": True, "language": "AGILANG", "target": "evm", "chainId": int(chain_id),
        "contractName": name, "contractKind": kind, "standard": "ERC-20",
        "compilerVersion": COMPILER_VERSION, "compiler": COMPILER_VERSION,
        "evmVersion": "shanghai", "optimization": False, "abi": abi,
        "bytecode": "0x" + creation.hex(), "runtimeBytecode": "0x" + runtime.hex(),
        "sourceCode": source, "generatedSource": generated,
        "token": {"name": token_name, "symbol": symbol, "decimals": decimals, "totalSupply": str(total_supply), "cap": str(cap)},
        "storageLayout": {"totalSupply": 0, "owner": 1, "cap": 2, "pendingOwner": 3, "paused": 4, "balances": 5, "allowances": 6},
        "functionSelectors": selectors,
        "events": {"Transfer(address,address,uint256)": evm_keccak("Transfer(address,address,uint256)"), "Approval(address,address,uint256)": evm_keccak("Approval(address,address,uint256)")},
        "security": security,
    }


# --------------------------- ERC721 compiler ---------------------------

def _erc721_abi() -> List[Dict[str, Any]]:
    return [
        {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "supportsInterface", "inputs": [{"name": "interfaceId", "type": "bytes4"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view"},
        {"type": "function", "name": "name", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "symbol", "inputs": [], "outputs": [{"name": "", "type": "string"}], "stateMutability": "view"},
        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "pendingOwner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "paused", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view"},
        {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "ownerOf", "inputs": [{"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "getApproved", "inputs": [{"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "isApprovedForAll", "inputs": [{"name": "tokenOwner", "type": "address"}, {"name": "operator", "type": "address"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view"},
        {"type": "function", "name": "approve", "inputs": [{"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "setApprovalForAll", "inputs": [{"name": "operator", "type": "address"}, {"name": "approved", "type": "bool"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "transferFrom", "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "safeTransferFrom", "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "mint", "inputs": [{"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "burn", "inputs": [{"name": "tokenId", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "pause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "unpause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "transferOwnership", "inputs": [{"name": "newOwner", "type": "address"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "acceptOwnership", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "event", "name": "Transfer", "inputs": [{"name": "from", "type": "address", "indexed": True}, {"name": "to", "type": "address", "indexed": True}, {"name": "tokenId", "type": "uint256", "indexed": True}], "anonymous": False},
        {"type": "event", "name": "Approval", "inputs": [{"name": "owner", "type": "address", "indexed": True}, {"name": "approved", "type": "address", "indexed": True}, {"name": "tokenId", "type": "uint256", "indexed": True}], "anonymous": False},
        {"type": "event", "name": "ApprovalForAll", "inputs": [{"name": "owner", "type": "address", "indexed": True}, {"name": "operator", "type": "address", "indexed": True}, {"name": "approved", "type": "bool", "indexed": False}], "anonymous": False},
    ]


def _emit_erc721_authorized(asm: _Assembler, token_calldata_offset: int, owner_mem: int = 0x220) -> None:
    authorized = _unique(asm, "nft_authorized")
    asm.push(owner_mem).op("MLOAD").op("CALLER").op("EQ").push_label(authorized).op("JUMPI")
    _emit_mapping_slot_from_calldata(asm, token_calldata_offset, ERC721_APPROVALS)
    asm.op("SLOAD").op("CALLER").op("EQ").push_label(authorized).op("JUMPI")
    # operator approval for owner => caller
    asm.push(owner_mem).op("MLOAD")
    _emit_mapping_slot_from_stack_word(asm, ERC721_OPERATORS)
    asm.push(32).op("MSTORE")
    asm.op("CALLER").push(0).op("MSTORE")
    asm.push(64).push(0).op("SHA3").op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI")
    asm.label(authorized)


def _emit_erc721_transfer_state(asm: _Assembler, from_offset: int, to_offset: int, token_offset: int) -> None:
    transfer_topic = _topic("Transfer(address,address,uint256)")
    _require_not_paused(asm, ERC721_PAUSED)
    _require_address_nonzero_at(asm, from_offset)
    _require_address_nonzero_at(asm, to_offset)
    # token owner slot and owner
    _emit_mapping_slot_from_calldata(asm, token_offset, ERC721_OWNERS)
    asm.op("DUP1").push(0x200).op("MSTORE").op("SLOAD").op("DUP1").push(0x220).op("MSTORE")
    asm.op("ISZERO").push_label("revert").op("JUMPI")
    # from must equal owner
    asm.push(from_offset).op("CALLDATALOAD").push(0x220).op("MLOAD").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    _emit_erc721_authorized(asm, token_offset)
    # clear token approval
    _emit_mapping_slot_from_calldata(asm, token_offset, ERC721_APPROVALS)
    asm.push(0).op("SWAP1").op("SSTORE")
    # from balance--
    _emit_mapping_slot_from_calldata(asm, from_offset, ERC721_BALANCES)
    asm.op("DUP1").push(0x240).op("MSTORE").op("SLOAD").op("DUP1").push(0x260).op("MSTORE")
    asm.op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(1).push(0x260).op("MLOAD").op("SUB").push(0x240).op("MLOAD").op("SSTORE")
    # to balance++ with overflow check
    _emit_mapping_slot_from_calldata(asm, to_offset, ERC721_BALANCES)
    asm.op("DUP1").push(0x280).op("MSTORE").op("SLOAD").op("DUP1").push(0x2A0).op("MSTORE")
    asm.push(1).op("ADD").op("DUP1").push(0x2C0).op("MSTORE")
    asm.push(0x2A0).op("MLOAD").push(0x2C0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(0x2C0).op("MLOAD").push(0x280).op("MLOAD").op("SSTORE")
    # owner[tokenId] = to
    asm.push(to_offset).op("CALLDATALOAD").push(0x200).op("MLOAD").op("SSTORE")
    # Transfer(from,to,tokenId) all indexed => LOG4, empty data
    asm.push(token_offset).op("CALLDATALOAD").push(to_offset).op("CALLDATALOAD").push(from_offset).op("CALLDATALOAD").push(transfer_topic).push(0).push(0).op("LOG4")


def _emit_safe_receiver_empty_data(asm: _Assembler, from_offset: int, to_offset: int, token_offset: int) -> None:
    done = _unique(asm, "receiver_done")
    asm.push(to_offset).op("CALLDATALOAD").op("EXTCODESIZE").op("ISZERO").push_label(done).op("JUMPI")
    # onERC721Received(address,address,uint256,bytes) with empty bytes
    asm.push(_selector("onERC721Received(address,address,uint256,bytes)") << 224).push(0).op("MSTORE")
    asm.op("CALLER").push(4).op("MSTORE")
    asm.push(from_offset).op("CALLDATALOAD").push(36).op("MSTORE")
    asm.push(token_offset).op("CALLDATALOAD").push(68).op("MSTORE")
    asm.push(128).push(100).op("MSTORE")
    asm.push(0).push(132).op("MSTORE")
    # CALL(gas,to,0,0,164,0x300,32)
    asm.push(32).push(0x300).push(164).push(0).push(0).push(to_offset).op("CALLDATALOAD").op("GAS").op("CALL")
    asm.op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(0x300).op("MLOAD").push(0x150B7A02 << 224).op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    asm.label(done)


def _erc721_runtime(name_text: str, symbol_text: str, contract_name: str) -> bytes:
    transfer_topic = _topic("Transfer(address,address,uint256)")
    approval_topic = _topic("Approval(address,address,uint256)")
    approval_all_topic = _topic("ApprovalForAll(address,address,bool)")
    asm = _Assembler()
    _emit_revert_if_callvalue(asm)
    _emit_revert_if_calldata_shorter_than(asm, 4)
    asm.push(0).op("CALLDATALOAD").push(224).op("SHR")
    handlers = [
        ("supportsInterface(bytes4)", "supportsInterface"), ("name()", "name"), ("symbol()", "symbol"),
        ("owner()", "owner"), ("pendingOwner()", "pendingOwner"), ("paused()", "paused"),
        ("balanceOf(address)", "balanceOf"), ("ownerOf(uint256)", "ownerOf"),
        ("getApproved(uint256)", "getApproved"), ("isApprovedForAll(address,address)", "isApprovedForAll"),
        ("approve(address,uint256)", "approve"), ("setApprovalForAll(address,bool)", "setApprovalForAll"),
        ("transferFrom(address,address,uint256)", "transferFrom"),
        ("safeTransferFrom(address,address,uint256)", "safeTransferFrom"),
        ("mint(address,uint256)", "mint"), ("burn(uint256)", "burn"),
        ("pause()", "pause"), ("unpause()", "unpause"),
        ("transferOwnership(address)", "transferOwnership"), ("acceptOwnership()", "acceptOwnership"),
        ("version()", "version"),
    ]
    for sig, label in handlers:
        asm.op("DUP1").push(_selector(sig)).op("EQ").push_label(label).op("JUMPI")
    asm.op("POP"); _emit_revert(asm)

    asm.label("supportsInterface")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    asm.push(4).op("CALLDATALOAD").push(224).op("SHR").op("DUP1").push(0x01FFC9A7).op("EQ")
    asm.op("SWAP1").push(0x80AC58CD).op("EQ").op("OR")
    asm.push(0).op("MSTORE").push(32).push(0).op("RETURN")
    asm.label("name"); _emit_return_string(asm, name_text)
    asm.label("symbol"); _emit_return_string(asm, symbol_text)
    asm.label("owner"); _emit_return_address_slot(asm, ERC721_OWNER)
    asm.label("pendingOwner"); _emit_return_address_slot(asm, ERC721_PENDING_OWNER)
    asm.label("paused"); _emit_return_uint_slot(asm, ERC721_PAUSED)
    asm.label("version"); _emit_return_string(asm, f"{contract_name} v1.0"[:32])

    asm.label("balanceOf")
    _emit_revert_if_calldata_shorter_than(asm, 36); _require_address_nonzero_at(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_BALANCES)
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("ownerOf")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_OWNERS)
    asm.op("SLOAD").op("DUP1").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("getApproved")
    _emit_revert_if_calldata_shorter_than(asm, 36)
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_OWNERS)
    asm.op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI")
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_APPROVALS)
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("isApprovedForAll")
    _emit_revert_if_calldata_shorter_than(asm, 68)
    _emit_revert_if_noncanonical_address_at(asm, 4); _emit_revert_if_noncanonical_address_at(asm, 36)
    _emit_nested_mapping_slot(asm, "4", "36", ERC721_OPERATORS)
    asm.op("SLOAD").push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("approve")
    _emit_revert_if_calldata_shorter_than(asm, 68); _require_not_paused(asm, ERC721_PAUSED)
    _emit_revert_if_noncanonical_address_at(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 36, ERC721_OWNERS)
    asm.op("SLOAD").op("DUP1").push(0x220).op("MSTORE").op("ISZERO").push_label("revert").op("JUMPI")
    # owner or operator
    approved = _unique(asm, "approve_authorized")
    asm.push(0x220).op("MLOAD").op("CALLER").op("EQ").push_label(approved).op("JUMPI")
    asm.push(0x220).op("MLOAD"); _emit_mapping_slot_from_stack_word(asm, ERC721_OPERATORS)
    asm.push(32).op("MSTORE").op("CALLER").push(0).op("MSTORE").push(64).push(0).op("SHA3").op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI")
    asm.label(approved)
    _emit_mapping_slot_from_calldata(asm, 36, ERC721_APPROVALS)
    asm.push(4).op("CALLDATALOAD").op("SWAP1").op("SSTORE")
    asm.push(36).op("CALLDATALOAD").push(4).op("CALLDATALOAD").push(0x220).op("MLOAD").push(approval_topic).push(0).push(0).op("LOG4")
    _emit_return_bool_true(asm)

    asm.label("setApprovalForAll")
    _emit_revert_if_calldata_shorter_than(asm, 68); _require_not_paused(asm, ERC721_PAUSED)
    _require_address_nonzero_at(asm, 4)
    asm.push(4).op("CALLDATALOAD").op("CALLER").op("EQ").push_label("revert").op("JUMPI")
    _emit_nested_mapping_slot(asm, "caller", "4", ERC721_OPERATORS)
    asm.push(36).op("CALLDATALOAD").op("ISZERO").op("ISZERO").op("SWAP1").op("SSTORE")
    asm.push(36).op("CALLDATALOAD").op("ISZERO").op("ISZERO").push(0).op("MSTORE")
    asm.push(4).op("CALLDATALOAD").op("CALLER").push(approval_all_topic).push(32).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("transferFrom")
    _emit_revert_if_calldata_shorter_than(asm, 100)
    _emit_erc721_transfer_state(asm, 4, 36, 68)
    _emit_return_bool_true(asm)

    asm.label("safeTransferFrom")
    _emit_revert_if_calldata_shorter_than(asm, 100)
    _emit_erc721_transfer_state(asm, 4, 36, 68)
    _emit_safe_receiver_empty_data(asm, 4, 36, 68)
    asm.push(0).push(0).op("RETURN")

    asm.label("mint")
    _emit_revert_if_calldata_shorter_than(asm, 68); _require_owner(asm, ERC721_OWNER); _require_not_paused(asm, ERC721_PAUSED)
    _require_address_nonzero_at(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 36, ERC721_OWNERS)
    asm.op("DUP1").push(0x200).op("MSTORE").op("SLOAD").push_label("revert").op("JUMPI")
    asm.push(4).op("CALLDATALOAD").push(0x200).op("MLOAD").op("SSTORE")
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_BALANCES)
    asm.op("DUP1").push(0x220).op("MSTORE").op("SLOAD").push(1).op("ADD").push(0x220).op("MLOAD").op("SSTORE")
    asm.push(36).op("CALLDATALOAD").push(4).op("CALLDATALOAD").push(0).push(transfer_topic).push(0).push(0).op("LOG4")
    _emit_return_bool_true(asm)

    asm.label("burn")
    _emit_revert_if_calldata_shorter_than(asm, 36); _require_not_paused(asm, ERC721_PAUSED)
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_OWNERS)
    asm.op("DUP1").push(0x200).op("MSTORE").op("SLOAD").op("DUP1").push(0x220).op("MSTORE").op("ISZERO").push_label("revert").op("JUMPI")
    _emit_erc721_authorized(asm, 4)
    _emit_mapping_slot_from_calldata(asm, 4, ERC721_APPROVALS); asm.push(0).op("SWAP1").op("SSTORE")
    # Compute the owner balance slot from the saved owner address.
    asm.push(0x220).op("MLOAD"); _emit_mapping_slot_from_stack_word(asm, ERC721_BALANCES)
    asm.op("DUP1").push(0x240).op("MSTORE").op("SLOAD").push(0x260).op("MSTORE")
    asm.push(1).push(0x260).op("MLOAD").op("SUB").push(0x240).op("MLOAD").op("SSTORE")
    asm.push(0).push(0x200).op("MLOAD").op("SSTORE")
    asm.push(4).op("CALLDATALOAD").push(0).push(0x220).op("MLOAD").push(transfer_topic).push(0).push(0).op("LOG4")
    _emit_return_bool_true(asm)

    asm.label("pause"); _require_owner(asm, ERC721_OWNER); asm.push(ERC721_PAUSED).op("SLOAD").push_label("revert").op("JUMPI"); asm.push(1).push(ERC721_PAUSED).op("SSTORE"); _emit_return_bool_true(asm)
    asm.label("unpause"); _require_owner(asm, ERC721_OWNER); asm.push(ERC721_PAUSED).op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI"); asm.push(0).push(ERC721_PAUSED).op("SSTORE"); _emit_return_bool_true(asm)
    _emit_two_step_ownership_handlers(asm, ERC721_OWNER, ERC721_PENDING_OWNER)

    asm.label("revert"); _emit_revert(asm)
    return asm.finish()


def _erc721_creation(runtime: bytes) -> bytes:
    asm = _Assembler(); _emit_revert_if_callvalue(asm)
    asm.op("CALLER").push(ERC721_OWNER).op("SSTORE")
    asm.push(0).push(ERC721_PENDING_OWNER).op("SSTORE")
    asm.push(0).push(ERC721_PAUSED).op("SSTORE")
    asm.push(1).push(ERC721_NEXT_TOKEN_ID).op("SSTORE")
    return _emit_copy_runtime_return_prefix(runtime, bytearray(asm.finish()))


def _compile_erc721(source: str, chain_id: int) -> Dict[str, Any]:
    name = _contract_name(source)
    collection_name = str(_parse_token_constant(source, "name", "AGILANG Secure NFT"))[:32]
    symbol = str(_parse_token_constant(source, "symbol", "ANFT"))[:32]
    runtime = _erc721_runtime(collection_name, symbol, name)
    creation = _erc721_creation(runtime)
    abi = _erc721_abi()
    selectors = {}
    for item in abi:
        if item.get("type") == "function":
            sig = item["name"] + "(" + ",".join(arg["type"] for arg in item.get("inputs", [])) + ")"
            selectors[sig] = evm_function_selector(sig)
    security = {
        "profile": "AGILANG-SECURE-ERC721/1.0",
        "risk": "privileged",
        "controls": ["ERC-165 interface detection", "two-step ownership", "zero-address validation", "approval clearing on transfer", "checks-effects-interactions safe transfer", "owner pausing"],
        "privileged_functions": ["mint", "pause", "unpause"],
        "warnings": ["Metadata URI storage is intentionally excluded from this core profile; keep metadata immutable or content-addressed off-chain."],
    }
    return {
        "ok": True, "language": "AGILANG", "target": "evm", "chainId": int(chain_id),
        "contractName": name, "contractKind": "erc721-secure", "standard": "ERC-721",
        "compilerVersion": COMPILER_VERSION, "compiler": COMPILER_VERSION,
        "evmVersion": "shanghai", "optimization": False, "abi": abi,
        "bytecode": "0x" + creation.hex(), "runtimeBytecode": "0x" + runtime.hex(),
        "sourceCode": source, "generatedSource": f"// Generated by {COMPILER_VERSION}\n// Secure ERC721 core profile\ncontract {name} {{ /* direct EVM implementation */ }}",
        "token": {"name": collection_name, "symbol": symbol},
        "storageLayout": {"owner": 0, "pendingOwner": 1, "paused": 2, "nextTokenId": 3, "balances": 4, "owners": 5, "approvals": 6, "operators": 7},
        "functionSelectors": selectors,
        "events": {"Transfer(address,address,uint256)": evm_keccak("Transfer(address,address,uint256)"), "Approval(address,address,uint256)": evm_keccak("Approval(address,address,uint256)"), "ApprovalForAll(address,address,bool)": evm_keccak("ApprovalForAll(address,address,bool)")},
        "security": security,
    }


# --------------------------- ERC3156 lender ---------------------------

def _emit_external_call(asm: _Assembler, to_slot: int, in_offset: int, in_size: int, out_offset: int, out_size: int, static: bool = False) -> None:
    asm.push(out_size).push(out_offset).push(in_size).push(in_offset)
    if not static:
        asm.push(0)
    asm.push(to_slot).op("SLOAD").op("GAS").op("STATICCALL" if static else "CALL")
    asm.op("ISZERO").push_label("revert").op("JUMPI")


def _emit_erc20_balance_of_self(asm: _Assembler, token_slot: int, out_offset: int) -> None:
    asm.push(_selector("balanceOf(address)") << 224).push(0).op("MSTORE")
    asm.op("ADDRESS").push(4).op("MSTORE")
    _emit_external_call(asm, token_slot, 0, 36, out_offset, 32, static=True)


def _emit_erc20_transfer_call(asm: _Assembler, token_slot: int, to_mem: int, amount_mem: int, out_offset: int) -> None:
    asm.push(_selector("transfer(address,uint256)") << 224).push(0).op("MSTORE")
    asm.push(to_mem).op("MLOAD").push(4).op("MSTORE")
    asm.push(amount_mem).op("MLOAD").push(36).op("MSTORE")
    _emit_external_call(asm, token_slot, 0, 68, out_offset, 32, static=False)
    asm.push(out_offset).op("MLOAD").op("ISZERO").push_label("revert").op("JUMPI")


def _emit_erc20_transfer_from_call(asm: _Assembler, token_slot: int, from_mem: int, amount_mem: int, out_offset: int) -> None:
    asm.push(_selector("transferFrom(address,address,uint256)") << 224).push(0).op("MSTORE")
    asm.push(from_mem).op("MLOAD").push(4).op("MSTORE")
    asm.op("ADDRESS").push(36).op("MSTORE")
    asm.push(amount_mem).op("MLOAD").push(68).op("MSTORE")
    _emit_external_call(asm, token_slot, 0, 100, out_offset, 32, static=False)
    asm.push(out_offset).op("MLOAD").op("ISZERO").push_label("revert").op("JUMPI")


def _flash_abi() -> List[Dict[str, Any]]:
    return [
        {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "pendingOwner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "supportedToken", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "feeBps", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "paused", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view"},
        {"type": "function", "name": "maxFlashLoan", "inputs": [{"name": "token", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "flashFee", "inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "flashLoan", "inputs": [{"name": "receiver", "type": "address"}, {"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}, {"name": "data", "type": "bytes"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "setFeeBps", "inputs": [{"name": "newFeeBps", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "withdraw", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "pause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "unpause", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "transferOwnership", "inputs": [{"name": "newOwner", "type": "address"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "acceptOwnership", "inputs": [], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
        {"type": "event", "name": "FlashLoan", "inputs": [{"name": "receiver", "type": "address", "indexed": True}, {"name": "token", "type": "address", "indexed": True}, {"name": "amount", "type": "uint256", "indexed": False}, {"name": "fee", "type": "uint256", "indexed": False}], "anonymous": False},
    ]


def _flash_runtime(contract_name: str) -> bytes:
    asm = _Assembler(); _emit_revert_if_callvalue(asm); _emit_revert_if_calldata_shorter_than(asm, 4)
    asm.push(0).op("CALLDATALOAD").push(224).op("SHR")
    handlers = [
        ("owner()", "owner"), ("pendingOwner()", "pendingOwner"), ("supportedToken()", "supportedToken"),
        ("feeBps()", "feeBps"), ("paused()", "paused"), ("maxFlashLoan(address)", "maxFlashLoan"),
        ("flashFee(address,uint256)", "flashFee"), ("flashLoan(address,address,uint256,bytes)", "flashLoan"),
        ("setFeeBps(uint256)", "setFeeBps"), ("withdraw(address,uint256)", "withdraw"),
        ("pause()", "pause"), ("unpause()", "unpause"),
        ("transferOwnership(address)", "transferOwnership"), ("acceptOwnership()", "acceptOwnership"),
        ("version()", "version"),
    ]
    for sig, label in handlers:
        asm.op("DUP1").push(_selector(sig)).op("EQ").push_label(label).op("JUMPI")
    asm.op("POP"); _emit_revert(asm)
    asm.label("owner"); _emit_return_address_slot(asm, FLASH_OWNER)
    asm.label("pendingOwner"); _emit_return_address_slot(asm, FLASH_PENDING_OWNER)
    asm.label("supportedToken"); _emit_return_address_slot(asm, FLASH_TOKEN)
    asm.label("feeBps"); _emit_return_uint_slot(asm, FLASH_FEE_BPS)
    asm.label("paused"); _emit_return_uint_slot(asm, FLASH_PAUSED)
    asm.label("version"); _emit_return_string(asm, f"{contract_name} v1.0"[:32])

    asm.label("maxFlashLoan")
    _emit_revert_if_calldata_shorter_than(asm, 36); _emit_revert_if_noncanonical_address_at(asm, 4)
    mismatch = _unique(asm, "max_mismatch"); done = _unique(asm, "max_done")
    asm.push(4).op("CALLDATALOAD").push(FLASH_TOKEN).op("SLOAD").op("EQ").op("ISZERO").push_label(mismatch).op("JUMPI")
    _emit_erc20_balance_of_self(asm, FLASH_TOKEN, 0x300)
    asm.push(0x300).op("MLOAD").push(0).op("MSTORE").push_label(done).op("JUMP")
    asm.label(mismatch); asm.push(0).push(0).op("MSTORE")
    asm.label(done); asm.push(32).push(0).op("RETURN")

    asm.label("flashFee")
    _emit_revert_if_calldata_shorter_than(asm, 68); _emit_revert_if_noncanonical_address_at(asm, 4)
    asm.push(4).op("CALLDATALOAD").push(FLASH_TOKEN).op("SLOAD").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(10_000).push(36).op("CALLDATALOAD").push(FLASH_FEE_BPS).op("SLOAD").op("MUL").op("DIV")
    asm.push(0).op("MSTORE").push(32).push(0).op("RETURN")

    asm.label("setFeeBps")
    _emit_revert_if_calldata_shorter_than(asm, 36); _require_owner(asm, FLASH_OWNER)
    asm.push(4).op("CALLDATALOAD").push(1_000).op("LT").push_label("revert").op("JUMPI")
    asm.push(4).op("CALLDATALOAD").push(FLASH_FEE_BPS).op("SSTORE"); _emit_return_bool_true(asm)

    asm.label("withdraw")
    _emit_revert_if_calldata_shorter_than(asm, 68); _require_owner(asm, FLASH_OWNER); _require_address_nonzero_at(asm, 4)
    asm.push(4).op("CALLDATALOAD").push(0x200).op("MSTORE"); asm.push(36).op("CALLDATALOAD").push(0x220).op("MSTORE")
    _emit_erc20_transfer_call(asm, FLASH_TOKEN, 0x200, 0x220, 0x300); _emit_return_bool_true(asm)

    asm.label("flashLoan")
    _emit_revert_if_calldata_shorter_than(asm, 132); _require_not_paused(asm, FLASH_PAUSED)
    _require_address_nonzero_at(asm, 4); _require_address_nonzero_at(asm, 36)
    asm.push(36).op("CALLDATALOAD").push(FLASH_TOKEN).op("SLOAD").op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(FLASH_REENTRANCY).op("SLOAD").push(2).op("EQ").push_label("revert").op("JUMPI")
    asm.push(2).push(FLASH_REENTRANCY).op("SSTORE")
    asm.push(4).op("CALLDATALOAD").push(0x200).op("MSTORE")
    asm.push(68).op("CALLDATALOAD").push(0x220).op("MSTORE")
    # fee
    asm.push(10_000).push(0x220).op("MLOAD").push(FLASH_FEE_BPS).op("SLOAD").op("MUL").op("DIV").push(0x240).op("MSTORE")
    # initial balance and amount <= balance
    _emit_erc20_balance_of_self(asm, FLASH_TOKEN, 0x300)
    asm.push(0x300).op("MLOAD").push(0x260).op("MSTORE")
    asm.push(0x220).op("MLOAD").push(0x260).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    # transfer amount to receiver
    _emit_erc20_transfer_call(asm, FLASH_TOKEN, 0x200, 0x220, 0x320)
    # Parse dynamic data offset and length
    asm.push(100).op("CALLDATALOAD").push(4).op("ADD").push(0x280).op("MSTORE")
    asm.push(0x280).op("MLOAD").op("CALLDATALOAD").push(0x2A0).op("MSTORE")
    asm.push(32).push(0x280).op("MLOAD").op("ADD").push(0x2C0).op("MSTORE")
    # bounds: calldata size >= data start + length
    asm.push(0x2A0).op("MLOAD").push(0x2C0).op("MLOAD").op("ADD").op("CALLDATASIZE").op("LT").push_label("revert").op("JUMPI")
    # callback head
    asm.push(_selector("onFlashLoan(address,address,uint256,uint256,bytes)") << 224).push(0).op("MSTORE")
    asm.op("CALLER").push(4).op("MSTORE")
    asm.push(FLASH_TOKEN).op("SLOAD").push(36).op("MSTORE")
    asm.push(0x220).op("MLOAD").push(68).op("MSTORE")
    asm.push(0x240).op("MLOAD").push(100).op("MSTORE")
    asm.push(160).push(132).op("MSTORE")
    asm.push(0x2A0).op("MLOAD").push(164).op("MSTORE")
    asm.push(0x2A0).op("MLOAD").push(0x2C0).op("MLOAD").push(196).op("CALLDATACOPY")
    # rounded callback size = 196 + ceil32(len)
    asm.push(0x2A0).op("MLOAD").push(31).op("ADD").push(WORD_MASK ^ 31).op("AND").push(196).op("ADD").push(0x2E0).op("MSTORE")
    # call receiver, output 32 at 0x360
    asm.push(32).push(0x360).push(0x2E0).op("MLOAD").push(0).push(0).push(0x200).op("MLOAD").op("GAS").op("CALL")
    asm.op("ISZERO").push_label("revert").op("JUMPI")
    asm.push(0x360).op("MLOAD").push(int(evm_keccak("ERC3156FlashBorrower.onFlashLoan"), 16)).op("EQ").op("ISZERO").push_label("revert").op("JUMPI")
    # total due amount + fee
    asm.push(0x240).op("MLOAD").push(0x220).op("MLOAD").op("ADD").push(0x380).op("MSTORE")
    _emit_erc20_transfer_from_call(asm, FLASH_TOKEN, 0x200, 0x380, 0x3A0)
    # final balance >= initial + fee
    _emit_erc20_balance_of_self(asm, FLASH_TOKEN, 0x3C0)
    asm.push(0x240).op("MLOAD").push(0x260).op("MLOAD").op("ADD").push(0x3C0).op("MLOAD").op("LT").push_label("revert").op("JUMPI")
    asm.push(1).push(FLASH_REENTRANCY).op("SSTORE")
    # FlashLoan(receiver,token,amount,fee)
    asm.push(0x220).op("MLOAD").push(0).op("MSTORE"); asm.push(0x240).op("MLOAD").push(32).op("MSTORE")
    asm.push(FLASH_TOKEN).op("SLOAD").push(0x200).op("MLOAD").push(_topic("FlashLoan(address,address,uint256,uint256)")).push(64).push(0).op("LOG3")
    _emit_return_bool_true(asm)

    asm.label("pause"); _require_owner(asm, FLASH_OWNER); asm.push(FLASH_PAUSED).op("SLOAD").push_label("revert").op("JUMPI"); asm.push(1).push(FLASH_PAUSED).op("SSTORE"); _emit_return_bool_true(asm)
    asm.label("unpause"); _require_owner(asm, FLASH_OWNER); asm.push(FLASH_PAUSED).op("SLOAD").op("ISZERO").push_label("revert").op("JUMPI"); asm.push(0).push(FLASH_PAUSED).op("SSTORE"); _emit_return_bool_true(asm)
    _emit_two_step_ownership_handlers(asm, FLASH_OWNER, FLASH_PENDING_OWNER)
    asm.label("revert"); _emit_revert(asm)
    return asm.finish()


def _flash_creation(runtime: bytes, token: int, fee_bps: int) -> bytes:
    asm = _Assembler(); _emit_revert_if_callvalue(asm)
    asm.op("CALLER").push(FLASH_OWNER).op("SSTORE")
    asm.push(0).push(FLASH_PENDING_OWNER).op("SSTORE")
    asm.push(token).push(FLASH_TOKEN).op("SSTORE")
    asm.push(fee_bps).push(FLASH_FEE_BPS).op("SSTORE")
    asm.push(0).push(FLASH_PAUSED).op("SSTORE")
    asm.push(1).push(FLASH_REENTRANCY).op("SSTORE")
    return _emit_copy_runtime_return_prefix(runtime, bytearray(asm.finish()))


def _compile_flash_lender(source: str, chain_id: int) -> Dict[str, Any]:
    name = _contract_name(source)
    token = _parse_address_constant(source, "assetToken")
    fee_bps = int(_parse_token_constant(source, "feeBps", 5))
    if not 0 <= fee_bps <= 1_000:
        raise AgilangContractCompileError("flash-loan feeBps must be between 0 and 1000")
    runtime = _flash_runtime(name)
    creation = _flash_creation(runtime, token, fee_bps)
    abi = _flash_abi()
    selectors = {}
    for item in abi:
        if item.get("type") == "function":
            sig = item["name"] + "(" + ",".join(arg["type"] for arg in item.get("inputs", [])) + ")"
            selectors[sig] = evm_function_selector(sig)
    security = {
        "profile": "AGILANG-SECURE-ERC3156-LENDER/1.0",
        "risk": "advanced",
        "controls": ["single supported asset", "callback magic-value validation", "reentrancy guard", "post-callback balance invariant", "fee cap", "owner pausing", "two-step ownership", "no arbitrary delegatecall"],
        "privileged_functions": ["withdraw", "setFeeBps", "pause", "unpause"],
        "warnings": ["Flash-loan systems are advanced DeFi infrastructure and require an independent audit, economic testing, and oracle/manipulation review before production use."],
    }
    return {
        "ok": True, "language": "AGILANG", "target": "evm", "chainId": int(chain_id),
        "contractName": name, "contractKind": "erc3156-flash-lender", "standard": "ERC-3156",
        "compilerVersion": COMPILER_VERSION, "compiler": COMPILER_VERSION,
        "evmVersion": "shanghai", "optimization": False, "abi": abi,
        "bytecode": "0x" + creation.hex(), "runtimeBytecode": "0x" + runtime.hex(),
        "sourceCode": source, "generatedSource": f"// Generated by {COMPILER_VERSION}\n// ERC3156 guarded lender for {hex(token)}\ncontract {name} {{ /* direct EVM implementation */ }}",
        "flashLoan": {"supportedToken": "0x" + token.to_bytes(20, "big").hex(), "feeBps": fee_bps},
        "storageLayout": {"owner": 0, "pendingOwner": 1, "supportedToken": 2, "feeBps": 3, "paused": 4, "reentrancyLock": 5},
        "functionSelectors": selectors,
        "events": {"FlashLoan(address,address,uint256,uint256)": evm_keccak("FlashLoan(address,address,uint256,uint256)")},
        "security": security,
    }


def compile_secure_agilang_contract(source: str, *, chain_id: int, kind: str) -> Dict[str, Any]:
    if kind.startswith("erc20-"):
        return _compile_erc20(source, chain_id, kind)
    if kind == "erc721-secure":
        return _compile_erc721(source, chain_id)
    if kind == "erc3156-flash-lender":
        return _compile_flash_lender(source, chain_id)
    raise AgilangContractCompileError(f"unsupported secure contract kind: {kind}")


__all__ = [
    "compile_secure_agilang_contract",
    "detect_secure_contract_kind",
    "secure_contract_template_catalog",
]
