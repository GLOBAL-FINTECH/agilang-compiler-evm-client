"""AGILANG Native Execution Client.

This module is the built-in execution layer for AGILANG / SmartChain networks.
It is intentionally not a Geth, Erigon, Besu, Nethermind, or Reth wrapper.

What it does now:
- Executes AGILANG/EVM-shaped transactions against AGILANG world state.
- Enforces chain-id, nonce, value, intrinsic gas, and balance rules.
- Charges gas for raw/charge_gas transactions while preserving legacy zero-fee tests.
- Executes native transfers, contract deployment, and EVM contract calls.
- Persists balances, nonces, contract code, contract storage, receipts, logs, and roots.
- Provides read APIs used by wallet/RPC/indexer layers.

Boundary:
This is a native execution client foundation. It is not yet byte-for-byte
Ethereum-mainnet equivalent until AGILANG implements the Ethereum MPT/state root,
receipts trie, fork-specific gas schedules, Engine API, devp2p sync, and passes
Ethereum execution-spec tests.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple
from .ethereum_trie import logs_bloom as ethereum_logs_bloom, receipts_root as ethereum_receipts_root, rlp as ethereum_rlp, state_root as ethereum_state_root

try:  # package import when used from the AGILANG runtime
    from .evm import EVMExecutionContext, EVMInterpreter, EVMWorldState, evm_keccak
except Exception:  # pragma: no cover - direct/standalone safety
    EVMExecutionContext = None  # type: ignore
    EVMInterpreter = None  # type: ignore
    EVMWorldState = None  # type: ignore

    def evm_keccak(data: bytes | str) -> str:  # type: ignore
        raw = data if isinstance(data, bytes) else str(data).encode("utf-8")
        return "0x" + hashlib.sha3_256(raw).hexdigest()


NATIVE_EXECUTION_CLIENT_VERSION = "AGILANG-NATIVE-EXECUTION/2.1.0"
ZERO_ADDRESS = "0x" + "00" * 20
TRANSFER_BASE_GAS = 21_000
CONTRACT_CALL_BASE_GAS = 21_000
CONTRACT_CREATE_BASE_GAS = 53_000
CODE_DEPOSIT_GAS = 200
MAX_U256 = 2**256 - 1


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = _stable_json(value).encode("utf-8")
    return "0x" + hashlib.sha256(data).hexdigest()


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


def _is_hex_address(value: Any) -> bool:
    text = str(value or "").lower()
    h = _strip_0x(text)
    return len(h) == 40 and all(ch in "0123456789abcdef" for ch in h)


def _norm_address(value: Any) -> str:
    """Normalize addresses while preserving AGILANG named dev accounts.

    Existing SmartChain tests use names like ``alice`` and ``bob``. Ethereum
    paths use 20-byte hex addresses. This function supports both.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if _is_hex_address(text):
        return "0x" + _strip_0x(text).rjust(40, "0")[-40:]
    return text


def _evm_address(value: Any, *, fallback: str = ZERO_ADDRESS) -> str:
    """Return a valid 20-byte EVM address for the interpreter.

    Named AGILANG accounts are deterministically mapped into 20-byte addresses
    only inside the EVM sandbox. Their external state keys remain unchanged.
    """
    text = _norm_address(value)
    if not text:
        return fallback
    if _is_hex_address(text):
        return "0x" + _strip_0x(text).rjust(40, "0")[-40:]
    return "0x" + hashlib.sha256(text.encode("utf-8")).hexdigest()[-40:]


def _hex_to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if value is None:
        return b""
    text = str(value).strip()
    if text.startswith(("0x", "0X")):
        text = _strip_0x(text)
        if len(text) % 2:
            text = "0" + text
        return bytes.fromhex(text) if text else b""
    return text.encode("utf-8")


def _bytes_to_hex(value: bytes | bytearray | str | None) -> str:
    if value is None:
        return "0x"
    if isinstance(value, str):
        return value if value.startswith("0x") else "0x" + value.encode("utf-8").hex()
    return "0x" + bytes(value).hex()


def _to_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return int(default)
    if isinstance(value, int):
        return value
    text = str(value)
    if text.startswith(("0x", "0X")):
        return int(text, 16)
    return int(text)


def _deepcopy_dict(value: Mapping[str, Any] | None) -> Dict[str, Any]:
    return copy.deepcopy(dict(value or {}))


def _contract_code(record: Any) -> str:
    if isinstance(record, Mapping):
        code = record.get("code", record.get("bytecode", "0x"))
    else:
        code = record
    if code is None or code == "":
        return "0x"
    text = str(code)
    return text if text.startswith("0x") else "0x" + text


def _contract_storage(record: Any) -> Dict[str, int]:
    if isinstance(record, Mapping):
        storage = record.get("storage", {}) or {}
        return {str(k): _to_int(v) for k, v in dict(storage).items()}
    return {}


def _make_contract_record(code: str, storage: Mapping[str, int] | None = None) -> Any:
    """Keep backward compatibility: plain code string if no storage exists."""
    normalized_code = code if str(code).startswith("0x") else "0x" + str(code)
    clean_storage = {str(k): int(v) for k, v in dict(storage or {}).items() if int(v) != 0}
    if clean_storage:
        return {
            "code": normalized_code,
            "storage": clean_storage,
            "code_hash": evm_keccak(_hex_to_bytes(normalized_code)),
        }
    return normalized_code


def _log_bloom_placeholder(logs: Iterable[Mapping[str, Any]]) -> str:
    return ethereum_logs_bloom(logs)


def _tx_chain_id(tx: Mapping[str, Any]) -> Optional[int]:
    if "chain_id" in tx:
        return _to_int(tx.get("chain_id"))
    meta = tx.get("metadata") or {}
    if isinstance(meta, Mapping) and "chain_id" in meta:
        return _to_int(meta.get("chain_id"))
    return None


def _charge_gas_enabled(tx: Mapping[str, Any]) -> bool:
    meta = tx.get("metadata") or {}
    return bool(
        isinstance(meta, Mapping)
        and (meta.get("ethereum_raw") or meta.get("charge_gas") or meta.get("fee_market"))
    )


def _tx_type(tx: Mapping[str, Any]) -> str:
    raw = str(tx.get("type", "") or "").strip().lower()
    data = str(tx.get("data", tx.get("input", "0x")) or "0x")
    to = str(tx.get("to", "") or "")
    if raw:
        return raw
    if not to and data and data != "0x":
        return "deploy_contract"
    if data and data != "0x":
        return "contract_call"
    return "transfer"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class NativeExecutionConfig:
    chain_id: int
    block_gas_limit: int = 30_000_000
    strict_accounting: bool = True
    enforce_nonce_order: bool = True
    evm_enabled: bool = True
    coinbase: str = ZERO_ADDRESS
    base_fee: int = 0
    gas_refunds: bool = True
    allow_named_accounts: bool = True


@dataclass
class NativeExecutionReceipt:
    tx_hash: str
    ok: bool
    gas_used: int
    error: str = ""
    tx_index: int = 0
    status: int = 1
    fee_charged: int = 0
    cumulative_gas_used: int = 0
    contract_address: str = ""
    output: str = "0x"
    logs: List[Dict[str, Any]] = field(default_factory=list)
    logs_bloom: str = ""

    def as_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "tx_hash": self.tx_hash,
            "ok": bool(self.ok),
            "status": 1 if self.ok else 0,
            "gas_used": int(self.gas_used),
            "cumulative_gas_used": int(self.cumulative_gas_used),
            "error": str(self.error or ""),
            "tx_index": int(self.tx_index),
            "logs": copy.deepcopy(self.logs),
            "logs_bloom": self.logs_bloom or _log_bloom_placeholder(self.logs),
        }
        if self.fee_charged:
            data["fee_charged"] = int(self.fee_charged)
        if self.contract_address:
            data["contract_address"] = self.contract_address
        if self.output and self.output != "0x":
            data["output"] = self.output
        return data


@dataclass
class NativeExecutionResult:
    receipts: List[Dict[str, Any]]
    state_updates: Dict[str, Any]
    gas_used: int
    state_root: str
    receipts_root: str
    logs: List[Dict[str, Any]] = field(default_factory=list)

    def as_tuple(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any], int]:
        """Compatibility with BlockchainNode._execute_transactions."""
        return self.receipts, self.state_updates, int(self.gas_used)


class NativeStateView:
    """Mutable execution view over AGILANG state.

    State shape accepted:
        {
            "balances": {address: int},
            "nonces": {address: int},
            "contracts": {address: "0x..." | {"code": "0x...", "storage": {...}}}
        }
    """

    def __init__(self, base_state: Mapping[str, Any] | None = None) -> None:
        base = dict(base_state or {})
        self.balances: Dict[str, int] = {
            _norm_address(k): _to_int(v) for k, v in dict(base.get("balances", {}) or {}).items()
        }
        self.nonces: Dict[str, int] = {
            _norm_address(k): _to_int(v) for k, v in dict(base.get("nonces", {}) or {}).items()
        }
        self.contracts: Dict[str, Any] = {
            _norm_address(k): copy.deepcopy(v) for k, v in dict(base.get("contracts", {}) or {}).items()
        }

    def snapshot(self) -> Dict[str, Any]:
        return {
            "balances": copy.deepcopy(self.balances),
            "nonces": copy.deepcopy(self.nonces),
            "contracts": copy.deepcopy(self.contracts),
        }

    def restore(self, snap: Mapping[str, Any]) -> None:
        self.balances.clear()
        self.balances.update(copy.deepcopy(dict(snap.get("balances", {}) or {})))
        self.nonces.clear()
        self.nonces.update(copy.deepcopy(dict(snap.get("nonces", {}) or {})))
        self.contracts.clear()
        self.contracts.update(copy.deepcopy(dict(snap.get("contracts", {}) or {})))

    def export(self) -> Dict[str, Any]:
        return {
            "balances": {k: int(v) for k, v in sorted(self.balances.items())},
            "contracts": {k: copy.deepcopy(v) for k, v in sorted(self.contracts.items())},
            "nonces": {k: int(v) for k, v in sorted(self.nonces.items())},
        }

    def balance(self, address: Any) -> int:
        return int(self.balances.get(_norm_address(address), 0))

    def set_balance(self, address: Any, value: int) -> None:
        self.balances[_norm_address(address)] = int(value)

    def add_balance(self, address: Any, delta: int) -> None:
        addr = _norm_address(address)
        self.balances[addr] = int(self.balances.get(addr, 0)) + int(delta)

    def nonce(self, address: Any) -> int:
        return int(self.nonces.get(_norm_address(address), 0))

    def set_nonce(self, address: Any, value: int) -> None:
        self.nonces[_norm_address(address)] = int(value)

    def contract_code(self, address: Any) -> str:
        return _contract_code(self.contracts.get(_norm_address(address), "0x"))

    def contract_storage(self, address: Any) -> Dict[str, int]:
        return _contract_storage(self.contracts.get(_norm_address(address), {}))

    def set_contract(self, address: Any, code: str, storage: Mapping[str, int] | None = None) -> None:
        self.contracts[_norm_address(address)] = _make_contract_record(code, storage)

    def set_contract_storage(self, address: Any, storage: Mapping[str, int]) -> None:
        addr = _norm_address(address)
        code = self.contract_code(addr)
        self.contracts[addr] = _make_contract_record(code, storage)


# ---------------------------------------------------------------------------
# Native execution client
# ---------------------------------------------------------------------------


class NativeExecutionClient:
    """Built-in AGILANG execution client.

    The client is deterministic and dependency-light. It can be called by the
    blockchain layer during block production and block import validation.
    """

    def __init__(
        self,
        *,
        chain_id: int,
        block_gas_limit: int = 30_000_000,
        strict_accounting: bool = True,
        enforce_nonce_order: bool = True,
        evm_enabled: bool = True,
        coinbase: str = ZERO_ADDRESS,
        base_fee: int = 0,
    ) -> None:
        self.config = NativeExecutionConfig(
            chain_id=int(chain_id),
            block_gas_limit=int(block_gas_limit),
            strict_accounting=bool(strict_accounting),
            enforce_nonce_order=bool(enforce_nonce_order),
            evm_enabled=bool(evm_enabled),
            coinbase=_norm_address(coinbase) if coinbase else ZERO_ADDRESS,
            base_fee=int(base_fee),
        )
        self.chain_id = self.config.chain_id
        self.block_gas_limit = self.config.block_gas_limit
        self.strict_accounting = self.config.strict_accounting
        self.enforce_nonce_order = self.config.enforce_nonce_order
        self.evm_enabled = self.config.evm_enabled

    # ------------------------------------------------------------------
    # Capability / read API
    # ------------------------------------------------------------------

    def capabilities(self) -> Dict[str, Any]:
        return {
            "version": NATIVE_EXECUTION_CLIENT_VERSION,
            "native_execution_client": True,
            "external_geth_required": False,
            "transaction_types": [
                "transfer",
                "deploy_contract",
                "contract_call",
                "evm_call",
                "call",
                "create",
            ],
            "features": [
                "chain_id_validation",
                "nonce_validation",
                "balance_validation",
                "intrinsic_gas",
                "gas_charging",
                "gas_refund",
                "native_value_transfer",
                "contract_deployment",
                "evm_interpreter_bridge",
                "contract_storage_persistence",
                "receipts",
                "logs",
                "ethereum_mpt_state_root",
                "ethereum_receipts_trie_root",
                "ethereum_2048_bit_log_bloom",
                "read_only_eth_call",
            ],
            "mainnet_equivalence": False,
            "mainnet_equivalence_requirements": [
                "fork-specific gas schedule and opcode rules",
                "official execution-spec-test corpus conformance",
                "standard Engine API payload decoding and execution",
                "devp2p snap/full sync",
            ],
        }

    def get_balance(self, state: Mapping[str, Any], address: Any) -> int:
        return NativeStateView(state).balance(address)

    def get_nonce(self, state: Mapping[str, Any], address: Any) -> int:
        return NativeStateView(state).nonce(address)

    def get_code(self, state: Mapping[str, Any], address: Any) -> str:
        return NativeStateView(state).contract_code(address)

    def get_storage_at(self, state: Mapping[str, Any], address: Any, slot: Any) -> int:
        storage = NativeStateView(state).contract_storage(address)
        return int(storage.get(str(_to_int(slot)), storage.get(str(slot), 0)))

    # ------------------------------------------------------------------
    # Block / transaction execution
    # ------------------------------------------------------------------

    def execute_block(
        self,
        txs: List[Dict[str, Any]],
        base_state: Mapping[str, Any],
        *,
        block_context: Optional[Mapping[str, Any]] = None,
    ) -> NativeExecutionResult:
        state = NativeStateView(base_state)
        receipts: List[Dict[str, Any]] = []
        all_logs: List[Dict[str, Any]] = []
        total_gas = 0
        context = dict(block_context or {})

        for index, tx in enumerate(txs):
            gas_limit = _to_int(tx.get("gas_limit", tx.get("gas", TRANSFER_BASE_GAS)), TRANSFER_BASE_GAS)
            if total_gas + max(0, gas_limit) > self.block_gas_limit:
                receipt = NativeExecutionReceipt(
                    tx_hash=str(tx.get("hash") or _hash(tx)),
                    ok=False,
                    status=0,
                    gas_used=0,
                    cumulative_gas_used=total_gas,
                    error="block_gas_limit_exceeded",
                    tx_index=index,
                )
                receipts.append(receipt.as_dict())
                continue

            receipt = self.execute_transaction(tx, state, context=context, tx_index=index)
            total_gas += int(receipt.gas_used)
            receipt.cumulative_gas_used = total_gas
            receipt.logs_bloom = _log_bloom_placeholder(receipt.logs)
            receipt_dict = receipt.as_dict()
            receipts.append(receipt_dict)
            all_logs.extend(receipt_dict.get("logs", []))

        exported = state.export()
        return NativeExecutionResult(
            receipts=receipts,
            state_updates=exported,
            gas_used=total_gas,
            state_root=self.state_root(exported),
            receipts_root=self.receipts_root(receipts),
            logs=all_logs,
        )

    def execute_transaction(
        self,
        tx: Dict[str, Any],
        state: NativeStateView,
        *,
        context: Mapping[str, Any],
        tx_index: int = 0,
    ) -> NativeExecutionReceipt:
        tx_hash = str(tx.get("hash") or _hash(tx))
        sender = _norm_address(tx.get("from") or tx.get("sender"))
        receiver = _norm_address(tx.get("to"))
        tx_type = _tx_type(tx)
        value = _to_int(tx.get("value", 0))
        gas_limit = _to_int(tx.get("gas_limit", tx.get("gas", TRANSFER_BASE_GAS)), TRANSFER_BASE_GAS)
        gas_price = _to_int(tx.get("gas_price", tx.get("gasPrice", 0)), 0)
        data = str(tx.get("data", tx.get("input", "0x")) or "0x")
        actual_nonce = _to_int(tx.get("nonce", 0), 0)
        charge_gas = _charge_gas_enabled(tx)
        if tx_type in {"transfer", "native_transfer"} and receiver and state.contract_code(receiver) != "0x":
            tx_type = "contract_call"

        base_validation = self._validate_base_tx(
            tx=tx,
            sender=sender,
            value=value,
            gas_limit=gas_limit,
            gas_price=gas_price,
            actual_nonce=actual_nonce,
            state=state,
        )
        if base_validation:
            return NativeExecutionReceipt(
                tx_hash=tx_hash,
                ok=False,
                status=0,
                gas_used=base_validation[1],
                error=base_validation[0],
                tx_index=tx_index,
            )

        intrinsic = self.intrinsic_gas(tx_type, data)
        if gas_limit < intrinsic:
            return NativeExecutionReceipt(
                tx_hash=tx_hash,
                ok=False,
                status=0,
                gas_used=gas_limit,
                error="intrinsic_gas_too_low",
                tx_index=tx_index,
            )

        max_fee = gas_limit * gas_price if charge_gas else 0
        required = value + max_fee
        if self.strict_accounting and state.balance(sender) < required:
            return NativeExecutionReceipt(
                tx_hash=tx_hash,
                ok=False,
                status=0,
                gas_used=intrinsic,
                error="insufficient_balance_for_value_and_gas",
                tx_index=tx_index,
            )

        pre_execution_state = state.snapshot()
        state.add_balance(sender, -max_fee)
        # Valid included transactions consume nonce even when EVM execution fails.
        state.set_nonce(sender, max(state.nonce(sender), actual_nonce))

        ok = True
        error = ""
        gas_used = intrinsic
        output = "0x"
        logs: List[Dict[str, Any]] = []
        contract_address = ""

        try:
            if tx_type in {"transfer", "native_transfer"} or (tx_type == "call" and data == "0x"):
                state.add_balance(sender, -value)
                if receiver:
                    state.add_balance(receiver, value)

            elif tx_type in {"deploy_contract", "create", "contract_create"}:
                deploy_result = self._execute_deploy(tx, state, data, gas_limit - intrinsic, context=context)
                ok = bool(deploy_result["ok"])
                error = str(deploy_result.get("error") or "")
                gas_used = min(gas_limit, intrinsic + int(deploy_result.get("gas_used", 0)))
                output = str(deploy_result.get("output", "0x"))
                contract_address = str(deploy_result.get("contract_address", ""))
                logs = list(deploy_result.get("logs", []))

            elif tx_type in {"contract_call", "evm_call", "call"}:
                call_result = self._execute_contract_call(tx, state, data, gas_limit - intrinsic, context=context)
                ok = bool(call_result["ok"])
                error = str(call_result.get("error") or "")
                gas_used = min(gas_limit, intrinsic + int(call_result.get("gas_used", 0)))
                output = str(call_result.get("output", "0x"))
                logs = list(call_result.get("logs", []))

            else:
                ok = False
                error = "unsupported_transaction_type"
        except Exception as exc:  # pragma: no cover - runtime boundary
            ok = False
            error = str(exc)
            gas_used = min(gas_limit, max(intrinsic, gas_used))

        if not ok:
            # Revert state effects except gas reserve and nonce. Then charge used gas.
            nonce_after = state.nonce(sender)
            state.restore(pre_execution_state)
            state.set_nonce(sender, max(state.nonce(sender), nonce_after, actual_nonce))
            if charge_gas:
                fee = gas_used * gas_price
                state.add_balance(sender, -fee)
                if self.config.coinbase != ZERO_ADDRESS:
                    state.add_balance(self.config.coinbase, fee)
            else:
                fee = 0
        else:
            if charge_gas:
                fee = gas_used * gas_price
                refund = max_fee - fee
                if refund:
                    state.add_balance(sender, refund)
                if self.config.coinbase != ZERO_ADDRESS:
                    state.add_balance(self.config.coinbase, fee)
            else:
                fee = 0

        normalized_logs = self._normalize_logs(logs, tx_hash=tx_hash, tx_index=tx_index)
        return NativeExecutionReceipt(
            tx_hash=tx_hash,
            ok=ok,
            status=1 if ok else 0,
            gas_used=int(gas_used),
            error=error,
            tx_index=tx_index,
            fee_charged=int(fee),
            logs=normalized_logs,
            contract_address=contract_address,
            output=output,
        )

    def _validate_base_tx(
        self,
        *,
        tx: Mapping[str, Any],
        sender: str,
        value: int,
        gas_limit: int,
        gas_price: int,
        actual_nonce: int,
        state: NativeStateView,
    ) -> Optional[Tuple[str, int]]:
        if not sender:
            return "missing_sender", 0
        chain_id = _tx_chain_id(tx)
        if chain_id is not None and int(chain_id) != int(self.chain_id):
            return "wrong_chain_id", 0
        if value < 0:
            return "negative_value", 0
        if gas_limit <= 0:
            return "invalid_gas_limit", 0
        if gas_price < 0:
            return "invalid_gas_price", 0
        if actual_nonce < 0:
            return "invalid_nonce", 0
        if self.strict_accounting and self.enforce_nonce_order:
            expected = state.nonce(sender) + 1
            if actual_nonce != expected:
                return f"invalid_nonce_expected_{expected}", min(max(gas_limit, 0), TRANSFER_BASE_GAS)
        return None

    # ------------------------------------------------------------------
    # Transaction handlers
    # ------------------------------------------------------------------

    def _execute_deploy(
        self,
        tx: Mapping[str, Any],
        state: NativeStateView,
        data: str,
        gas: int,
        *,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        sender = _norm_address(tx.get("from") or tx.get("sender"))
        value = _to_int(tx.get("value", 0))
        nonce = _to_int(tx.get("nonce", 0))
        contract_address = self.derive_contract_address(sender, nonce)

        state.add_balance(sender, -value)
        state.add_balance(contract_address, value)

        if not self.evm_enabled:
            state.set_contract(contract_address, data, {})
            return {
                "ok": True,
                "gas_used": CODE_DEPOSIT_GAS * len(_hex_to_bytes(data)),
                "output": "0x",
                "contract_address": contract_address,
                "logs": [],
            }

        # Run init code. If it returns runtime bytecode, store that output.
        # If it halts with no output, store the supplied bytecode for AGILANG
        # compatibility with existing direct-bytecode deployment tests.
        evm_result = self._run_evm(
            code=data,
            calldata="0x",
            gas=max(0, gas),
            caller=sender,
            address=contract_address,
            value=value,
            context=context,
            state=state,
            static=False,
        )
        if not evm_result.get("ok"):
            return evm_result | {"contract_address": contract_address}

        runtime_code = str(evm_result.get("output") or "0x")
        if runtime_code == "0x":
            # AGILANG compatibility mode: direct bytecode deployment stores the
            # supplied bytecode and does not treat constructor SSTORE side
            # effects as persistent runtime storage unless runtime code is
            # explicitly returned.
            runtime_code = data
            state.set_contract(contract_address, runtime_code, {})
        else:
            state.set_contract(contract_address, runtime_code, state.contract_storage(contract_address))
        return evm_result | {"contract_address": contract_address, "output": runtime_code}

    def _execute_contract_call(
        self,
        tx: Mapping[str, Any],
        state: NativeStateView,
        data: str,
        gas: int,
        *,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        sender = _norm_address(tx.get("from") or tx.get("sender"))
        receiver = _norm_address(tx.get("to"))
        value = _to_int(tx.get("value", 0))
        if not receiver:
            return {"ok": False, "error": "missing_contract_address", "gas_used": 0, "output": "0x", "logs": []}
        code = state.contract_code(receiver)
        if code == "0x":
            # Ethereum allows calls to empty accounts; they succeed and transfer value.
            state.add_balance(sender, -value)
            state.add_balance(receiver, value)
            return {"ok": True, "gas_used": 0, "output": "0x", "logs": []}
        return self._run_evm(
            code=code,
            calldata=data,
            gas=max(0, gas),
            caller=sender,
            address=receiver,
            value=value,
            context=context,
            state=state,
            static=False,
        )

    # ------------------------------------------------------------------
    # EVM bridge
    # ------------------------------------------------------------------

    def _run_evm(
        self,
        *,
        code: Any,
        calldata: Any,
        gas: int,
        caller: str,
        address: str,
        value: int,
        context: Mapping[str, Any],
        state: NativeStateView,
        static: bool,
    ) -> Dict[str, Any]:
        if not self.evm_enabled:
            return {"ok": False, "error": "evm_disabled", "gas_used": 0, "output": "0x", "logs": []}
        if EVMInterpreter is None or EVMWorldState is None or EVMExecutionContext is None:
            return {"ok": False, "error": "evm_runtime_unavailable", "gas_used": 0, "output": "0x", "logs": []}

        world, reverse_map = self._world_from_state(state, primary_accounts=[caller, address])
        evm_caller = _evm_address(caller)
        evm_address = _evm_address(address)

        # External transaction value transfer into the execution account. This
        # happens in the world snapshot so reverts can roll back cleanly.
        if value:
            if not world.transfer(evm_caller, evm_address, value):
                return {"ok": False, "error": "insufficient_balance_for_call_value", "gas_used": 0, "output": "0x", "logs": []}

        evm_context = EVMExecutionContext(
            address=evm_address,
            caller=evm_caller,
            origin=evm_caller,
            value=int(value),
            calldata=_hex_to_bytes(calldata),
            gas_price=0,
            chain_id=self.chain_id,
            coinbase=_evm_address(self.config.coinbase),
            timestamp=_to_int(context.get("timestamp", context.get("timestamp_ms", int(time.time()))), int(time.time())),
            block_number=_to_int(context.get("height", context.get("number", 0)), 0),
            prev_randao=_to_int(context.get("prev_randao", context.get("mix_hash", 0)), 0),
            gas_limit=self.block_gas_limit,
            basefee=self.config.base_fee,
            fork=str(context.get("fork", "cancun")),
            static=bool(static),
            world=world,
        )
        result = EVMInterpreter(world=world, trace=False).execute(code or "0x", calldata=calldata, gas=gas, context=evm_context)
        if result.ok:
            self._persist_world_to_state(result.world or world.snapshot(), state, reverse_map)
        return {
            "ok": bool(result.ok),
            "error": result.error or "",
            "gas_used": int(result.gas_used),
            "output": result.output or "0x",
            "logs": list(result.logs or []),
            "world": result.world or world.snapshot(),
        }

    def _world_from_state(
        self,
        state: NativeStateView,
        *,
        primary_accounts: Iterable[str] = (),
    ) -> Tuple[Any, Dict[str, str]]:
        world = EVMWorldState()
        reverse_map: Dict[str, str] = {}
        accounts = set(state.balances) | set(state.nonces) | set(state.contracts) | {_norm_address(a) for a in primary_accounts if a}
        for account in sorted(accounts):
            evm_addr = _evm_address(account)
            reverse_map[evm_addr] = account
            storage = state.contract_storage(account)
            world.create_account(
                evm_addr,
                balance=state.balance(account),
                nonce=state.nonce(account),
                code=state.contract_code(account),
                storage=storage,
            )
        return world, reverse_map

    def _persist_world_to_state(self, world_snapshot: Mapping[str, Any], state: NativeStateView, reverse_map: Mapping[str, str]) -> None:
        for evm_addr, account in dict(world_snapshot or {}).items():
            external = reverse_map.get(_norm_address(evm_addr), _norm_address(evm_addr))
            if not external:
                continue
            if "balance" in account:
                state.set_balance(external, _to_int(account.get("balance")))
            if "nonce" in account:
                state.set_nonce(external, _to_int(account.get("nonce")))
            code = str(account.get("code", "0x") or "0x")
            storage = {str(k): _to_int(v) for k, v in dict(account.get("storage", {}) or {}).items()}
            if code != "0x" or storage:
                state.set_contract(external, code, storage)

    # ------------------------------------------------------------------
    # Read-only calls / estimation
    # ------------------------------------------------------------------

    def call(
        self,
        tx: Mapping[str, Any],
        state: Mapping[str, Any],
        *,
        block_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Read-only eth_call-style execution.

        The input state is never mutated. The transaction nonce is not consumed.
        """
        view = NativeStateView(state)
        tx_copy = dict(tx)
        tx_copy.setdefault("type", "contract_call")
        tx_copy.setdefault("nonce", view.nonce(tx_copy.get("from") or tx_copy.get("sender")) + 1)
        tx_copy.setdefault("gas_limit", tx_copy.get("gas", 1_000_000))
        tx_copy.setdefault("gas_price", 0)
        tx_copy.setdefault("metadata", {})
        result = self._execute_contract_call(
            tx_copy,
            view,
            str(tx_copy.get("data", tx_copy.get("input", "0x")) or "0x"),
            _to_int(tx_copy.get("gas_limit", tx_copy.get("gas", 1_000_000)), 1_000_000),
            context=dict(block_context or {}),
        )
        return result

    def estimate_gas(self, tx: Mapping[str, Any], state: Mapping[str, Any], *, block_context: Optional[Mapping[str, Any]] = None) -> int:
        tx_type = _tx_type(tx)
        data = str(tx.get("data", tx.get("input", "0x")) or "0x")
        intrinsic = self.intrinsic_gas(tx_type, data)
        recipient = str(tx.get("to") or tx.get("recipient") or "")
        view = NativeStateView(state)
        recipient_code = view.contract_code(recipient) if recipient else "0x"
        if recipient_code == "0x" and (tx_type in {"transfer", "native_transfer"} or data == "0x"):
            return intrinsic
        simulated = self.call(tx, state, block_context=block_context)
        if not simulated.get("ok"):
            raise ValueError(str(simulated.get("error") or "execution reverted"))
        return intrinsic + int(simulated.get("gas_used", 0))

    # ------------------------------------------------------------------
    # Roots / gas / addresses / logs
    # ------------------------------------------------------------------

    def intrinsic_gas(self, tx_type: str, data: Any) -> int:
        payload = _hex_to_bytes(data)
        data_gas = sum(4 if b == 0 else 16 for b in payload)
        normalized = str(tx_type or "transfer").lower()
        if normalized in {"deploy_contract", "create", "contract_create"}:
            return CONTRACT_CREATE_BASE_GAS + data_gas + CODE_DEPOSIT_GAS * len(payload)
        if normalized in {"contract_call", "evm_call", "call"}:
            return CONTRACT_CALL_BASE_GAS + data_gas
        return TRANSFER_BASE_GAS + data_gas

    def derive_contract_address(self, sender: str, nonce: int) -> str:
        normalized = _norm_address(sender)
        if not normalized.startswith("0x") or len(normalized) != 42:
            # Preserve the explicit alias/dev-account lane; canonical Ethereum
            # accounts always take the exact CREATE derivation below.
            seed = {"sender": normalized, "nonce": int(nonce), "chain_id": int(self.chain_id)}
            return "0x" + _hash(seed)[-40:]
        # AGILANG stores the last committed nonce one-based internally, while
        # Ethereum derives CREATE addresses from the sender's zero-based nonce.
        external_nonce = max(0, int(nonce) - 1)
        digest = evm_keccak(ethereum_rlp([bytes.fromhex(normalized[2:]), external_nonce]))
        return "0x" + str(digest)[-40:].lower()

    def state_root(self, state: Mapping[str, Any]) -> str:
        return ethereum_state_root(state)

    def receipts_root(self, receipts: Iterable[Mapping[str, Any]]) -> str:
        return ethereum_receipts_root(receipts)

    def transaction_hash(self, tx: Mapping[str, Any]) -> str:
        return str(tx.get("hash") or _hash(tx))

    def _normalize_logs(self, logs: Iterable[Mapping[str, Any]], *, tx_hash: str, tx_index: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for log_index, item in enumerate(logs):
            log = dict(item)
            log.setdefault("address", ZERO_ADDRESS)
            log.setdefault("topics", [])
            log.setdefault("data", "0x")
            log["address"] = _norm_address(log.get("address")) or ZERO_ADDRESS
            log["topics"] = [str(t) for t in list(log.get("topics") or [])]
            log["data"] = str(log.get("data") or "0x")
            log["tx_hash"] = tx_hash
            log["tx_index"] = int(tx_index)
            log["log_index"] = int(log_index)
            out.append(log)
        return out


# Public factory used by AGILANG runtime import hooks.
def native_execution_client(**kwargs: Any) -> NativeExecutionClient:
    return NativeExecutionClient(**kwargs)


__all__ = [
    "NATIVE_EXECUTION_CLIENT_VERSION",
    "NativeExecutionConfig",
    "NativeExecutionReceipt",
    "NativeExecutionResult",
    "NativeStateView",
    "NativeExecutionClient",
    "native_execution_client",
]
