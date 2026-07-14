"""Minimal, side-effect-free package surface for the AGILANG compiler distribution.

The full AGILANG language toolkit lives in the main AGILANG repository.  This
distribution intentionally exposes only compiler and EVM helpers so importing
``agilang.agilang_contract_compiler`` cannot pull in web, P2P, ML, or optional
runtime modules that are not part of the reproducible compiler bundle.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "2.1.0"

_LAZY_EXPORTS = {
    "AgilangContractCompileError": ("agilang_contract_compiler", "AgilangContractCompileError"),
    "COMPILER_VERSION": ("agilang_contract_compiler", "COMPILER_VERSION"),
    "compile_agilang_contract": ("agilang_contract_compiler", "compile_agilang_contract"),
    "contract_template_catalog": ("agilang_contract_compiler", "contract_template_catalog"),
    "compile_secure_agilang_contract": (
        "agilang_secure_contract_compiler",
        "compile_secure_agilang_contract",
    ),
    "detect_secure_contract_kind": (
        "agilang_secure_contract_compiler",
        "detect_secure_contract_kind",
    ),
    "secure_contract_template_catalog": (
        "agilang_secure_contract_compiler",
        "secure_contract_template_catalog",
    ),
    "compile_advanced_agilang_contract": (
        "agilang_advanced_contract_compiler",
        "compile_advanced_agilang_contract",
    ),
    "detect_advanced_contract_kind": (
        "agilang_advanced_contract_compiler",
        "detect_advanced_contract_kind",
    ),
    "advanced_contract_template_catalog": (
        "agilang_advanced_contract_compiler",
        "advanced_contract_template_catalog",
    ),
    "evm_function_selector": ("evm", "evm_function_selector"),
    "evm_keccak": ("evm", "evm_keccak"),
}

__all__ = sorted(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(f".{module_name}", __name__), attribute_name)
    globals()[name] = value
    return value
