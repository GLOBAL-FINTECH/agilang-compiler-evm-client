"""AGILANG production language toolkit."""

__version__ = "2.1.0"

from .checker import check_file, check_source
from .lexer import tokenize
from .parser import parse_file, parse_source
from .translator import AGILTranslator
from .typechecker import typecheck_file, typecheck_source
from .realtime import JsonEvent, websocket_listen, websocket_connect, pubsub_bus, realtime_channel
from .web import WebApp, Request, Response, web_app, json_response, html_response, text_response, Model, model, migrate, validate, csrf_protect, auth_required, job_queue, render_ags, seo_tags
from .webrtc import WebRTCSignalServer, webrtc_signal_server, webrtc_offer, webrtc_answer, webrtc_ice
from .security import security_headers, rate_limit, body_limit
from .hybrid_runtime import HybridWebRuntime, NativeNetRuntime, hybrid_web_runtime, native_web_runtime, native_runtime_status, native_runtime_available, native_prebuilt_status, native_prebuilt_runtime_install, native_platform_matrix, agilab_web_runtime, agilab_native_runtime
from .cgi_runtime import discover_shared_hosting, shared_hosting_capabilities, write_shared_hosting_files, run_cgi, run_fastcgi
from .mobile_runtime import mobile_runtime_matrix, mobile_runtime_capabilities, mobile_runtime_doctor, create_mobile_native_bridge

from .lowlevel_network import tcp_listen, tcp_connect, udp_socket, packet_frame, packet_unframe, packet_json, packet_json_parse, gossip_node, lowlevel_network_capabilities
from .evm import evm_capabilities, evm_keccak, evm_function_selector, evm_abi_encode, evm_abi_decode, evm_contract_call_data, evm_bytecode_builder, evm_disassemble, evm_execute, evm_simulate_call, evm_estimate_gas, evm_trace, evm_world_state, evm_interpreter, evm_rpc, evm_rlp_encode, evm_legacy_unsigned_tx, evm_external_engine
from .interop import python_package, python_package_status, native_library, capability_manifest, interop_capabilities, systems_capabilities
from .zk import zk_capabilities, zk_field, zk_circuit, zk_commit, zk_verify_commitment as zk_verify_commit, zk_merkle_tree, zk_merkle_proof, zk_verify_merkle_proof, zk_nullifier, zk_schnorr_keypair, zk_schnorr_prove, zk_schnorr_verify, zk_bridge_status, zk_external_engine, zk_demo_payload

from .blockchain import blockchain_capabilities, blockchain_config, blockchain_mainnet_config, blockchain_transaction, blockchain_merkle_root, blockchain_node, blockchain_devnet, blockchain_consensus_simulation, blockchain_demo, consensus_engine, pos_consensus_engine, dpos_consensus_engine, dev_consensus_engine, BlockchainNode, BlockchainConfig, ProofOfStakeEngine, DelegatedProofOfStakeEngine, DevConsensusEngine, Mempool, ChainDatabase

from .production_hardening import ValidatorSigner, LocalFileSigner, EnvSigner, ExternalCommandSigner, signer_from_config, PeerScoring, DosGuard, SlashingManager, ReadinessGate, generate_local_validator_key
from .p2p_node import P2PNodeService

try:
    from .secp256k1_api import capabilities as secp256k1_capabilities, recover_address as secp256k1_recover_address, recover_public_key as secp256k1_recover_public_key, verify_recoverable as secp256k1_verify_recoverable
except Exception:
    secp256k1_capabilities = None
    secp256k1_recover_address = None
    secp256k1_recover_public_key = None
    secp256k1_verify_recoverable = None

try:
    from .ethereum_consensus_replica import ethereum_consensus_capabilities, ethereum_consensus_replica_config, ethereum_consensus_check, ethereum_consensus_simulation
except Exception:
    ethereum_consensus_capabilities = None
    ethereum_consensus_replica_config = None
    ethereum_consensus_check = None
    ethereum_consensus_simulation = None

try:
    from .beacon import BeaconConfig, BeaconState, BeaconStore, BeaconValidator, beacon_capabilities, create_beacon_state, produce_beacon_block, attest_to_head, process_epoch_finality, fork_choice_head, simulate_beacon
except Exception:
    BeaconConfig = None
    BeaconState = None
    BeaconStore = None
    BeaconValidator = None
    beacon_capabilities = None
    create_beacon_state = None
    produce_beacon_block = None
    attest_to_head = None
    process_epoch_finality = None
    fork_choice_head = None
    simulate_beacon = None

__all__ = [
    "AGILTranslator",
    "check_file",
    "check_source",
    "parse_file",
    "parse_source",
    "tokenize",
    "typecheck_file",
    "typecheck_source",
    "JsonEvent",
    "websocket_listen",
    "websocket_connect",
    "pubsub_bus",
    "realtime_channel",
    "WebApp",
    "Request",
    "Response",
    "web_app",
    "json_response",
    "html_response",
    "text_response",
    "Model",
    "model",
    "migrate",
    "validate",
    "csrf_protect",
    "auth_required",
    "job_queue",
    "render_ags",
    "seo_tags",
    "WebRTCSignalServer",
    "webrtc_signal_server",
    "webrtc_offer",
    "webrtc_answer",
    "webrtc_ice",
    "security_headers",
    "rate_limit",
    "body_limit",
    "HybridWebRuntime",
    "NativeNetRuntime",
    "hybrid_web_runtime",
    "native_web_runtime",
    "native_runtime_status",
    "native_runtime_available",
    "native_prebuilt_status",
    "native_prebuilt_runtime_install",
    "native_platform_matrix",
    "agilab_web_runtime",
    "agilab_native_runtime",
    "discover_shared_hosting",
    "write_shared_hosting_files",
    "run_cgi",
    "run_fastcgi",
    "create_mobile_native_bridge",
    "BeaconConfig",
    "BeaconState",
    "BeaconStore",
    "BeaconValidator",
    "beacon_capabilities",
    "create_beacon_state",
    "produce_beacon_block",
    "attest_to_head",
    "process_epoch_finality",
    "fork_choice_head",
    "simulate_beacon",
]

__all__.extend(["ValidatorSigner", "LocalFileSigner", "EnvSigner", "ExternalCommandSigner", "signer_from_config", "PeerScoring", "DosGuard", "SlashingManager", "ReadinessGate", "generate_local_validator_key", "P2PNodeService"])

from .ml import *
