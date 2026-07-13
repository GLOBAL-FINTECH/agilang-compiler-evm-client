Library
/
README.md


# AGILANG Smart Contracts EVM Compiler Clients

**Multi-chain smart-contract compilation, deployment artifact generation, and contract verification for EVM-compatible networks.**

AGILANG Smart Contracts EVM Compiler Clients is the public client and integration layer for compiling AGILANG smart contracts to standard EVM artifacts and submitting reproducible verification packages across multiple blockchain networks.

The project is designed to provide one consistent AGILANG workflow for:

- compiling AGILANG source code to EVM bytecode;
- generating ABI, metadata, selectors, event topics, and storage layouts;
- deploying contracts to EVM-compatible networks;
- verifying deployed runtime bytecode;
- publishing source and compiler metadata to supported verification registries;
- integrating native AGILANG verification, explorer APIs, Sourcify-compatible services, and IPFS-based artifact storage.

> AGILANG is a separate smart-contract source language. The EVM executes bytecode and does not require Solidity. External verifiers must, however, be able to reproduce the deployed bytecode with the exact AGILANG compiler version used for the original build.

---

## Project goals

This project aims to provide a universal verification client for AGILANG contracts deployed across EVM-compatible networks.

1. **One compiler interface** — use one AGILANG compiler workflow across supported EVM chains.
2. **Deterministic builds** — the same source, compiler version, settings, and constructor arguments must reproduce the same artifacts.
3. **Standard EVM outputs** — generate ABI, creation bytecode, runtime bytecode, selectors, event topics, storage layouts, and metadata.
4. **Multi-chain verification routing** — select the correct verification adapter according to chain ID.
5. **Native AGILANG verification** — verify AGILANG/SIBAQ deployments through the in-house verifier.
6. **External EVM verification** — submit reproducible verification packages to supported public registries and explorer APIs.
7. **Immutable artifact publication** — publish source bundles, manifests, and proofs to IPFS.
8. **Public compiler distribution** — resolve exact compiler versions through a trusted compiler registry, GitHub Releases, OCI images, or IPFS mirrors.

---

## Verification architecture

Deployment and source verification are separate operations.

### Deployment flow

```text
AGILANG source
      ↓
AGILANG compiler
      ↓
Creation bytecode + ABI + metadata
      ↓
Wallet or deployment client
      ↓
EVM JSON-RPC
      ↓
Contract deployed on destination chain
```

### Verification flow

```text
AGILANG source
      ↓
Exact compiler version and settings
      ↓
Recompile contract
      ↓
Read deployed code with eth_getCode
      ↓
Compare expected and observed runtime bytecode
      ↓
Create verification proof
      ↓
Publish to the selected verification registry
```

A verification badge is not written directly into the contract bytecode. It is normally maintained by an explorer or verification registry after that service independently confirms that the submitted source reproduces the deployed bytecode.

---

## Multi-chain verification routing

The client routes verification according to the destination chain and configured provider.

```text
if chain_id == 1923:
    use AGILANG native verifier
elif chain is supported by a Sourcify-compatible service:
    use Sourcify adapter
elif chain explorer exposes a verification API:
    use explorer adapter
else:
    store local verification proof and publish artifacts to IPFS
```

Recommended provider priority:

1. native AGILANG verifier;
2. chain-specific explorer API;
3. Sourcify-compatible verifier;
4. IPFS publication with local exact-runtime verification;
5. manual verification export.

---

## Core components

### AGILANG compiler client

The compiler client submits source and settings to an installed or remote AGILANG compiler.

Expected artifacts:

```text
Contract.agi
Contract.abi.json
Contract.creation.bin
Contract.runtime.bin
Contract.metadata.json
Contract.storage-layout.json
Contract.selectors.json
Contract.events.json
Contract.verification.json
```

### Compiler registry client

The registry client resolves the exact compiler build needed for reproducible verification.

Example compiler manifest:

```json
{
  "name": "AGILANG",
  "version": "0.5.0",
  "target": "EVM",
  "evm_version": "shanghai",
  "source_commit": "GIT_COMMIT_HASH",
  "source_sha256": "SOURCE_ARCHIVE_SHA256",
  "binary_sha256": "COMPILER_BINARY_SHA256",
  "container": {
    "image": "ghcr.io/your-organization/agilang-compiler",
    "digest": "sha256:OCI_IMAGE_DIGEST"
  },
  "ipfs_cid": "bafy..."
}
```

### EVM RPC client

The RPC client interacts with EVM-compatible nodes through standard JSON-RPC methods:

```text
eth_chainId
eth_sendRawTransaction
eth_getTransactionReceipt
eth_getTransactionByHash
eth_getCode
eth_getBlockByHash
eth_getBlockByNumber
```

### Native AGILANG verifier

The native verifier is intended for AGILANG-owned networks, including SIBAQ deployments.

It verifies:

- chain ID;
- contract address;
- deployment transaction;
- compiler name and version;
- compiler input hash;
- source hash;
- creation bytecode;
- runtime bytecode;
- constructor arguments;
- metadata;
- storage layout;
- observed on-chain runtime code;
- exact or metadata-aware bytecode match.

### Sourcify-compatible adapter

The adapter prepares a standard verification package and submits it to a supported verification service.

AGILANG contracts still require a verifier that understands how to execute the AGILANG compiler. Publishing source and metadata alone does not make an external service capable of compiling AGILANG automatically.

### Explorer adapters

Explorer adapters translate AGILANG verification artifacts into the format expected by a particular explorer.

Typical fields include:

- explorer API URL;
- API key;
- chain ID;
- contract address;
- source bundle;
- ABI;
- compiler version;
- compiler settings;
- constructor arguments;
- optimization settings;
- metadata.

### IPFS publisher

Recommended IPFS package:

```text
source/
  Contract.agi
artifacts/
  Contract.abi.json
  Contract.creation.bin
  Contract.runtime.bin
  Contract.metadata.json
  Contract.storage-layout.json
  Contract.selectors.json
verification/
  compiler-input.json
  verification-proof.json
  checksums-sha256.txt
compiler/
  compiler-manifest.json
```

---

## Repository structure

```text
agilang-evm-verifier-clients/
├── clients/
│   ├── compiler/
│   ├── registry/
│   ├── rpc/
│   ├── sourcify/
│   ├── explorers/
│   ├── ipfs/
│   └── native/
├── schemas/
│   ├── compiler-manifest.schema.json
│   ├── compiler-input.schema.json
│   ├── verification-bundle.schema.json
│   └── verification-result.schema.json
├── examples/
│   ├── erc20/
│   ├── erc721/
│   ├── erc1155/
│   ├── escrow/
│   ├── multisig/
│   └── vault/
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── conformance/
├── docs/
│   ├── compiler-registry.md
│   ├── verification-routing.md
│   ├── explorer-adapters.md
│   └── ipfs-publication.md
├── pyproject.toml
├── Dockerfile
├── LICENSE
├── SECURITY.md
└── README.md
```

---

## Installation

### Python client

```bash
python -m pip install agilang-evm-verifier
```

Development installation:

```bash
git clone https://github.com/YOUR-ORGANIZATION/agilang-evm-verifier-clients.git
cd agilang-evm-verifier-clients
python -m pip install -e .
```

### Container client

```bash
docker pull ghcr.io/YOUR-ORGANIZATION/agilang-evm-verifier:latest
```

For reproducible verification, pin the image by digest:

```bash
docker pull ghcr.io/YOUR-ORGANIZATION/agilang-evm-verifier@sha256:IMAGE_DIGEST
```

---

## Configuration

```env
AGILANG_COMPILER_REGISTRY_URL=https://compiler.agilang.example
AGILANG_COMPILER_VERSION=0.5.0

EVM_RPC_URL=https://rpc.example
EVM_CHAIN_ID=1923

AGILANG_NATIVE_VERIFIER_URL=https://verifier.example
AGILANG_NATIVE_VERIFIER_API_KEY=

SOURCIFY_API_URL=https://sourcify.example
SOURCIFY_ENABLED=true

EXPLORER_API_URL=https://explorer.example/api
EXPLORER_API_KEY=

IPFS_API_URL=http://127.0.0.1:5001
IPFS_GATEWAY_URL=https://ipfs.io/ipfs/
IPFS_PINNING_ENABLED=true

VERIFICATION_TIMEOUT_SECONDS=30
VERIFICATION_MAX_RETRIES=12
```

Do not commit secrets, API keys, wallet seed phrases, or private keys.

---

## Compile an AGILANG contract

```bash
agilang-evm compile \
  --source examples/erc20/UniversalToken.agi \
  --contract UniversalToken \
  --chain-id 1 \
  --evm-version shanghai \
  --output build/UniversalToken
```

Expected output:

```text
build/UniversalToken/
├── UniversalToken.abi.json
├── UniversalToken.creation.bin
├── UniversalToken.runtime.bin
├── UniversalToken.metadata.json
├── UniversalToken.storage-layout.json
├── UniversalToken.selectors.json
└── UniversalToken.verification.json
```

---

## Verify a deployed contract

```bash
agilang-evm verify \
  --chain-id 1 \
  --rpc-url "$ETHEREUM_RPC_URL" \
  --address 0xContractAddress \
  --source examples/erc20/UniversalToken.agi \
  --compiler-version 0.5.0
```

Example result:

```json
{
  "ok": true,
  "status": "VERIFIED",
  "match_type": "EXACT_RUNTIME",
  "chain_id": 1,
  "contract_address": "0xContractAddress",
  "compiler": {
    "name": "AGILANG",
    "version": "0.5.0"
  },
  "expected_runtime_hash": "sha256:...",
  "observed_runtime_hash": "sha256:..."
}
```

---

## Publish verification artifacts to IPFS

```bash
agilang-evm publish-ipfs \
  --build build/UniversalToken \
  --output verification-publication.json
```

Example result:

```json
{
  "ok": true,
  "root_cid": "bafy...",
  "compiler_manifest_cid": "bafy...",
  "source_bundle_cid": "bafy...",
  "verification_bundle_cid": "bafy..."
}
```

---

## Submit to the native AGILANG verifier

```bash
agilang-evm submit \
  --provider agilang-native \
  --chain-id 1923 \
  --address 0xContractAddress \
  --build build/UniversalToken
```

---

## Submit to an external verifier

```bash
agilang-evm submit \
  --provider sourcify \
  --chain-id 1 \
  --address 0xContractAddress \
  --build build/UniversalToken
```

Chain-specific explorer adapter:

```bash
agilang-evm submit \
  --provider explorer \
  --chain-id 1 \
  --address 0xContractAddress \
  --build build/UniversalToken
```

---

## Verification bundle format

```json
{
  "schema": "agilang-verification-bundle/1.0",
  "language": "AGILANG",
  "contract_name": "UniversalToken",
  "chain_id": 1,
  "contract_address": "0xContractAddress",
  "compiler": {
    "name": "AGILANG",
    "version": "0.5.0",
    "evm_version": "shanghai",
    "binary_sha256": "...",
    "container_digest": "sha256:...",
    "source_commit": "..."
  },
  "source": {
    "entry": "UniversalToken.agi",
    "sha256": "...",
    "ipfs_cid": "bafy..."
  },
  "artifacts": {
    "abi_sha256": "...",
    "creation_bytecode_sha256": "...",
    "runtime_bytecode_sha256": "...",
    "metadata_sha256": "..."
  },
  "deployment": {
    "transaction_hash": "0x...",
    "deployer": "0x...",
    "block_number": 12345678
  },
  "verification": {
    "match_type": "EXACT_RUNTIME",
    "expected_runtime_sha256": "...",
    "observed_runtime_sha256": "..."
  }
}
```

---

## Supported contract profiles

### Tokens and digital assets

- ERC20 fixed supply
- ERC20 mintable
- ERC20 burnable
- ERC20 capped
- ERC20 pausable
- ERC721 NFT
- ERC1155 multi-token
- ERC4626 tokenized vault

### Finance and payments

- Payment escrow
- Token vesting
- Staking rewards
- Multisig treasury
- Flash-loan lender
- Constant-product AMM

### Governance and infrastructure

- Governance token
- Governor with timelock
- Transparent proxy
- Minimal proxy factory
- Bridge vault
- ERC4337 smart account
- ERC4337 paymaster

Advanced financial, bridge, proxy, and account-abstraction contracts require independent security review before production use.

---

## Security requirements

A verifier must never trust a submitted `"verified": true` flag.

Verification must be independently established through:

1. compiler identity and version validation;
2. compiler binary or container digest validation;
3. reproducible compilation;
4. source hash validation;
5. compiler-input hash validation;
6. constructor-argument handling;
7. metadata normalization;
8. on-chain runtime retrieval;
9. bytecode comparison;
10. chain ID and contract-address validation.

Recommended controls:

- run compilers inside isolated containers;
- disable unnecessary network access during compilation;
- apply memory and CPU limits;
- verify all compiler hashes;
- pin OCI images by digest;
- preserve historical compiler versions;
- log every verification attempt;
- sign verification results;
- store immutable source and metadata packages;
- never accept private keys through the verification API.

---

## Compiler distribution

Recommended public distribution channels:

```text
Source repository:     GitHub
Versioned binaries:    GitHub Releases
Compiler containers:   GitHub Container Registry
Python client:         PyPI
Immutable mirror:      IPFS
Build provenance:      GitHub artifact attestations
Software inventory:    SPDX or CycloneDX SBOM
```

A verifier should resolve compilers by exact version and immutable digest.

---

## Verification status model

Recommended statuses:

```text
PENDING
COMPILING
BYTECODE_MATCH
BYTECODE_MISMATCH
LOCALLY_VERIFIED
PUBLISHING
PUBLISHED
EXPLORER_VERIFIED
REJECTED
FAILED
```

Recommended match types:

```text
EXACT_RUNTIME
EXACT_CREATION
METADATA_NORMALIZED
PARTIAL
MISMATCH
```

---

## Important limitations

- EVM compatibility does not automatically make external explorers understand AGILANG source.
- Each verifier must support the AGILANG compiler or call a trusted AGILANG compiler service.
- Publishing artifacts to IPFS does not itself create an explorer badge.
- Sourcify or an explorer must independently rebuild and compare the contract.
- A verification result is chain-specific and contract-address-specific.
- The same source deployed to two chains requires two verification records.
- Exact verification may depend on constructor arguments, compiler settings, metadata, optimizer settings, linked libraries, and EVM revision.
- Experimental DeFi, bridge, proxy, and account-abstraction contracts require specialist audits before mainnet use.

---

## Development

Run tests:

```bash
python -m pytest
```

Run conformance checks:

```bash
python -m pytest tests/conformance
```

Run integration tests:

```bash
python -m pytest tests/integration
```

Run static checks:

```bash
python -m ruff check .
python -m mypy clients
```

---

## Contributing

Contributions are welcome for:

- new explorer adapters;
- new chain configurations;
- compiler registry integrations;
- Sourcify-compatible submission formats;
- IPFS publication;
- bytecode normalization;
- constructor-argument extraction;
- metadata parsing;
- verification conformance fixtures;
- security hardening;
- documentation.

Before submitting a pull request:

1. add tests;
2. preserve deterministic output;
3. document new configuration fields;
4. avoid breaking existing compiler manifests;
5. include security considerations;
6. update verification schemas where required.

---

## Responsible disclosure

Do not report security vulnerabilities in public issues.

Send reports to:

```text
security@YOUR-DOMAIN.example
```

Include the affected version, reproduction steps, impact, and suggested mitigation.

---

## License

Add the selected project license in `LICENSE`.

Common choices:

- Apache-2.0 for broad commercial and open-source use;
- MIT for minimal restrictions;
- GPL-3.0 for reciprocal open-source distribution.

The AGILANG compiler, verifier clients, runtime components, and example contracts may use separate licenses. Document every component's license and redistribution terms clearly.

---

## Project status

Current focus:

- deterministic AGILANG-to-EVM compilation;
- exact runtime-bytecode verification;
- native AGILANG/SIBAQ verification;
- external verification adapters;
- compiler registry integration;
- IPFS artifact publication;
- multi-chain verification automation;
- reproducible public compiler distribution.

---

## Summary

```text
Write AGILANG
      ↓
Compile to standard EVM artifacts
      ↓
Deploy to an EVM-compatible chain
      ↓
Read the deployed runtime bytecode
      ↓
Recompile with the exact AGILANG compiler
      ↓
Compare bytecode
      ↓
Publish immutable verification artifacts
      ↓
Submit to the destination chain's supported verifier
```

**One AGILANG source language. One deterministic compiler workflow. Multiple EVM chains. Reproducible contract verification.**
