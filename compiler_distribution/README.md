# AGILANG reproducible EVM compiler distribution

This directory turns an AGILANG compiler release into a content-addressed artifact that explorers, RPC operators, CI systems, and independent verifiers can run without trusting a gateway database.

## Trust model

1. Publish `manifest.json` and the deterministic ZIP from `build_release.py` in a signed Git tag/GitHub Release.
2. Publish the container from `Dockerfile` to a registry that exposes an immutable OCI digest.
3. Sign the Git tag, ZIP checksum, manifest and OCI digest with the same documented release identity (Sigstore/cosign is recommended).
4. Mirrors verify every file with `verify_install.py`; explorers compile `sourceCode` with the manifest-selected compiler and compare exact runtime bytes.

## Local verification and service

```powershell
python compiler_distribution/verify_install.py
python compiler_distribution/build_release.py
$env:AGILANG_COMPILER_PORT=8090
python compiler_distribution/compiler_service.py
```

Endpoints:

- `GET /health`
- `GET /v1/manifest`
- `POST /v1/compile`
- `POST /api/contracts/verify` (`AGILANG-VERIFICATION-RELAY/1.0` compatible)

Public hosting is a release operation, not a source-code change. Use at least two independent hosts (for example GitHub Releases plus an OCI registry) and publish immutable hashes rather than a mutable "latest" URL.
