# lite-llm-security

Security controls crate for Lite LLM (`SPEC-051` to `SPEC-060`).

## Overview
Implements deterministic security controls for integrity verification, authorization, audit logging, and production-grade encryption.

This crate provides the complete security stack: memory-safety policies, secure model loading with cryptographic signature verification, AES-256-GCM encryption at rest, SHA-256/SHA-512 integrity digests, Ed25519 digital signatures for manifest signing, RBAC/tier authorization, tamper-evident audit logs, key management, sandboxing, compliance checks, and deployment hardening artifacts.

## Features

### Feature Flag: `default` (includes `crypto`)
Enables production cryptography: `aes-gcm`, `sha2`, `ed25519-dalek`, and `zeroize` dependencies.

### Feature Flag: `crypto` (enabled by default)
Activates the full cryptographic stack including authenticated encryption, digest computation, and digital signatures.

## Dependencies
| Crate | Version | Purpose |
|-------|---------|---------|
| aes-gcm | 0.10 | AES-256-GCM authenticated encryption |
| sha2 | 0.10 | SHA-256/SHA-512 cryptographic digests |
| ed25519-dalek | 2.1 | Ed25519 digital signatures for manifest signing |
| rand | 0.8 | Cryptographic RNG for key generation |
| hex | 0.4 | Hex encoding for digest/signature serialization |
| zeroize | 1.7 | Secure memory clearing for sensitive data |

## Key Modules
- `memory_safety` — memory-safety policy and unsafe/FFI audit controls
- `integrity` — SHA-256/SHA-512 digests, Ed25519 signatures, secure model manifest/loader
- `encryption` — AES-256-GCM authenticated encryption with per-tier key derivation
- `zeroization` — secure memory zeroization using the `zeroize` crate
- `access_control` — RBAC/tier authorization engine
- `audit` — deterministic tamper-evident audit logging
- `key_management` — key lifecycle and derivation policies
- `sandbox` — sandboxing configuration and runtime
- `compliance` — compliance engine and profiles
- `hardening` — deployment hardening checklist
- `types` — shared type contracts (`TierId`, hex utilities)
- `error` — security error model

## Public API
### Core Types
- `SecureModelManifest` — cryptographically signed model manifest with canonical serialization
- `SecureModelLoader` — end-to-end model loading with integrity + signature + shard digest verification
- `SignatureVerifier` — Ed25519 signature verification with registered public keys
- `Ed25519KeyPair` — Ed25519 keypair generation and signing
- `ArtifactDigest` — SHA-256/SHA-512 cryptographic digest
- `CryptographicDigestVerifier` — constant-time digest comparison
- `DerivedKey` — per-tier key derivation with deterministic nonce encoding
- `EncryptedShard` — AES-256-GCM encrypted shard with auth tag
- `SensitiveBytes` — zeroize-wrapped sensitive byte data

### Core Functions
- `encrypt_shard_at_rest()` — encrypt model shards with AES-256-GCM
- `decrypt_shard_at_rest()` — verify auth tag and decrypt shards
- `compute_shard_digest()` — SHA-256 integrity digest
- `secure_zeroize_bytes()` / `secure_zeroize_f32()` — guaranteed memory clearing
- `zeroize_session_buffers()` — session-end zeroization for keys and KV-cache

### Traits
- `IntegrityVerifier` — trait for digest verification implementations
- `Zeroizable` — trait for types supporting secure zeroization
- `ArtifactStore` — abstract artifact store for reading model shards

## Quick Start
```rust
use lite_llm_security::{
    Ed25519KeyPair, SecureModelManifest, SecureModelLoader,
    SignatureVerifier, ArtifactDigest, ManifestShard,
    InMemoryArtifactStore, CryptographicDigestVerifier,
};
use std::collections::BTreeSet;

// Generate signing keypair
let keypair = Ed25519KeyPair::generate("publisher-1");

// Build manifest with shard digests
let mut manifest = SecureModelManifest {
    model_id: "lite-llm-v1".to_owned(),
    version_major: 1, version_minor: 0, version_patch: 0,
    tiers: vec![1, 2],
    shards: vec![ManifestShard {
        path: "weights.bin".to_owned(),
        tier: 1,
        digest: ArtifactDigest::sha256(b"model-weights"),
        bytes: 13,
    }],
    manifest_hash_hex: String::new(),
    signature: Default::default(),
};
manifest.manifest_hash_hex = manifest.recompute_hash();
manifest.sign_with(&keypair, "publisher");

// Verify and load
let mut verifier = SignatureVerifier::default();
verifier.register_key("publisher-1", keypair.verifying_key);

let loader = SecureModelLoader {
    verifier: CryptographicDigestVerifier,
    signature_verifier: verifier,
    supported_major_version: 1,
    expected_tiers: BTreeSet::from([1, 2]),
};

let mut store = InMemoryArtifactStore::default();
store.insert("weights.bin", b"model-weights".to_vec());
let loaded = loader.load(&manifest, &store).expect("load should succeed");
```

## Running Tests
```bash
cargo fmt
cargo test
```

## Architecture
This crate implements the security layer for the lite-llm platform, providing cryptographic guarantees for model integrity (SHA-256/SHA-512 digests), authenticity (Ed25519 signatures), confidentiality (AES-256-GCM encryption), and memory safety (zeroization). It integrates with `lite-llm-storage` for encrypted checkpoint persistence and with `lite-llm` orchestrator for secure bootstrap.

## Changelog
See `CHANGELOG.md`.

## License
See `LICENSE`.
