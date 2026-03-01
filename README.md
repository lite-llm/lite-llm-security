# lite-llm-security

Security controls crate for Lite LLM (`SPEC-051` to `SPEC-060`).

## Scope
Implements deterministic security controls:

- memory-safety policy and unsafe/FFI auditing
- secure model loading with manifest hash/signature and shard digest verification
- encryption at rest and zeroization support
- access control and tier authorization policy
- tamper-evident deterministic audit logging
- key management, sandboxing, compliance, and hardening artifacts

## Modules
- `src/memory_safety.rs`
- `src/integrity.rs`
- `src/encryption.rs`
- `src/zeroization.rs`
- `src/access_control.rs`
- `src/audit.rs`
- `src/key_management.rs`
- `src/sandbox.rs`
- `src/compliance.rs`
- `src/hardening.rs`
- `src/types.rs`
- `src/error.rs`

## Build and Test
```bash
cargo fmt
cargo test
```

## Documentation
- System docs: `../lite-llm-docs/README.md`
- Security docs: `../lite-llm-docs/security/security-model.md`

## Changelog
See `CHANGELOG.md`.

## License
See `LICENSE`.
