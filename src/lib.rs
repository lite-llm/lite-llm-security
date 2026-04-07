pub mod access_control;
pub mod audit;
pub mod compliance;
pub mod encryption;
pub mod error;
pub mod hardening;
pub mod integrity;
pub mod key_management;
pub mod memory_safety;
pub mod sandbox;
pub mod types;
pub mod zeroization;

pub use access_control::{AccessController, Action, AuthorizationDecision, Principal, TierPolicy};
pub use audit::{AuditCategory, AuditEvent, AuditRecord, AuditSink, DeterministicAuditLog};
pub use compliance::{
    ComplianceArtifact, ComplianceEngine, ComplianceProfile, ComplianceReport, Regulation,
};
pub use encryption::{
    decrypt_shard_at_rest, encrypt_shard_at_rest, EncryptedShard, EncryptionMetadata,
    TierEncryptionPolicy,
};
pub use error::{SecurityError, SecurityResult};
pub use hardening::{
    default_incident_response_plan, ChecklistItem, HardeningChecklist, HardeningReport,
    IncidentResponsePlan, Threat,
};
pub use integrity::{
    ArtifactDigest, ArtifactStore, DeterministicDigestVerifier, InMemoryArtifactStore,
    IntegrityVerifier, LoadedModel, ManifestShard, SecureModelLoader, SecureModelManifest,
    SignatureEnvelope, SignatureVerifier,
};
pub use key_management::{KeyAccessPolicy, KeyKind, KeyManager, KeyMaterialRef, KeyRotationPolicy};
pub use memory_safety::{
    audit_memory_safety, FfiBoundaryAudit, MemorySafetyProfile, MemorySafetyReport,
    UnsafeBlockPolicy, UnsafeUsageRecord,
};
pub use sandbox::{Capability, CapabilityToken, ResourceUsage, SandboxConfig, SandboxRuntime};
pub use types::{
    deterministic_hash_hex, fnv64_hex, hex_decode, hex_encode, pseudo_sha256_hex, TierId,
};
pub use zeroization::{
    secure_zeroize_bytes, secure_zeroize_f32, zeroize_session_buffers, SensitiveBytes, Zeroizable,
    ZeroizationEvent, ZeroizationPolicy, ZeroizationTracker,
};
