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

pub use access_control::{AccessController, Action, TierPolicy};
pub use audit::{AuditCategory, AuditEvent, AuditSink, DeterministicAuditLog};
pub use compliance::{ComplianceEngine, ComplianceProfile};
pub use encryption::{
    encrypt_shard_at_rest, compute_shard_digest, decrypt_shard_at_rest, DerivedKey,
    EncryptedShard, EncryptionMetadata, TierEncryptionPolicy, AES_256_GCM_ALGORITHM,
};
pub use error::{SecurityError, SecurityResult};
pub use hardening::HardeningChecklist;
pub use integrity::{
    ArtifactDigest, ArtifactStore, CryptographicDigestVerifier, Ed25519KeyPair,
    InMemoryArtifactStore, IntegrityVerifier, LoadedModel, ManifestShard, SecureModelLoader,
    SecureModelManifest, SignatureEnvelope, SignatureVerifier, ED25519_ALGORITHM,
    SHA256_ALGORITHM,
};
pub use key_management::{KeyAccessPolicy, KeyKind, KeyManager, KeyMaterialRef, KeyRotationPolicy};
pub use memory_safety::{MemorySafetyProfile, UnsafeBlockPolicy};
pub use sandbox::{SandboxConfig, SandboxRuntime};
pub use types::{TierId, fnv64_hex, hex_decode, hex_encode};
pub use zeroization::{
    secure_zeroize_bytes, secure_zeroize_f32, zeroize_session_buffers, SensitiveBytes, Zeroizable,
    ZeroizationEvent, ZeroizationPolicy, ZeroizationTracker,
};
