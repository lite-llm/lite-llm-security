pub mod access_control;
pub mod audit;
pub mod integrity;
pub mod key_management;
pub mod memory_safety;

pub type TierId = u16;

pub use access_control::{Action, AuthorizationDecision, Principal, TierPolicy};
pub use audit::{AuditEvent, AuditSink};
pub use integrity::{ArtifactDigest, IntegrityVerifier};
pub use key_management::{KeyMaterialRef, KeyRotationPolicy};
pub use memory_safety::{MemorySafetyProfile, UnsafeBlockPolicy};
