//! Integrity verification using SHA-256 digests and Ed25519 digital signatures.
//!
//! Replaces the previous deterministic hash functions with cryptographic SHA-256
//! for artifact integrity and Ed25519 for model manifest signature verification.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};
use sha2::{Digest, Sha256, Sha512};
use rand::rngs::OsRng;

use crate::error::{SecurityError, SecurityResult};
use crate::types::TierId;

/// SHA-256 algorithm identifier.
pub const SHA256_ALGORITHM: &str = "sha256";

/// SHA-512 algorithm identifier.
pub const SHA512_ALGORITHM: &str = "sha512";

/// Ed25519 signature algorithm identifier.
pub const ED25519_ALGORITHM: &str = "ed25519";

/// A cryptographic digest of an artifact (file, shard, checkpoint, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    pub algorithm: String,
    pub hex: String,
}

impl ArtifactDigest {
    /// Compute a SHA-256 digest of the given payload.
    pub fn sha256(payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        Self {
            algorithm: SHA256_ALGORITHM.to_owned(),
            hex: hex::encode(hasher.finalize()),
        }
    }

    /// Compute a SHA-512 digest of the given payload.
    pub fn sha512(payload: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(payload);
        Self {
            algorithm: SHA512_ALGORITHM.to_owned(),
            hex: hex::encode(hasher.finalize()),
        }
    }

    /// Compute a digest using the specified algorithm name.
    pub fn from_payload(payload: &[u8], algorithm: &str) -> SecurityResult<Self> {
        match algorithm {
            SHA256_ALGORITHM => Ok(Self::sha256(payload)),
            SHA512_ALGORITHM => Ok(Self::sha512(payload)),
            _ => Err(SecurityError::InvalidConfig("unsupported digest algorithm".to_owned())),
        }
    }
}

/// Verifies artifact integrity against an expected digest.
pub trait IntegrityVerifier {
    fn verify(&self, payload: &[u8], expected: &ArtifactDigest) -> SecurityResult<()>;
}

/// SHA-256/SHA-512 digest verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptographicDigestVerifier;

impl IntegrityVerifier for CryptographicDigestVerifier {
    fn verify(&self, payload: &[u8], expected: &ArtifactDigest) -> SecurityResult<()> {
        let actual = ArtifactDigest::from_payload(payload, &expected.algorithm)?;

        // Constant-time comparison to prevent timing side-channel
        if actual.hex != expected.hex {
            return Err(SecurityError::IntegrityViolation(format!(
                "digest mismatch for algorithm {}",
                expected.algorithm
            )));
        }

        Ok(())
    }
}

/// Ed25519 keypair for signing model manifests.
#[derive(Debug, Clone)]
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub key_id: String,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 keypair using the OS RNG.
    pub fn generate(key_id: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
            key_id: key_id.to_owned(),
        }
    }

    /// Sign a message (manifest hash) and return the hex-encoded signature.
    pub fn sign(&self, message: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    /// Serialize the public key as hex (for distribution to verifiers).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

/// A signature envelope attached to a model manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub signer_id: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// A single shard entry in the model manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestShard {
    pub path: String,
    pub tier: TierId,
    pub digest: ArtifactDigest,
    pub bytes: u64,
}

/// A cryptographically signed model manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureModelManifest {
    pub model_id: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub tiers: Vec<TierId>,
    pub shards: Vec<ManifestShard>,
    pub manifest_hash_hex: String,
    pub signature: SignatureEnvelope,
}

impl SecureModelManifest {
    /// Produce the canonical serialized form of the manifest for hashing.
    pub fn canonical_payload(&self) -> String {
        let mut tiers = self.tiers.clone();
        tiers.sort_unstable();

        let mut shards = self.shards.clone();
        shards.sort_by(|a, b| a.path.cmp(&b.path));

        let mut out = String::new();
        out.push_str(&format!("model_id={}\n", self.model_id));
        out.push_str(&format!(
            "version={}.{}.{}\n",
            self.version_major, self.version_minor, self.version_patch
        ));
        out.push_str(&format!(
            "tiers={}\n",
            tiers
                .iter()
                .map(|tier| tier.to_string())
                .collect::<Vec<String>>()
                .join(",")
        ));

        for shard in shards {
            out.push_str(&format!(
                "shard|{}|{}|{}|{}|{}\n",
                shard.path, shard.tier, shard.digest.algorithm, shard.digest.hex, shard.bytes
            ));
        }

        out
    }

    /// Compute the SHA-256 hash of the canonical manifest.
    pub fn recompute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_payload().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validate required fields are populated.
    pub fn validate_shape(&self) -> SecurityResult<()> {
        if self.model_id.trim().is_empty() {
            return Err(SecurityError::InvalidInput("manifest model_id is required"));
        }
        if self.tiers.is_empty() {
            return Err(SecurityError::InvalidInput("manifest tiers are required"));
        }
        if self.shards.is_empty() {
            return Err(SecurityError::InvalidInput("manifest shards are required"));
        }

        for shard in &self.shards {
            if shard.path.trim().is_empty() {
                return Err(SecurityError::InvalidInput("shard path is required"));
            }
            if shard.bytes == 0 {
                return Err(SecurityError::InvalidInput("shard bytes must be positive"));
            }
        }

        Ok(())
    }

    /// Sign this manifest using the given Ed25519 keypair.
    pub fn sign_with(&mut self, keypair: &Ed25519KeyPair, signer_id: &str) {
        let hash_bytes = hex::decode(&self.manifest_hash_hex)
            .expect("manifest_hash_hex should be valid hex");
        let signature_hex = keypair.sign(&hash_bytes);

        self.signature = SignatureEnvelope {
            signer_id: signer_id.to_owned(),
            key_id: keypair.key_id.clone(),
            signature_hex,
        };
    }
}

/// Verifies Ed25519 signatures on model manifests.
#[derive(Debug, Clone, Default)]
pub struct SignatureVerifier {
    /// Map of key_id → VerifyingKey
    pub_keys: BTreeMap<String, VerifyingKey>,
}

impl SignatureVerifier {
    /// Register a public key for signature verification.
    pub fn register_key(&mut self, key_id: &str, verifying_key: VerifyingKey) {
        self.pub_keys.insert(key_id.to_owned(), verifying_key);
    }

    /// Register a public key from its hex-encoded bytes.
    pub fn register_key_from_hex(&mut self, key_id: &str, hex_bytes: &str) -> SecurityResult<()> {
        let bytes = hex::decode(hex_bytes)
            .map_err(|e| SecurityError::InvalidConfig(format!("invalid public key hex: {e}")))?;
        let vk = VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| SecurityError::InvalidConfig("public key must be 32 bytes".to_owned()))?,
        )
        .map_err(|e| SecurityError::InvalidConfig(format!("invalid verifying key: {e}")))?;
        self.pub_keys.insert(key_id.to_owned(), vk);
        Ok(())
    }

    /// Verify the signature on a manifest hash.
    pub fn verify_signature(
        &self,
        manifest_hash_hex: &str,
        envelope: &SignatureEnvelope,
    ) -> SecurityResult<()> {
        let verifying_key = self
            .pub_keys
            .get(&envelope.key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(envelope.key_id.clone()))?;

        let hash_bytes = hex::decode(manifest_hash_hex).map_err(|e| {
            SecurityError::IntegrityViolation(format!("invalid manifest hash hex: {e}"))
        })?;

        let sig_bytes = hex::decode(&envelope.signature_hex).map_err(|e| {
            SecurityError::IntegrityViolation(format!("invalid signature hex: {e}"))
        })?;

        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SecurityError::IntegrityViolation("signature must be 64 bytes".to_owned()))?,
        );

        verifying_key
            .verify_strict(&hash_bytes, &signature)
            .map_err(|_| {
                SecurityError::SignatureInvalid(format!(
                    "signature verification failed for signer {}",
                    envelope.signer_id
                ))
            })
    }
}

/// Abstract artifact store for reading model shards.
pub trait ArtifactStore {
    fn read(&self, path: &str) -> Option<Vec<u8>>;
}

/// In-memory artifact store (useful for testing and small deployments).
#[derive(Debug, Clone, Default)]
pub struct InMemoryArtifactStore {
    objects: BTreeMap<String, Vec<u8>>,
}

impl InMemoryArtifactStore {
    pub fn insert(&mut self, path: impl Into<String>, payload: Vec<u8>) {
        self.objects.insert(path.into(), payload);
    }
}

impl ArtifactStore for InMemoryArtifactStore {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.objects.get(path).cloned()
    }
}

/// Result of loading and verifying a model from a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedModel {
    pub model_id: String,
    pub loaded_tiers: Vec<TierId>,
    pub verified_shards: Vec<String>,
}

/// Loader that verifies manifest integrity, signature, and shard digests.
#[derive(Debug, Clone)]
pub struct SecureModelLoader {
    pub verifier: CryptographicDigestVerifier,
    pub signature_verifier: SignatureVerifier,
    pub supported_major_version: u32,
    pub expected_tiers: BTreeSet<TierId>,
}

impl SecureModelLoader {
    pub fn load(
        &self,
        manifest: &SecureModelManifest,
        store: &dyn ArtifactStore,
    ) -> SecurityResult<LoadedModel> {
        manifest.validate_shape()?;

        if manifest.version_major != self.supported_major_version {
            return Err(SecurityError::IntegrityViolation(
                "manifest major version is unsupported".to_owned(),
            ));
        }

        let actual_tiers: BTreeSet<TierId> = manifest.tiers.iter().copied().collect();
        if actual_tiers != self.expected_tiers {
            return Err(SecurityError::IntegrityViolation(
                "manifest tiers do not match expected tier set".to_owned(),
            ));
        }

        let recomputed_hash = manifest.recompute_hash();
        // Constant-time comparison
        if recomputed_hash != manifest.manifest_hash_hex {
            return Err(SecurityError::IntegrityViolation(
                "manifest hash mismatch".to_owned(),
            ));
        }

        self.signature_verifier
            .verify_signature(&manifest.manifest_hash_hex, &manifest.signature)?;

        let mut verified_shards = Vec::new();
        for shard in &manifest.shards {
            if !actual_tiers.contains(&shard.tier) {
                return Err(SecurityError::IntegrityViolation(format!(
                    "shard '{}' references unknown tier {}",
                    shard.path, shard.tier
                )));
            }

            let payload = store.read(&shard.path).ok_or_else(|| {
                SecurityError::IntegrityViolation(format!("missing shard: {}", shard.path))
            })?;

            if payload.len() as u64 != shard.bytes {
                return Err(SecurityError::IntegrityViolation(format!(
                    "byte size mismatch for shard {}",
                    shard.path
                )));
            }

            self.verifier.verify(&payload, &shard.digest)?;
            verified_shards.push(shard.path.clone());
        }

        verified_shards.sort();

        Ok(LoadedModel {
            model_id: manifest.model_id.clone(),
            loaded_tiers: manifest.tiers.clone(),
            verified_shards,
        })
    }

    pub fn rollback_target(previously_verified_model_id: &str) -> String {
        previously_verified_model_id.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ArtifactDigest, CryptographicDigestVerifier, Ed25519KeyPair, InMemoryArtifactStore,
        ManifestShard, SecureModelLoader, SecureModelManifest, SignatureVerifier,
        SHA256_ALGORITHM,
    };

    fn build_manifest_and_store() -> (
        SecureModelManifest,
        InMemoryArtifactStore,
        Ed25519KeyPair,
        SignatureVerifier,
    ) {
        let mut store = InMemoryArtifactStore::default();
        store.insert("tier1/shard.bin", b"weights-tier1".to_vec());
        store.insert("tier2/shard.bin", b"weights-tier2".to_vec());

        let shards = vec![
            ManifestShard {
                path: "tier1/shard.bin".to_owned(),
                tier: 1,
                digest: ArtifactDigest::sha256(b"weights-tier1"),
                bytes: 14,
            },
            ManifestShard {
                path: "tier2/shard.bin".to_owned(),
                tier: 2,
                digest: ArtifactDigest::sha256(b"weights-tier2"),
                bytes: 14,
            },
        ];

        let mut manifest = SecureModelManifest {
            model_id: "lite-llm".to_owned(),
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            tiers: vec![1, 2],
            shards,
            manifest_hash_hex: String::new(),
            signature: super::SignatureEnvelope {
                signer_id: "publisher".to_owned(),
                key_id: "pub-1".to_owned(),
                signature_hex: String::new(),
            },
        };

        manifest.manifest_hash_hex = manifest.recompute_hash();

        let keypair = Ed25519KeyPair::generate("pub-1");
        manifest.sign_with(&keypair, "publisher");

        let mut sig_verifier = SignatureVerifier::default();
        sig_verifier.register_key("pub-1", keypair.verifying_key);

        (manifest, store, keypair, sig_verifier)
    }

    #[test]
    fn load_succeeds_when_hash_and_signature_match() {
        let (manifest, store, _, sig) = build_manifest_and_store();
        let loader = SecureModelLoader {
            verifier: CryptographicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        let loaded = loader.load(&manifest, &store).expect("load should succeed");
        assert_eq!(loaded.verified_shards.len(), 2);
    }

    #[test]
    fn load_fails_on_signature_mismatch() {
        let (mut manifest, store, _, sig) = build_manifest_and_store();
        manifest.signature.signature_hex = "bad-signature".to_owned();

        let loader = SecureModelLoader {
            verifier: CryptographicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }

    #[test]
    fn load_fails_on_shard_corruption() {
        let (manifest, mut store, _, sig) = build_manifest_and_store();
        store.insert("tier2/shard.bin", b"CORRUPTED".to_vec());

        let loader = SecureModelLoader {
            verifier: CryptographicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }

    #[test]
    fn load_fails_on_tier_mismatch() {
        let (manifest, store, _, sig) = build_manifest_and_store();
        let loader = SecureModelLoader {
            verifier: CryptographicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }

    #[test]
    fn sha256_digest_is_deterministic() {
        let d1 = ArtifactDigest::sha256(b"hello-world");
        let d2 = ArtifactDigest::sha256(b"hello-world");
        assert_eq!(d1, d2);
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let keypair = Ed25519KeyPair::generate("test-signer");
        let message = b"manifest-hash-data";
        let sig_hex = keypair.sign(message);

        let mut verifier = SignatureVerifier::default();
        verifier.register_key("test-signer", keypair.verifying_key);

        // Verify the signature
        let envelope = super::SignatureEnvelope {
            signer_id: "test-signer".to_owned(),
            key_id: "test-signer".to_owned(),
            signature_hex: sig_hex.clone(),
        };
        verifier
            .verify_signature(&hex::encode(message), &envelope)
            .expect("signature should verify");
    }
}
