use std::collections::{BTreeMap, BTreeSet};

use crate::error::{SecurityError, SecurityResult};
use crate::types::{deterministic_hash_hex, fnv64_hex, TierId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    pub algorithm: String,
    pub hex: String,
}

impl ArtifactDigest {
    pub fn from_payload(payload: &[u8], algorithm: &str) -> SecurityResult<Self> {
        let hex = deterministic_hash_hex(algorithm, payload)
            .ok_or(SecurityError::InvalidConfig("unsupported digest algorithm"))?;
        Ok(Self {
            algorithm: algorithm.to_owned(),
            hex,
        })
    }
}

pub trait IntegrityVerifier {
    fn verify(&self, payload: &[u8], expected: &ArtifactDigest) -> SecurityResult<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeterministicDigestVerifier;

impl IntegrityVerifier for DeterministicDigestVerifier {
    fn verify(&self, payload: &[u8], expected: &ArtifactDigest) -> SecurityResult<()> {
        let actual = deterministic_hash_hex(&expected.algorithm, payload)
            .ok_or(SecurityError::InvalidConfig("unsupported digest algorithm"))?;

        if actual != expected.hex {
            return Err(SecurityError::IntegrityViolation(format!(
                "digest mismatch for algorithm {}",
                expected.algorithm
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub signer_id: String,
    pub key_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestShard {
    pub path: String,
    pub tier: TierId,
    pub digest: ArtifactDigest,
    pub bytes: u64,
}

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

    pub fn recompute_hash(&self) -> String {
        fnv64_hex(self.canonical_payload().as_bytes())
    }

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
}

#[derive(Debug, Clone, Default)]
pub struct SignatureVerifier {
    pub_keys: BTreeMap<String, String>,
}

impl SignatureVerifier {
    pub fn register_key(&mut self, key_id: &str, public_key_material: &str) {
        self.pub_keys
            .insert(key_id.to_owned(), public_key_material.to_owned());
    }

    pub fn verify_signature(
        &self,
        manifest_hash_hex: &str,
        envelope: &SignatureEnvelope,
    ) -> SecurityResult<()> {
        let public_key = self
            .pub_keys
            .get(&envelope.key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(envelope.key_id.clone()))?;

        let expected = signature_material(public_key, &envelope.signer_id, manifest_hash_hex);
        if expected != envelope.signature_hex {
            return Err(SecurityError::SignatureInvalid(format!(
                "signature mismatch for signer {}",
                envelope.signer_id
            )));
        }

        Ok(())
    }

    pub fn sign_for_testing(
        public_key_material: &str,
        signer_id: &str,
        manifest_hash_hex: &str,
    ) -> String {
        signature_material(public_key_material, signer_id, manifest_hash_hex)
    }
}

fn signature_material(
    public_key_material: &str,
    signer_id: &str,
    manifest_hash_hex: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}",
        public_key_material, signer_id, manifest_hash_hex
    );
    fnv64_hex(payload.as_bytes())
}

pub trait ArtifactStore {
    fn read(&self, path: &str) -> Option<Vec<u8>>;
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedModel {
    pub model_id: String,
    pub loaded_tiers: Vec<TierId>,
    pub verified_shards: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecureModelLoader {
    pub verifier: DeterministicDigestVerifier,
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
        ArtifactDigest, DeterministicDigestVerifier, InMemoryArtifactStore, ManifestShard,
        SecureModelLoader, SecureModelManifest, SignatureEnvelope, SignatureVerifier,
    };

    fn build_manifest_and_store() -> (
        SecureModelManifest,
        InMemoryArtifactStore,
        SignatureVerifier,
    ) {
        let mut store = InMemoryArtifactStore::default();
        store.insert("tier1/shard.bin", b"weights-tier1".to_vec());
        store.insert("tier2/shard.bin", b"weights-tier2".to_vec());

        let shards = vec![
            ManifestShard {
                path: "tier1/shard.bin".to_owned(),
                tier: 1,
                digest: ArtifactDigest::from_payload(b"weights-tier1", "sha256")
                    .expect("digest should build"),
                bytes: 13,
            },
            ManifestShard {
                path: "tier2/shard.bin".to_owned(),
                tier: 2,
                digest: ArtifactDigest::from_payload(b"weights-tier2", "sha256")
                    .expect("digest should build"),
                bytes: 13,
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
            signature: SignatureEnvelope {
                signer_id: "publisher".to_owned(),
                key_id: "pub-1".to_owned(),
                signature_hex: String::new(),
            },
        };

        manifest.manifest_hash_hex = manifest.recompute_hash();
        let pub_material = "publisher-public-material";
        manifest.signature.signature_hex = SignatureVerifier::sign_for_testing(
            pub_material,
            &manifest.signature.signer_id,
            &manifest.manifest_hash_hex,
        );

        let mut sig = SignatureVerifier::default();
        sig.register_key("pub-1", pub_material);

        (manifest, store, sig)
    }

    #[test]
    fn load_succeeds_when_hash_and_signature_match() {
        let (manifest, store, sig) = build_manifest_and_store();
        let loader = SecureModelLoader {
            verifier: DeterministicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        let loaded = loader.load(&manifest, &store).expect("load should succeed");
        assert_eq!(loaded.verified_shards.len(), 2);
    }

    #[test]
    fn load_fails_on_signature_mismatch() {
        let (mut manifest, store, sig) = build_manifest_and_store();
        manifest.signature.signature_hex = "bad-signature".to_owned();

        let loader = SecureModelLoader {
            verifier: DeterministicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }

    #[test]
    fn load_fails_on_shard_corruption() {
        let (manifest, mut store, sig) = build_manifest_and_store();
        store.insert("tier2/shard.bin", b"CORRUPTED".to_vec());

        let loader = SecureModelLoader {
            verifier: DeterministicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1, 2]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }

    #[test]
    fn load_fails_on_tier_mismatch() {
        let (manifest, store, sig) = build_manifest_and_store();
        let loader = SecureModelLoader {
            verifier: DeterministicDigestVerifier,
            signature_verifier: sig,
            supported_major_version: 1,
            expected_tiers: BTreeSet::from([1]),
        };

        assert!(loader.load(&manifest, &store).is_err());
    }
}
