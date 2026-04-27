//! Real production-grade encryption using AES-256-GCM authenticated encryption.
//!
//! Replaces the previous XOR-stream cipher with industry-standard AEAD encryption.
//! Supports per-tier key derivation, nonce generation, and authenticated decryption.

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{SecurityError, SecurityResult};
use crate::key_management::KeyMaterialRef;
use crate::types::TierId;

/// AES-256-GCM algorithm identifier.
pub const AES_256_GCM_ALGORITHM: &str = "aes-256-gcm-v1";

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Derived key material from a master key using HKDF (RFC 5869).
#[derive(Debug, Clone)]
pub struct DerivedKey {
    pub bytes: [u8; 32],
    pub nonce: [u8; AES_GCM_NONCE_SIZE],
}

impl DerivedKey {
    /// Derive an encryption key and nonce from a master key, tier, and seed using HKDF.
    /// Uses HKDF-SHA256 for standard-compliant key derivation.
    /// The nonce encodes the seed directly so it can be re-derived during decryption.
    pub fn derive(master_key: &[u8], tier: TierId, seed: u64) -> Self {
        // Derive the 256-bit key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(master_key), b"lite-llm-derivation");

        let mut bytes = [0u8; 32];
        // HKDF-Expand with tier and seed as info
        let info = format!("{}:{}", tier, seed);
        hk.expand(info.as_bytes(), &mut bytes)
            .expect("256-bit output from HKDF-SHA256 is valid");

        // Encode nonce: 4-byte context prefix + 8-byte big-endian seed
        // This allows re-deriving the key from the nonce during decryption.
        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        nonce[0..4].copy_from_slice(&[0x4C, 0x4C, 0x4D, 0x4B]); // "LLMK"
        nonce[4..12].copy_from_slice(&seed.to_be_bytes());

        Self { bytes, nonce }
    }
}

/// Metadata attached to an encrypted shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub tier: TierId,
    pub key_id: String,
    pub key_version: u32,
    pub nonce_hex: String,
    pub auth_tag_hex: String,
}

/// An encrypted shard with AES-256-GCM ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShard {
    /// The ciphertext (includes AES-GCM auth tag appended by the library).
    pub ciphertext: Vec<u8>,
    pub metadata: EncryptionMetadata,
}

/// Per-tier encryption policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierEncryptionPolicy {
    pub required_encrypted_tiers: BTreeSet<TierId>,
    pub tier_key_map: BTreeMap<TierId, String>,
}

impl TierEncryptionPolicy {
    pub fn key_for_tier(&self, tier: TierId) -> Option<&str> {
        self.tier_key_map.get(&tier).map(|v| v.as_str())
    }

    pub fn requires_encryption(&self, tier: TierId) -> bool {
        self.required_encrypted_tiers.contains(&tier)
    }
}

/// Encrypt a shard using AES-256-GCM authenticated encryption.
///
/// The authentication tag is produced by AES-GCM and appended to the ciphertext.
/// On decryption, the tag is verified before any plaintext is returned.
pub fn encrypt_shard_at_rest(
    plaintext: &[u8],
    tier: TierId,
    key_ref: &KeyMaterialRef,
    key_bytes: &[u8],
    seed: u64,
) -> SecurityResult<EncryptedShard> {
    if key_bytes.is_empty() {
        return Err(SecurityError::EncryptionFailed(
            "key material must not be empty".to_owned(),
        ));
    }

    // Derive a 256-bit key and 96-bit nonce from the master key
    let derived = DerivedKey::derive(key_bytes, tier, seed);
    let cipher = Aes256Gcm::new_from_slice(&derived.bytes)
        .map_err(|e| SecurityError::EncryptionFailed(format!("invalid derived key: {e}")))?;

    let nonce = Nonce::from_slice(&derived.nonce);

    // AES-256-GCM encrypts and authenticates in one step.
    // The auth tag is appended to the ciphertext.
    let ciphertext_with_tag = cipher
        .encrypt(nonce, Payload::from(plaintext))
        .map_err(|e| SecurityError::EncryptionFailed(format!("aes-gcm encryption failed: {e}")))?;

    // Extract the 16-byte auth tag (last 16 bytes of AES-GCM output)
    let tag_start = ciphertext_with_tag.len().saturating_sub(16);
    let auth_tag_hex = hex::encode(&ciphertext_with_tag[tag_start..]);

    Ok(EncryptedShard {
        ciphertext: ciphertext_with_tag,
        metadata: EncryptionMetadata {
            algorithm: AES_256_GCM_ALGORITHM.to_owned(),
            tier,
            key_id: key_ref.key_id.clone(),
            key_version: key_ref.version,
            nonce_hex: hex::encode(&derived.nonce),
            auth_tag_hex,
        },
    })
}

/// Decrypt a shard using AES-256-GCM authenticated encryption.
///
/// Verifies the authentication tag before returning plaintext.
/// Returns an integrity violation if the tag is invalid or the key mismatches.
pub fn decrypt_shard_at_rest(
    encrypted: &EncryptedShard,
    key_ref: &KeyMaterialRef,
    key_bytes: &[u8],
) -> SecurityResult<Vec<u8>> {
    if encrypted.metadata.key_id != key_ref.key_id
        || encrypted.metadata.key_version != key_ref.version
    {
        return Err(SecurityError::DecryptionFailed(
            "key reference does not match encrypted metadata".to_owned(),
        ));
    }

    // Re-derive the same key and nonce
    let seed = extract_seed_from_nonce(&encrypted.metadata.nonce_hex)?;
    let derived = DerivedKey::derive(key_bytes, encrypted.metadata.tier, seed);
    let cipher = Aes256Gcm::new_from_slice(&derived.bytes)
        .map_err(|e| SecurityError::DecryptionFailed(format!("invalid derived key: {e}")))?;

    let nonce = Nonce::from_slice(&derived.nonce);

    // AES-256-GCM decrypt verifies the auth tag before returning plaintext
    let plaintext = cipher
        .decrypt(nonce, Payload::from(encrypted.ciphertext.as_slice()))
        .map_err(|_| {
            SecurityError::IntegrityViolation(
                "authentication tag mismatch or corrupted ciphertext".to_owned(),
            )
        })?;

    Ok(plaintext)
}

/// Compute the per-shard SHA-256 integrity digest.
pub fn compute_shard_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Extract the seed value encoded in a nonce for key re-derivation.
fn extract_seed_from_nonce(nonce_hex: &str) -> SecurityResult<u64> {
    let nonce = hex::decode(nonce_hex)
        .map_err(|e| SecurityError::DecryptionFailed(format!("invalid nonce hex: {e}")))?;
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(SecurityError::DecryptionFailed(
            "nonce must be 12 bytes".to_owned(),
        ));
    }
    // Seed is stored in bytes 4..12 of the 12-byte nonce
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&nonce[4..12]);
    Ok(u64::from_be_bytes(seed_bytes))
}

#[cfg(test)]
mod tests {
    use super::{decrypt_shard_at_rest, encrypt_shard_at_rest, TierEncryptionPolicy};
    use crate::key_management::{KeyKind, KeyMaterialRef};
    use std::collections::{BTreeMap, BTreeSet};

    fn test_key_ref() -> KeyMaterialRef {
        KeyMaterialRef {
            key_id: "aes-model-key".to_owned(),
            version: 1,
            kind: KeyKind::Encryption,
        }
    }

    #[test]
    fn aes_gcm_encryption_roundtrip() {
        let key_ref = test_key_ref();
        let plaintext = b"secret-transformer-weights-v2";
        let encrypted =
            encrypt_shard_at_rest(plaintext, 2, &key_ref, b"master-key-32-bytes!!!", 42)
                .expect("encryption should succeed");

        // Ciphertext must differ from plaintext
        assert_ne!(encrypted.ciphertext.as_slice(), plaintext);

        let decrypted = decrypt_shard_at_rest(&encrypted, &key_ref, b"master-key-32-bytes!!!")
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key_ref = test_key_ref();
        let mut encrypted = encrypt_shard_at_rest(
            b"secret-weights",
            2,
            &key_ref,
            b"master-key-32-bytes!!!",
            42,
        )
        .expect("encryption should succeed");

        // Flip a byte of ciphertext
        encrypted.ciphertext[0] ^= 0xAB;

        // AES-GCM must reject this before returning any plaintext
        let result = decrypt_shard_at_rest(&encrypted, &key_ref, b"master-key-32-bytes!!!");
        assert!(result.is_err(), "AES-GCM must reject tampered ciphertext");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key_ref = test_key_ref();
        let encrypted =
            encrypt_shard_at_rest(b"secret-data", 2, &key_ref, b"master-key-32-bytes!!!", 42)
                .expect("encryption should succeed");

        // Attempt decryption with wrong key
        let result = decrypt_shard_at_rest(&encrypted, &key_ref, b"wrong-master-key-32-bytes!!!!");
        assert!(
            result.is_err(),
            "AES-GCM must reject wrong key (tag mismatch)"
        );
    }

    #[test]
    fn different_seeds_produce_different_ciphertexts() {
        let key_ref = test_key_ref();
        let e1 =
            encrypt_shard_at_rest(b"same-plaintext", 1, &key_ref, b"master-key-32-bytes!!!", 1)
                .unwrap();
        let e2 = encrypt_shard_at_rest(
            b"same-plaintext",
            1,
            &key_ref,
            b"master-key-32-bytes!!!",
            999,
        )
        .unwrap();

        assert_ne!(e1.ciphertext, e2.ciphertext);
        assert_ne!(e1.metadata.nonce_hex, e2.metadata.nonce_hex);
    }

    #[test]
    fn tier_policy_maps_keys() {
        let policy = TierEncryptionPolicy {
            required_encrypted_tiers: BTreeSet::from([2, 3]),
            tier_key_map: BTreeMap::from([(2_u16, "k2".to_owned()), (3_u16, "k3".to_owned())]),
        };

        assert!(policy.requires_encryption(2));
        assert!(!policy.requires_encryption(1));
        assert_eq!(policy.key_for_tier(3), Some("k3"));
    }

    #[test]
    fn large_data_encryption() {
        let key_ref = test_key_ref();
        // Encrypt a 1MB payload
        let large_data = vec![0xAB_u8; 1024 * 1024];
        let encrypted =
            encrypt_shard_at_rest(&large_data, 3, &key_ref, b"master-key-32-bytes!!!", 0)
                .expect("large data encryption should succeed");

        let decrypted = decrypt_shard_at_rest(&encrypted, &key_ref, b"master-key-32-bytes!!!")
            .expect("large data decryption should succeed");
        assert_eq!(decrypted, large_data);
    }
}

#[cfg(all(test, feature = "crypto"))]
mod proptest_tests {
    use super::*;
    use crate::key_management::KeyKind;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encryption_roundtrip_any_input(
            tier in 0u16..100,
            seed in 0u64..1000,
            key_ref_version in 1u32..10,
        ) {
            let key_ref = KeyMaterialRef {
                key_id: "prop-test-key".to_owned(),
                version: key_ref_version,
                kind: KeyKind::Encryption,
            };
            let plaintext = vec![0x42; 256];
            let key = b"master-key-32-bytes-test!!";

            let encrypted = encrypt_shard_at_rest(&plaintext, tier, &key_ref, key, seed).unwrap();
            let decrypted = decrypt_shard_at_rest(&encrypted, &key_ref, key).unwrap();

            prop_assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn derived_key_deterministic(tier in 0u16..100, seed in 0u64..1000) {
            let key = b"deterministic-key-32-test!!";
            let derived1 = DerivedKey::derive(key, tier, seed);
            let derived2 = DerivedKey::derive(key, tier, seed);

            prop_assert_eq!(derived1.bytes, derived2.bytes, "HKDF should be deterministic");
            prop_assert_eq!(derived1.nonce, derived2.nonce, "nonce encoding should be deterministic");
        }

        #[test]
        fn different_tiers_produce_different_keys(tier_a in 0u16..50, tier_b in 51u16..100) {
            let key = b"test-key-32-bytes-different!";

            prop_assert_ne!(tier_a, tier_b, "test setup sanity check");

            let derived_a = DerivedKey::derive(key, tier_a, 42);
            let derived_b = DerivedKey::derive(key, tier_b, 42);

            prop_assert_ne!(derived_a.bytes, derived_b.bytes, "different tiers should give different keys");
        }

        #[test]
        fn different_seeds_produce_different_keys(seed_a in 0u64..500, seed_b in 500u64..1000) {
            let key = b"test-key-seed-variation!!";

            prop_assert_ne!(seed_a, seed_b, "test setup sanity check");

            let derived_a = DerivedKey::derive(key, 1, seed_a);
            let derived_b = DerivedKey::derive(key, 1, seed_b);

            prop_assert_ne!(derived_a.bytes, derived_b.bytes, "different seeds should give different keys");
        }
    }
}
