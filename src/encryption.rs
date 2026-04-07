use std::collections::{BTreeMap, BTreeSet};

use crate::error::{SecurityError, SecurityResult};
use crate::key_management::KeyMaterialRef;
use crate::types::{fnv64_hex, hex_decode, hex_encode, TierId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub tier: TierId,
    pub key_id: String,
    pub key_version: u32,
    pub iv_hex: String,
    pub auth_tag_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShard {
    pub ciphertext: Vec<u8>,
    pub metadata: EncryptionMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierEncryptionPolicy {
    pub required_encrypted_tiers: BTreeSet<TierId>,
    pub tier_key_map: BTreeMap<TierId, String>,
}

impl TierEncryptionPolicy {
    pub fn key_for_tier(&self, tier: TierId) -> Option<&str> {
        self.tier_key_map.get(&tier).map(|value| value.as_str())
    }

    pub fn requires_encryption(&self, tier: TierId) -> bool {
        self.required_encrypted_tiers.contains(&tier)
    }
}

pub fn encrypt_shard_at_rest(
    plaintext: &[u8],
    tier: TierId,
    key_ref: &KeyMaterialRef,
    key_bytes: &[u8],
    seed: u64,
) -> SecurityResult<EncryptedShard> {
    if key_bytes.is_empty() {
        return Err(SecurityError::EncryptionFailed(
            "key material must not be empty",
        ));
    }

    let iv_hex =
        fnv64_hex(format!("{}|{}|{}|{}", key_ref.key_id, key_ref.version, tier, seed).as_bytes());

    let iv_bytes =
        hex_decode(&iv_hex).ok_or(SecurityError::EncryptionFailed("invalid IV encoding"))?;
    let keystream = derive_keystream(key_bytes, &iv_bytes, plaintext.len());

    let ciphertext = plaintext
        .iter()
        .zip(keystream.iter())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .collect::<Vec<u8>>();

    let auth_tag_hex = compute_auth_tag(key_bytes, &iv_bytes, &ciphertext, tier);

    Ok(EncryptedShard {
        ciphertext,
        metadata: EncryptionMetadata {
            algorithm: "xor-stream-v1".to_owned(),
            tier,
            key_id: key_ref.key_id.clone(),
            key_version: key_ref.version,
            iv_hex,
            auth_tag_hex,
        },
    })
}

pub fn decrypt_shard_at_rest(
    encrypted: &EncryptedShard,
    key_ref: &KeyMaterialRef,
    key_bytes: &[u8],
) -> SecurityResult<Vec<u8>> {
    if encrypted.metadata.key_id != key_ref.key_id
        || encrypted.metadata.key_version != key_ref.version
    {
        return Err(SecurityError::DecryptionFailed(
            "key reference does not match encrypted metadata",
        ));
    }

    let iv_bytes = hex_decode(&encrypted.metadata.iv_hex)
        .ok_or(SecurityError::DecryptionFailed("invalid IV encoding"))?;
    let expected_tag = compute_auth_tag(
        key_bytes,
        &iv_bytes,
        &encrypted.ciphertext,
        encrypted.metadata.tier,
    );
    if expected_tag != encrypted.metadata.auth_tag_hex {
        return Err(SecurityError::IntegrityViolation(
            "authentication tag mismatch".to_owned(),
        ));
    }

    let keystream = derive_keystream(key_bytes, &iv_bytes, encrypted.ciphertext.len());
    let plaintext = encrypted
        .ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .collect::<Vec<u8>>();

    Ok(plaintext)
}

fn derive_keystream(key: &[u8], iv: &[u8], len: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(len);
    let mut counter = 0_u64;

    while stream.len() < len {
        let payload = format!("{}|{}|{}", hex_encode(key), hex_encode(iv), counter);
        let block = fnv64_hex(payload.as_bytes());
        stream.extend_from_slice(block.as_bytes());
        counter = counter.wrapping_add(1);
    }

    stream.truncate(len);
    stream
}

fn compute_auth_tag(key: &[u8], iv: &[u8], ciphertext: &[u8], tier: TierId) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(key);
    payload.extend_from_slice(iv);
    payload.extend_from_slice(&tier.to_le_bytes());
    payload.extend_from_slice(ciphertext);
    fnv64_hex(&payload)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{decrypt_shard_at_rest, encrypt_shard_at_rest, TierEncryptionPolicy};
    use crate::key_management::{KeyKind, KeyMaterialRef};

    fn key_ref() -> KeyMaterialRef {
        KeyMaterialRef {
            key_id: "model-key".to_owned(),
            version: 1,
            kind: KeyKind::Encryption,
        }
    }

    #[test]
    fn encryption_roundtrip_succeeds() {
        let key_ref = key_ref();
        let encrypted = encrypt_shard_at_rest(b"secret-weights", 2, &key_ref, b"key-material", 42)
            .expect("encryption should succeed");
        let decrypted = decrypt_shard_at_rest(&encrypted, &key_ref, b"key-material")
            .expect("decryption should succeed");

        assert_eq!(decrypted, b"secret-weights");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key_ref = key_ref();
        let mut encrypted =
            encrypt_shard_at_rest(b"secret-weights", 2, &key_ref, b"key-material", 42)
                .expect("encryption should succeed");
        encrypted.ciphertext[0] ^= 0xAB;

        assert!(decrypt_shard_at_rest(&encrypted, &key_ref, b"key-material").is_err());
    }

    #[test]
    fn tier_policy_maps_keys() {
        let policy = TierEncryptionPolicy {
            required_encrypted_tiers: BTreeSet::from([2, 3]),
            tier_key_map: BTreeMap::from([(2_u16, "k2".to_owned()), (3_u16, "k3".to_owned())]),
        };

        assert!(policy.requires_encryption(2));
        assert_eq!(policy.key_for_tier(3), Some("k3"));
    }
}
