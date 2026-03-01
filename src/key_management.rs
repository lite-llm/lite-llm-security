use std::collections::{BTreeMap, BTreeSet};

use crate::error::{SecurityError, SecurityResult};
use crate::types::fnv64_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    Encryption,
    Signature,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMaterialRef {
    pub key_id: String,
    pub version: u32,
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRotationPolicy {
    pub rotate_every_days: u32,
    pub overlap_days: u32,
}

impl KeyRotationPolicy {
    pub fn is_valid(self) -> bool {
        self.rotate_every_days > 0 && self.overlap_days <= self.rotate_every_days
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAccessPolicy {
    pub identity: String,
    pub allowed_key_ids: BTreeSet<String>,
    pub allowed_kinds: BTreeSet<KeyKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedKey {
    reference: KeyMaterialRef,
    material: Vec<u8>,
    activated_day: u32,
    expires_day: u32,
    revoked: bool,
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    rotation_policy: KeyRotationPolicy,
    keys: BTreeMap<String, Vec<ManagedKey>>,
    policies: BTreeMap<String, KeyAccessPolicy>,
}

impl KeyManager {
    pub fn new(rotation_policy: KeyRotationPolicy) -> SecurityResult<Self> {
        if !rotation_policy.is_valid() {
            return Err(SecurityError::InvalidConfig("invalid key rotation policy"));
        }

        Ok(Self {
            rotation_policy,
            keys: BTreeMap::new(),
            policies: BTreeMap::new(),
        })
    }

    pub fn add_access_policy(&mut self, policy: KeyAccessPolicy) {
        self.policies.insert(policy.identity.clone(), policy);
    }

    pub fn generate_key(
        &mut self,
        key_id: &str,
        kind: KeyKind,
        version: u32,
        activated_day: u32,
        seed: u64,
    ) -> SecurityResult<KeyMaterialRef> {
        if key_id.trim().is_empty() {
            return Err(SecurityError::InvalidInput("key_id must not be empty"));
        }
        if version == 0 {
            return Err(SecurityError::InvalidInput(
                "key version must be greater than zero",
            ));
        }

        let material = derive_key_material(key_id, kind, version, seed);
        let reference = KeyMaterialRef {
            key_id: key_id.to_owned(),
            version,
            kind,
        };

        let managed = ManagedKey {
            reference: reference.clone(),
            material,
            activated_day,
            expires_day: activated_day + self.rotation_policy.rotate_every_days,
            revoked: false,
        };

        self.keys
            .entry(key_id.to_owned())
            .or_default()
            .push(managed);
        self.keys
            .get_mut(key_id)
            .expect("key bucket should exist")
            .sort_by_key(|key| key.reference.version);

        Ok(reference)
    }

    pub fn rotate_key(
        &mut self,
        key_id: &str,
        day: u32,
        seed: u64,
    ) -> SecurityResult<KeyMaterialRef> {
        let versions = self
            .keys
            .get(key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(key_id.to_owned()))?;
        let latest = versions
            .last()
            .ok_or_else(|| SecurityError::KeyNotFound(key_id.to_owned()))?;

        self.generate_key(
            key_id,
            latest.reference.kind,
            latest.reference.version + 1,
            day,
            seed,
        )
    }

    pub fn revoke_key(&mut self, key_id: &str, version: u32) -> SecurityResult<()> {
        let versions = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(key_id.to_owned()))?;

        let mut found = false;
        for key in versions {
            if key.reference.version == version {
                key.revoked = true;
                found = true;
                break;
            }
        }

        if !found {
            return Err(SecurityError::KeyNotFound(format!(
                "{}@{}",
                key_id, version
            )));
        }

        Ok(())
    }

    pub fn retrieve_key(
        &self,
        identity: &str,
        reference: &KeyMaterialRef,
        day: u32,
    ) -> SecurityResult<Vec<u8>> {
        self.authorize(identity, reference)?;

        let versions = self
            .keys
            .get(&reference.key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(reference.key_id.clone()))?;
        let key = versions
            .iter()
            .find(|key| key.reference.version == reference.version)
            .ok_or_else(|| {
                SecurityError::KeyNotFound(format!("{}@{}", reference.key_id, reference.version))
            })?;

        if key.revoked {
            return Err(SecurityError::KeyRevoked(format!(
                "{}@{}",
                key.reference.key_id, key.reference.version
            )));
        }

        if day > key.expires_day + self.rotation_policy.overlap_days {
            return Err(SecurityError::KeyRevoked(format!(
                "{}@{} expired",
                key.reference.key_id, key.reference.version
            )));
        }

        Ok(key.material.clone())
    }

    fn authorize(&self, identity: &str, reference: &KeyMaterialRef) -> SecurityResult<()> {
        let policy = self.policies.get(identity).ok_or_else(|| {
            SecurityError::Unauthorized(format!("identity '{}' has no key policy", identity))
        })?;

        if !policy.allowed_key_ids.contains(&reference.key_id) {
            return Err(SecurityError::Unauthorized(format!(
                "identity '{}' not allowed for key '{}'",
                identity, reference.key_id
            )));
        }
        if !policy.allowed_kinds.contains(&reference.kind) {
            return Err(SecurityError::Unauthorized(format!(
                "identity '{}' not allowed for key kind {:?}",
                identity, reference.kind
            )));
        }

        Ok(())
    }
}

fn derive_key_material(key_id: &str, kind: KeyKind, version: u32, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0_u64;

    while out.len() < 32 {
        let payload = format!("{}|{:?}|{}|{}|{}", key_id, kind, version, seed, counter);
        let hash = fnv64_hex(payload.as_bytes());
        out.extend_from_slice(hash.as_bytes());
        counter += 1;
    }

    out.truncate(32);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{KeyAccessPolicy, KeyKind, KeyManager, KeyRotationPolicy};

    fn manager() -> KeyManager {
        let mut manager = KeyManager::new(KeyRotationPolicy {
            rotate_every_days: 30,
            overlap_days: 7,
        })
        .expect("manager should initialize");

        manager.add_access_policy(KeyAccessPolicy {
            identity: "loader".to_owned(),
            allowed_key_ids: BTreeSet::from(["model-key".to_owned()]),
            allowed_kinds: BTreeSet::from([KeyKind::Encryption]),
        });

        manager
    }

    #[test]
    fn retrieval_requires_authorization() {
        let mut manager = manager();
        let key = manager
            .generate_key("model-key", KeyKind::Encryption, 1, 0, 42)
            .expect("key should generate");

        assert!(manager.retrieve_key("loader", &key, 1).is_ok());
        assert!(manager.retrieve_key("intruder", &key, 1).is_err());
    }

    #[test]
    fn rotation_creates_new_version() {
        let mut manager = manager();
        let _ = manager
            .generate_key("model-key", KeyKind::Encryption, 1, 0, 42)
            .expect("key should generate");
        let rotated = manager
            .rotate_key("model-key", 30, 99)
            .expect("rotation should succeed");

        assert_eq!(rotated.version, 2);
    }

    #[test]
    fn revoked_keys_are_rejected() {
        let mut manager = manager();
        let key = manager
            .generate_key("model-key", KeyKind::Encryption, 1, 0, 42)
            .expect("key should generate");

        manager
            .revoke_key("model-key", 1)
            .expect("revoke should succeed");

        assert!(manager.retrieve_key("loader", &key, 1).is_err());
    }
}
