//! Secure memory zeroization using the `zeroize` crate.
//!
//! Provides guaranteed clearing of sensitive data (keys, tokens, KV-cache)
//! from memory after use, preventing leakage in core dumps or cold memory reads.
//! Uses the `zeroize` crate which handles compiler_fence and volatile writes
//! correctly across all Rust targets.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{SecurityError, SecurityResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroizationPolicy {
    pub zeroize_keys_after_use: bool,
    pub zeroize_cache_on_evict: bool,
    pub zeroize_session_on_end: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroizationEvent {
    pub resource_id: String,
    pub bytes_zeroized: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZeroizationTracker {
    pub events: Vec<ZeroizationEvent>,
}

/// Trait for types that support secure zeroization.
pub trait Zeroizable {
    fn zeroize(&mut self);
}

/// A wrapper around sensitive byte data that is automatically zeroized on drop.
/// Uses the `zeroize` crate's `Zeroizing` for guaranteed clearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveBytes {
    pub bytes: Zeroizing<Vec<u8>>,
}

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }
}

impl Zeroizable for SensitiveBytes {
    fn zeroize(&mut self) {
        // Zeroizing already zeroizes on drop, but we also support explicit zeroization.
        // We replace with an empty vector to clear the memory immediately.
        self.bytes = Zeroizing::new(Vec::new());
    }
}

/// Securely zeroize a byte slice. Uses the `zeroize` crate's guaranteed clearing.
pub fn secure_zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Securely zeroize a float slice. Converts to bytes and zeros.
pub fn secure_zeroize_f32(values: &mut [f32]) {
    // SAFETY: f32 has a valid zero representation (0.0).
    // We zeroize the underlying bytes directly.
    let slice = unsafe {
        std::slice::from_raw_parts_mut(values.as_mut_ptr() as *mut u8, values.len() * 4)
    };
    slice.zeroize();
}

/// Securely zeroize session buffers (keys and KV-cache).
pub fn zeroize_session_buffers(
    tracker: &mut ZeroizationTracker,
    session_id: &str,
    key_buffer: &mut [u8],
    kv_buffer: &mut [f32],
    policy: ZeroizationPolicy,
) -> SecurityResult<()> {
    if session_id.trim().is_empty() {
        return Err(SecurityError::InvalidInput("session_id must not be empty"));
    }

    if policy.zeroize_keys_after_use {
        let len = key_buffer.len();
        secure_zeroize_bytes(key_buffer);
        tracker.events.push(ZeroizationEvent {
            resource_id: format!("session:{}:keys", session_id),
            bytes_zeroized: len,
            reason: "key-use-complete".to_owned(),
        });
    }

    if policy.zeroize_cache_on_evict || policy.zeroize_session_on_end {
        let len = std::mem::size_of_val(kv_buffer);
        secure_zeroize_f32(kv_buffer);
        tracker.events.push(ZeroizationEvent {
            resource_id: format!("session:{}:kv", session_id),
            bytes_zeroized: len,
            reason: "session-end-or-evict".to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        secure_zeroize_bytes, secure_zeroize_f32, zeroize_session_buffers, SensitiveBytes,
        Zeroizable, ZeroizationPolicy, ZeroizationTracker,
    };

    #[test]
    fn byte_zeroization_overwrites_buffer() {
        let mut data = vec![1_u8, 2, 3, 4];
        secure_zeroize_bytes(&mut data);
        assert_eq!(data, vec![0_u8, 0, 0, 0]);
    }

    #[test]
    fn sensitive_bytes_zeroize_trait_works() {
        let mut secret = SensitiveBytes::new(vec![7, 8, 9]);
        secret.zeroize();
        assert_eq!(*secret.bytes, Vec::<u8>::new());
    }

    #[test]
    fn session_zeroization_records_events() {
        let mut tracker = ZeroizationTracker::default();
        let mut keys = vec![1_u8, 2, 3];
        let mut cache = vec![1.0_f32, 2.0, 3.0];

        zeroize_session_buffers(
            &mut tracker,
            "s1",
            &mut keys,
            &mut cache,
            ZeroizationPolicy {
                zeroize_keys_after_use: true,
                zeroize_cache_on_evict: true,
                zeroize_session_on_end: true,
            },
        )
        .expect("zeroization should succeed");

        assert_eq!(keys, vec![0_u8, 0, 0]);
        assert_eq!(cache, vec![0.0_f32, 0.0, 0.0]);
        assert_eq!(tracker.events.len(), 2);
    }

    #[test]
    fn f32_zeroization_works() {
        let mut values = vec![1.5_f32, 2.5, 3.5];
        secure_zeroize_f32(&mut values);
        assert_eq!(values, vec![0.0_f32, 0.0, 0.0]);
    }
}
