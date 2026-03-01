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

pub trait Zeroizable {
    fn zeroize(&mut self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveBytes {
    pub bytes: Vec<u8>,
}

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Zeroizable for SensitiveBytes {
    fn zeroize(&mut self) {
        secure_zeroize_bytes(&mut self.bytes);
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn secure_zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: write_volatile is used to avoid compiler elision of zeroization.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn secure_zeroize_f32(values: &mut [f32]) {
    for value in values {
        // SAFETY: write_volatile is used to avoid compiler elision of zeroization.
        unsafe {
            std::ptr::write_volatile(value, 0.0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

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
        let len = kv_buffer.len() * std::mem::size_of::<f32>();
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
        secure_zeroize_bytes, zeroize_session_buffers, SensitiveBytes, Zeroizable,
        ZeroizationPolicy, ZeroizationTracker,
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
        assert_eq!(secret.bytes, vec![0, 0, 0]);
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
}
