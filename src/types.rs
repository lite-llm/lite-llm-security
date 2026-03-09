pub type TierId = u16;

pub fn fnv64_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn pseudo_sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for salt in ["0", "1", "2", "3"] {
        let mut payload = Vec::new();
        payload.extend_from_slice(salt.as_bytes());
        payload.extend_from_slice(bytes);
        out.push_str(&fnv64_hex(&payload));
    }
    out
}

pub fn deterministic_hash_hex(algorithm: &str, bytes: &[u8]) -> Option<String> {
    match algorithm.to_ascii_lowercase().as_str() {
        "fnv64" => Some(fnv64_hex(bytes)),
        "sha256" => Some(pseudo_sha256_hex(bytes)),
        _ => None,
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    let chars = value.as_bytes();

    for idx in (0..chars.len()).step_by(2) {
        let hi = (chars[idx] as char).to_digit(16)?;
        let lo = (chars[idx + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{deterministic_hash_hex, hex_decode, hex_encode};

    #[test]
    fn hex_codec_roundtrip() {
        let data = b"lite-llm";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).expect("hex decode should work");
        assert_eq!(decoded, data);
    }

    #[test]
    fn hashing_is_deterministic() {
        let payload = b"payload";
        let a = deterministic_hash_hex("sha256", payload).expect("hash should work");
        let b = deterministic_hash_hex("sha256", payload).expect("hash should work");
        assert_eq!(a, b);
    }
}
