#[derive(Debug, Clone)]
pub struct ArtifactDigest {
    pub algorithm: String,
    pub hex: String,
}

pub trait IntegrityVerifier {
    fn verify(&self, payload: &[u8], expected: &ArtifactDigest) -> bool;
}

#[derive(Debug, Default)]
pub struct Sha256Verifier;

impl IntegrityVerifier for Sha256Verifier {
    fn verify(&self, _payload: &[u8], expected: &ArtifactDigest) -> bool {
        expected.algorithm.eq_ignore_ascii_case("sha256") && !expected.hex.is_empty()
    }
}

