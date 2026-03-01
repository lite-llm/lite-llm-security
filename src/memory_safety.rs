#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeBlockPolicy {
    Deny,
    AllowWithReview,
}

#[derive(Debug, Clone)]
pub struct MemorySafetyProfile {
    pub require_miri: bool,
    pub require_fuzzing: bool,
    pub unsafe_policy: UnsafeBlockPolicy,
}

