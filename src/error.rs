use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    InvalidConfig(&'static str),
    InvalidInput(&'static str),
    InvalidState(&'static str),
    ParseError(&'static str),
    Unauthorized(String),
    IntegrityViolation(String),
    SignatureInvalid(String),
    EncryptionFailed(&'static str),
    DecryptionFailed(&'static str),
    KeyNotFound(String),
    KeyRevoked(String),
    SandboxDenied(String),
    TamperDetected(String),
    ComplianceGap(String),
    IoError(String),
}

pub type SecurityResult<T> = Result<T, SecurityError>;

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            Self::IntegrityViolation(msg) => write!(f, "integrity violation: {msg}"),
            Self::SignatureInvalid(msg) => write!(f, "signature invalid: {msg}"),
            Self::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::KeyNotFound(msg) => write!(f, "key not found: {msg}"),
            Self::KeyRevoked(msg) => write!(f, "key revoked: {msg}"),
            Self::SandboxDenied(msg) => write!(f, "sandbox denied: {msg}"),
            Self::TamperDetected(msg) => write!(f, "tamper detected: {msg}"),
            Self::ComplianceGap(msg) => write!(f, "compliance gap: {msg}"),
            Self::IoError(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl Error for SecurityError {}

impl From<std::io::Error> for SecurityError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value.to_string())
    }
}
