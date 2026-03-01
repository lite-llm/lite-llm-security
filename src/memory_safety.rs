use crate::error::{SecurityError, SecurityResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeBlockPolicy {
    Deny,
    AllowWithReview,
    AllowWithAudit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySafetyProfile {
    pub require_miri: bool,
    pub require_fuzzing: bool,
    pub unsafe_policy: UnsafeBlockPolicy,
    pub max_unsafe_blocks: usize,
    pub require_ffi_layout_validation: bool,
    pub require_ffi_lifetime_validation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeUsageRecord {
    pub module_path: String,
    pub line: u32,
    pub reason: String,
    pub reviewed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiBoundaryAudit {
    pub boundary_name: String,
    pub uses_unsafe: bool,
    pub layout_validated: bool,
    pub lifetime_validated: bool,
    pub reviewed_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySafetyReport {
    pub accepted: bool,
    pub unsafe_block_count: usize,
    pub reviewed_unsafe_block_count: usize,
    pub violations: Vec<String>,
}

pub fn audit_memory_safety(
    profile: &MemorySafetyProfile,
    unsafe_records: &[UnsafeUsageRecord],
    ffi_audits: &[FfiBoundaryAudit],
    miri_passed: bool,
    fuzzing_passed: bool,
) -> SecurityResult<MemorySafetyReport> {
    if profile.max_unsafe_blocks == 0 && profile.unsafe_policy != UnsafeBlockPolicy::Deny {
        return Err(SecurityError::InvalidConfig(
            "max_unsafe_blocks must be positive when unsafe blocks are allowed",
        ));
    }

    let mut violations = Vec::new();

    if profile.require_miri && !miri_passed {
        violations.push("miri requirement not satisfied".to_owned());
    }
    if profile.require_fuzzing && !fuzzing_passed {
        violations.push("fuzzing requirement not satisfied".to_owned());
    }

    let unsafe_block_count = unsafe_records.len();
    let reviewed_unsafe_block_count = unsafe_records
        .iter()
        .filter(|record| record.reviewed)
        .count();

    if unsafe_block_count > profile.max_unsafe_blocks {
        violations.push(format!(
            "unsafe block count {} exceeds limit {}",
            unsafe_block_count, profile.max_unsafe_blocks
        ));
    }

    match profile.unsafe_policy {
        UnsafeBlockPolicy::Deny => {
            if unsafe_block_count > 0 {
                violations.push("unsafe blocks are denied by policy".to_owned());
            }
        }
        UnsafeBlockPolicy::AllowWithReview => {
            for record in unsafe_records {
                if !record.reviewed {
                    violations.push(format!(
                        "unsafe block at {}:{} lacks review",
                        record.module_path, record.line
                    ));
                }
            }
        }
        UnsafeBlockPolicy::AllowWithAudit => {
            for record in unsafe_records {
                if record.reason.trim().is_empty() {
                    violations.push(format!(
                        "unsafe block at {}:{} lacks justification",
                        record.module_path, record.line
                    ));
                }
            }
        }
    }

    for ffi in ffi_audits {
        if ffi.uses_unsafe && ffi.reviewed_by.as_deref().unwrap_or("{}").trim().is_empty() {
            violations.push(format!(
                "ffi boundary '{}' lacks reviewer",
                ffi.boundary_name
            ));
        }
        if profile.require_ffi_layout_validation && ffi.uses_unsafe && !ffi.layout_validated {
            violations.push(format!(
                "ffi boundary '{}' missing layout validation",
                ffi.boundary_name
            ));
        }
        if profile.require_ffi_lifetime_validation && ffi.uses_unsafe && !ffi.lifetime_validated {
            violations.push(format!(
                "ffi boundary '{}' missing lifetime validation",
                ffi.boundary_name
            ));
        }
    }

    violations.sort();

    Ok(MemorySafetyReport {
        accepted: violations.is_empty(),
        unsafe_block_count,
        reviewed_unsafe_block_count,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        audit_memory_safety, FfiBoundaryAudit, MemorySafetyProfile, UnsafeBlockPolicy,
        UnsafeUsageRecord,
    };

    fn profile(policy: UnsafeBlockPolicy) -> MemorySafetyProfile {
        MemorySafetyProfile {
            require_miri: true,
            require_fuzzing: true,
            unsafe_policy: policy,
            max_unsafe_blocks: 2,
            require_ffi_layout_validation: true,
            require_ffi_lifetime_validation: true,
        }
    }

    #[test]
    fn deny_policy_rejects_unsafe_blocks() {
        let report = audit_memory_safety(
            &profile(UnsafeBlockPolicy::Deny),
            &[UnsafeUsageRecord {
                module_path: "ffi.rs".to_owned(),
                line: 10,
                reason: "ffi call".to_owned(),
                reviewed: true,
            }],
            &[],
            true,
            true,
        )
        .expect("audit should run");

        assert!(!report.accepted);
    }

    #[test]
    fn review_policy_requires_reviewed_unsafe_blocks() {
        let report = audit_memory_safety(
            &profile(UnsafeBlockPolicy::AllowWithReview),
            &[UnsafeUsageRecord {
                module_path: "ffi.rs".to_owned(),
                line: 11,
                reason: "ffi call".to_owned(),
                reviewed: false,
            }],
            &[],
            true,
            true,
        )
        .expect("audit should run");

        assert!(!report.accepted);
    }

    #[test]
    fn ffi_audit_checks_layout_and_lifetimes() {
        let report = audit_memory_safety(
            &profile(UnsafeBlockPolicy::AllowWithAudit),
            &[],
            &[FfiBoundaryAudit {
                boundary_name: "cuda".to_owned(),
                uses_unsafe: true,
                layout_validated: false,
                lifetime_validated: false,
                reviewed_by: Some("sec-review".to_owned()),
            }],
            true,
            true,
        )
        .expect("audit should run");

        assert!(!report.accepted);
        assert_eq!(report.violations.len(), 2);
    }

    #[test]
    fn fully_compliant_profile_is_accepted() {
        let report = audit_memory_safety(
            &profile(UnsafeBlockPolicy::AllowWithReview),
            &[UnsafeUsageRecord {
                module_path: "ffi.rs".to_owned(),
                line: 22,
                reason: "ffi call".to_owned(),
                reviewed: true,
            }],
            &[FfiBoundaryAudit {
                boundary_name: "rdma".to_owned(),
                uses_unsafe: true,
                layout_validated: true,
                lifetime_validated: true,
                reviewed_by: Some("sec-review".to_owned()),
            }],
            true,
            true,
        )
        .expect("audit should run");

        assert!(report.accepted);
    }
}
