use std::collections::BTreeSet;

use crate::types::fnv64_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Regulation {
    Gdpr,
    Ccpa,
    Cpra,
    Hipaa,
    Soc2,
    Iso27001,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceProfile {
    pub data_minimization: bool,
    pub deletion_requests_supported: bool,
    pub encryption_at_rest: bool,
    pub access_control: bool,
    pub audit_logging: bool,
    pub incident_response_plan: bool,
    pub zeroization: bool,
    pub telemetry_pii_redaction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceArtifact {
    pub artifact_id: String,
    pub generated_day: u32,
    pub control: String,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceReport {
    pub regulation: Regulation,
    pub ready: bool,
    pub missing_controls: Vec<String>,
    pub artifacts: Vec<ComplianceArtifact>,
}

#[derive(Debug, Clone)]
pub struct ComplianceEngine {
    profile: ComplianceProfile,
}

impl ComplianceEngine {
    pub fn new(profile: ComplianceProfile) -> Self {
        Self { profile }
    }

    pub fn evaluate(&self, regulation: Regulation, day: u32) -> ComplianceReport {
        let required_controls = required_controls(regulation);

        let mut missing = Vec::new();
        let mut artifacts = Vec::new();

        for control in required_controls {
            let enabled = self.control_enabled(control);
            if !enabled {
                missing.push(control.to_string());
            }

            artifacts.push(self.generate_artifact(control, day, enabled));
        }

        missing.sort();
        artifacts.sort_by(|a, b| a.control.cmp(&b.control));

        ComplianceReport {
            regulation,
            ready: missing.is_empty(),
            missing_controls: missing,
            artifacts,
        }
    }

    pub fn enabled_controls(&self) -> BTreeSet<String> {
        let mut controls = BTreeSet::new();
        for control in all_controls() {
            if self.control_enabled(control) {
                controls.insert(control.to_string());
            }
        }
        controls
    }

    fn generate_artifact(&self, control: &str, day: u32, enabled: bool) -> ComplianceArtifact {
        let evidence_hash = fnv64_hex(format!("{}|{}|{}", control, day, enabled).as_bytes());
        ComplianceArtifact {
            artifact_id: format!("{}-{}", control, day),
            generated_day: day,
            control: control.to_owned(),
            evidence_hash,
        }
    }

    fn control_enabled(&self, control: &str) -> bool {
        match control {
            "data_minimization" => self.profile.data_minimization,
            "deletion_requests" => self.profile.deletion_requests_supported,
            "encryption_at_rest" => self.profile.encryption_at_rest,
            "access_control" => self.profile.access_control,
            "audit_logging" => self.profile.audit_logging,
            "incident_response" => self.profile.incident_response_plan,
            "zeroization" => self.profile.zeroization,
            "telemetry_redaction" => self.profile.telemetry_pii_redaction,
            _ => false,
        }
    }
}

fn required_controls(regulation: Regulation) -> &'static [&'static str] {
    match regulation {
        Regulation::Gdpr => &[
            "data_minimization",
            "deletion_requests",
            "access_control",
            "audit_logging",
            "telemetry_redaction",
        ],
        Regulation::Ccpa | Regulation::Cpra => &[
            "data_minimization",
            "deletion_requests",
            "access_control",
            "audit_logging",
        ],
        Regulation::Hipaa => &[
            "encryption_at_rest",
            "access_control",
            "audit_logging",
            "incident_response",
            "zeroization",
        ],
        Regulation::Soc2 | Regulation::Iso27001 => &[
            "encryption_at_rest",
            "access_control",
            "audit_logging",
            "incident_response",
            "data_minimization",
        ],
    }
}

fn all_controls() -> &'static [&'static str] {
    &[
        "data_minimization",
        "deletion_requests",
        "encryption_at_rest",
        "access_control",
        "audit_logging",
        "incident_response",
        "zeroization",
        "telemetry_redaction",
    ]
}

#[cfg(test)]
mod tests {
    use super::{ComplianceEngine, ComplianceProfile, Regulation};

    fn profile(ready: bool) -> ComplianceProfile {
        ComplianceProfile {
            data_minimization: true,
            deletion_requests_supported: ready,
            encryption_at_rest: true,
            access_control: true,
            audit_logging: true,
            incident_response_plan: true,
            zeroization: true,
            telemetry_pii_redaction: true,
        }
    }

    #[test]
    fn gdpr_report_flags_missing_controls() {
        let engine = ComplianceEngine::new(profile(false));
        let report = engine.evaluate(Regulation::Gdpr, 100);

        assert!(!report.ready);
        assert!(report
            .missing_controls
            .contains(&"deletion_requests".to_owned()));
    }

    #[test]
    fn hipaa_report_is_ready_when_controls_enabled() {
        let engine = ComplianceEngine::new(profile(true));
        let report = engine.evaluate(Regulation::Hipaa, 100);

        assert!(report.ready);
        assert!(report.missing_controls.is_empty());
    }

    #[test]
    fn artifact_generation_is_deterministic() {
        let engine = ComplianceEngine::new(profile(true));
        let a = engine.evaluate(Regulation::Soc2, 100);
        let b = engine.evaluate(Regulation::Soc2, 100);

        assert_eq!(a.artifacts, b.artifacts);
    }
}
