#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Threat {
    SupplyChainAttack,
    ParameterTheft,
    SideChannel,
    PrivilegeEscalation,
    Ddos,
    InsiderThreat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistItem {
    pub id: String,
    pub threat: Threat,
    pub description: String,
    pub mitigation: String,
    pub severity: u8,
    pub completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningChecklist {
    pub items: Vec<ChecklistItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HardeningReport {
    pub total_items: usize,
    pub completed_items: usize,
    pub coverage_percent: f32,
    pub missing_critical: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentResponsePlan {
    pub detection: Vec<String>,
    pub containment: Vec<String>,
    pub eradication: Vec<String>,
    pub recovery: Vec<String>,
    pub lessons_learned: Vec<String>,
}

impl HardeningChecklist {
    pub fn default_items() -> Self {
        Self {
            items: vec![
                ChecklistItem {
                    id: "HC-001".to_owned(),
                    threat: Threat::SupplyChainAttack,
                    description: "Verify model manifests and shard hashes".to_owned(),
                    mitigation: "SPEC-052 integrity verification enabled".to_owned(),
                    severity: 5,
                    completed: false,
                },
                ChecklistItem {
                    id: "HC-002".to_owned(),
                    threat: Threat::ParameterTheft,
                    description: "Encrypt persistent tiers and protect keys".to_owned(),
                    mitigation: "SPEC-053 + SPEC-057 controls".to_owned(),
                    severity: 5,
                    completed: false,
                },
                ChecklistItem {
                    id: "HC-003".to_owned(),
                    threat: Threat::PrivilegeEscalation,
                    description: "Enforce RBAC and tier authorization".to_owned(),
                    mitigation: "SPEC-055 access checks".to_owned(),
                    severity: 4,
                    completed: false,
                },
                ChecklistItem {
                    id: "HC-004".to_owned(),
                    threat: Threat::SideChannel,
                    description: "Minimize cross-tenant timing leakage".to_owned(),
                    mitigation: "tenant quotas and sandbox isolation".to_owned(),
                    severity: 4,
                    completed: false,
                },
                ChecklistItem {
                    id: "HC-005".to_owned(),
                    threat: Threat::Ddos,
                    description: "Apply request rate limiting and quotas".to_owned(),
                    mitigation: "multi-tenant quota enforcement".to_owned(),
                    severity: 3,
                    completed: false,
                },
                ChecklistItem {
                    id: "HC-006".to_owned(),
                    threat: Threat::InsiderThreat,
                    description: "Enable tamper-evident deterministic audit logs".to_owned(),
                    mitigation: "SPEC-056 audit chain".to_owned(),
                    severity: 4,
                    completed: false,
                },
            ],
        }
    }

    pub fn mark_completed(&mut self, id: &str) -> bool {
        for item in &mut self.items {
            if item.id == id {
                item.completed = true;
                return true;
            }
        }
        false
    }

    pub fn report(&self) -> HardeningReport {
        let total = self.items.len();
        let completed = self.items.iter().filter(|item| item.completed).count();
        let coverage = if total == 0 {
            100.0
        } else {
            completed as f32 * 100.0 / total as f32
        };

        let mut missing_critical = self
            .items
            .iter()
            .filter(|item| !item.completed)
            .filter(|item| item.severity >= 4)
            .map(|item| item.id.clone())
            .collect::<Vec<String>>();
        missing_critical.sort();

        HardeningReport {
            total_items: total,
            completed_items: completed,
            coverage_percent: coverage,
            missing_critical,
        }
    }
}

pub fn default_incident_response_plan() -> IncidentResponsePlan {
    IncidentResponsePlan {
        detection: vec![
            "alert on integrity verification failures".to_owned(),
            "alert on repeated authorization denials".to_owned(),
        ],
        containment: vec![
            "isolate compromised nodes".to_owned(),
            "revoke affected keys".to_owned(),
        ],
        eradication: vec![
            "remove untrusted artifacts".to_owned(),
            "patch vulnerable components".to_owned(),
        ],
        recovery: vec![
            "restore from verified checkpoints".to_owned(),
            "re-enable services with rotated credentials".to_owned(),
        ],
        lessons_learned: vec![
            "update threat model".to_owned(),
            "expand regression and security tests".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{default_incident_response_plan, HardeningChecklist};

    #[test]
    fn checklist_report_tracks_coverage() {
        let mut checklist = HardeningChecklist::default_items();
        assert!(checklist.mark_completed("HC-001"));
        assert!(checklist.mark_completed("HC-002"));

        let report = checklist.report();
        assert_eq!(report.total_items, 6);
        assert_eq!(report.completed_items, 2);
        assert!(report.coverage_percent > 30.0);
        assert!(!report.missing_critical.is_empty());
    }

    #[test]
    fn incident_plan_has_all_phases() {
        let plan = default_incident_response_plan();
        assert!(!plan.detection.is_empty());
        assert!(!plan.containment.is_empty());
        assert!(!plan.eradication.is_empty());
        assert!(!plan.recovery.is_empty());
        assert!(!plan.lessons_learned.is_empty());
    }
}
