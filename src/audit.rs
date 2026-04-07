use crate::error::{SecurityError, SecurityResult};
use crate::types::fnv64_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditCategory {
    ModelLoad,
    TierActivation,
    Routing,
    AccessControl,
    Cache,
    Error,
    Security,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub category: AuditCategory,
    pub actor: String,
    pub action: String,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub event: AuditEvent,
    pub prev_hash: String,
    pub event_hash: String,
    pub chain_hash: String,
    pub signature_hex: String,
}

pub trait AuditSink {
    fn append(&mut self, event: AuditEvent) -> SecurityResult<AuditRecord>;
}

#[derive(Debug, Clone)]
pub struct DeterministicAuditLog {
    node_id: String,
    signer_id: String,
    signing_secret: String,
    records: Vec<AuditRecord>,
}

impl DeterministicAuditLog {
    pub fn new(
        node_id: impl Into<String>,
        signer_id: impl Into<String>,
        signing_secret: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            signer_id: signer_id.into(),
            signing_secret: signing_secret.into(),
            records: Vec::new(),
        }
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn root_hash(&self) -> String {
        self.records
            .last()
            .map(|record| record.chain_hash.clone())
            .unwrap_or_else(|| "0000000000000000".to_owned())
    }

    pub fn verify_chain(&self) -> SecurityResult<()> {
        let mut previous = "0000000000000000".to_owned();

        for (idx, record) in self.records.iter().enumerate() {
            if record.event.sequence != idx as u64 {
                return Err(SecurityError::TamperDetected(
                    "non-contiguous audit sequence".to_owned(),
                ));
            }
            if record.prev_hash != previous {
                return Err(SecurityError::TamperDetected(
                    "audit prev_hash mismatch".to_owned(),
                ));
            }

            let canonical = canonical_event_payload(&record.event, &self.node_id);
            let expected_event_hash = fnv64_hex(canonical.as_bytes());
            if expected_event_hash != record.event_hash {
                return Err(SecurityError::TamperDetected(
                    "audit event hash mismatch".to_owned(),
                ));
            }

            let expected_chain_hash =
                fnv64_hex(format!("{}|{}", previous, expected_event_hash).as_bytes());
            if expected_chain_hash != record.chain_hash {
                return Err(SecurityError::TamperDetected(
                    "audit chain hash mismatch".to_owned(),
                ));
            }

            let expected_sig =
                signature_material(&self.signing_secret, &self.signer_id, &record.chain_hash);
            if expected_sig != record.signature_hex {
                return Err(SecurityError::TamperDetected(
                    "audit signature mismatch".to_owned(),
                ));
            }

            previous = record.chain_hash.clone();
        }

        Ok(())
    }
}

impl AuditSink for DeterministicAuditLog {
    fn append(&mut self, event: AuditEvent) -> SecurityResult<AuditRecord> {
        if event.sequence != self.records.len() as u64 {
            return Err(SecurityError::InvalidInput(
                "audit sequence must be contiguous",
            ));
        }

        let prev_hash = self.root_hash();
        let canonical = canonical_event_payload(&event, &self.node_id);
        let event_hash = fnv64_hex(canonical.as_bytes());
        let chain_hash = fnv64_hex(format!("{}|{}", prev_hash, event_hash).as_bytes());
        let signature_hex = signature_material(&self.signing_secret, &self.signer_id, &chain_hash);

        let record = AuditRecord {
            event,
            prev_hash,
            event_hash,
            chain_hash,
            signature_hex,
        };

        self.records.push(record.clone());
        Ok(record)
    }
}

fn canonical_event_payload(event: &AuditEvent, node_id: &str) -> String {
    format!(
        "{}|{}|{:?}|{}|{}|{}|{}",
        node_id,
        event.sequence,
        event.category,
        event.timestamp_ms,
        event.actor,
        event.action,
        event.payload
    )
}

fn signature_material(secret: &str, signer_id: &str, chain_hash: &str) -> String {
    fnv64_hex(format!("{}|{}|{}", secret, signer_id, chain_hash).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{AuditCategory, AuditEvent, AuditSink, DeterministicAuditLog};

    fn event(sequence: u64, action: &str) -> AuditEvent {
        AuditEvent {
            sequence,
            timestamp_ms: 1000 + sequence,
            category: AuditCategory::Security,
            actor: "runtime".to_owned(),
            action: action.to_owned(),
            payload: "ok".to_owned(),
        }
    }

    #[test]
    fn append_and_verify_chain_succeeds() {
        let mut log = DeterministicAuditLog::new("n1", "signer", "secret");
        log.append(event(0, "load")).expect("append should succeed");
        log.append(event(1, "auth")).expect("append should succeed");

        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn tamper_is_detected() {
        let mut log = DeterministicAuditLog::new("n1", "signer", "secret");
        log.append(event(0, "load")).expect("append should succeed");
        log.append(event(1, "auth")).expect("append should succeed");

        log.records[1].event.payload = "tampered".to_owned();
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn deterministic_root_hash_for_identical_runs() {
        let mut a = DeterministicAuditLog::new("n1", "signer", "secret");
        let mut b = DeterministicAuditLog::new("n1", "signer", "secret");

        a.append(event(0, "load")).expect("append should succeed");
        a.append(event(1, "auth")).expect("append should succeed");

        b.append(event(0, "load")).expect("append should succeed");
        b.append(event(1, "auth")).expect("append should succeed");

        assert_eq!(a.root_hash(), b.root_hash());
    }
}
