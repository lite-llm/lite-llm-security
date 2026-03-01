#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub sequence: u64,
    pub category: String,
    pub payload: String,
}

pub trait AuditSink {
    fn append(&mut self, event: AuditEvent) -> Result<(), &'static str>;
}

#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    pub events: Vec<AuditEvent>,
}

impl AuditSink for InMemoryAuditSink {
    fn append(&mut self, event: AuditEvent) -> Result<(), &'static str> {
        self.events.push(event);
        Ok(())
    }
}

