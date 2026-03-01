use crate::TierId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    pub id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone)]
pub struct TierPolicy {
    pub tier: TierId,
    pub min_role: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

pub fn authorize(principal: &Principal, policy: &TierPolicy, _action: Action) -> AuthorizationDecision {
    if principal.roles.iter().any(|r| r == &policy.min_role) {
        AuthorizationDecision::Allow
    } else {
        AuthorizationDecision::Deny
    }
}
