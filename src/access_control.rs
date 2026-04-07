use std::collections::{BTreeMap, BTreeSet};

use crate::error::{SecurityError, SecurityResult};
use crate::types::TierId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub tenant_id: String,
    pub roles: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    LoadModel,
    RunInference,
    ReadTelemetry,
    ReadAudit,
    Prefetch,
    DecryptTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicy {
    pub tier: TierId,
    pub allowed_roles: BTreeSet<String>,
    pub allowed_tenants: BTreeSet<String>,
    pub downgrade_tier: Option<TierId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Downgrade { to_tier: TierId, reason: String },
    Deny { reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct AccessController {
    action_roles: BTreeMap<Action, BTreeSet<String>>,
    tier_policies: BTreeMap<TierId, TierPolicy>,
}

impl AccessController {
    pub fn set_action_roles(&mut self, action: Action, roles: BTreeSet<String>) {
        self.action_roles.insert(action, roles);
    }

    pub fn set_tier_policy(&mut self, policy: TierPolicy) {
        self.tier_policies.insert(policy.tier, policy);
    }

    pub fn authorize(
        &self,
        principal: &Principal,
        action: Action,
        requested_tier: Option<TierId>,
    ) -> SecurityResult<AuthorizationDecision> {
        if principal.id.trim().is_empty() || principal.tenant_id.trim().is_empty() {
            return Err(SecurityError::InvalidInput(
                "principal id and tenant_id are required",
            ));
        }

        if let Some(required_roles) = self.action_roles.get(&action) {
            let has_action_role = principal
                .roles
                .iter()
                .any(|role| required_roles.contains(role));
            if !has_action_role {
                return Ok(AuthorizationDecision::Deny {
                    reason: format!(
                        "principal {} lacks role for action {:?}",
                        principal.id, action
                    ),
                });
            }
        }

        if let Some(tier) = requested_tier {
            let policy = self
                .tier_policies
                .get(&tier)
                .ok_or_else(|| SecurityError::Unauthorized(format!("no policy for tier {tier}")))?;

            if !policy.allowed_tenants.contains(&principal.tenant_id) {
                if let Some(downgrade) = policy.downgrade_tier {
                    return Ok(AuthorizationDecision::Downgrade {
                        to_tier: downgrade,
                        reason: format!(
                            "tenant {} not allowed for tier {}",
                            principal.tenant_id, tier
                        ),
                    });
                }

                return Ok(AuthorizationDecision::Deny {
                    reason: format!(
                        "tenant {} not allowed for tier {}",
                        principal.tenant_id, tier
                    ),
                });
            }

            let has_tier_role = principal
                .roles
                .iter()
                .any(|role| policy.allowed_roles.contains(role));

            if !has_tier_role {
                if let Some(downgrade) = policy.downgrade_tier {
                    return Ok(AuthorizationDecision::Downgrade {
                        to_tier: downgrade,
                        reason: format!("principal {} lacks role for tier {}", principal.id, tier),
                    });
                }
                return Ok(AuthorizationDecision::Deny {
                    reason: format!("principal {} lacks role for tier {}", principal.id, tier),
                });
            }
        }

        Ok(AuthorizationDecision::Allow)
    }

    pub fn authorized_tiers(&self, principal: &Principal) -> Vec<TierId> {
        let mut tiers = self
            .tier_policies
            .iter()
            .filter(|(_, policy)| {
                policy.allowed_tenants.contains(&principal.tenant_id)
                    && principal
                        .roles
                        .iter()
                        .any(|role| policy.allowed_roles.contains(role))
            })
            .map(|(tier, _)| *tier)
            .collect::<Vec<TierId>>();

        tiers.sort_unstable();
        tiers
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AccessController, Action, AuthorizationDecision, Principal, TierPolicy};

    fn principal(role: &str, tenant: &str) -> Principal {
        Principal {
            id: "user-1".to_owned(),
            tenant_id: tenant.to_owned(),
            roles: BTreeSet::from([role.to_owned()]),
            scopes: BTreeSet::new(),
        }
    }

    fn controller() -> AccessController {
        let mut controller = AccessController::default();

        controller.set_action_roles(
            Action::RunInference,
            BTreeSet::from(["inference".to_owned(), "admin".to_owned()]),
        );

        controller.set_tier_policy(TierPolicy {
            tier: 1,
            allowed_roles: BTreeSet::from(["inference".to_owned(), "admin".to_owned()]),
            allowed_tenants: BTreeSet::from(["tenant-a".to_owned(), "tenant-b".to_owned()]),
            downgrade_tier: None,
        });

        controller.set_tier_policy(TierPolicy {
            tier: 2,
            allowed_roles: BTreeSet::from(["admin".to_owned()]),
            allowed_tenants: BTreeSet::from(["tenant-a".to_owned()]),
            downgrade_tier: Some(1),
        });

        controller
    }

    #[test]
    fn allows_authorized_tier_access() {
        let decision = controller()
            .authorize(
                &principal("admin", "tenant-a"),
                Action::RunInference,
                Some(2),
            )
            .expect("authorization should run");

        assert_eq!(decision, AuthorizationDecision::Allow);
    }

    #[test]
    fn downgrades_when_tenant_not_allowed() {
        let decision = controller()
            .authorize(
                &principal("admin", "tenant-b"),
                Action::RunInference,
                Some(2),
            )
            .expect("authorization should run");

        assert!(matches!(
            decision,
            AuthorizationDecision::Downgrade { to_tier: 1, .. }
        ));
    }

    #[test]
    fn denies_when_action_role_missing() {
        let decision = controller()
            .authorize(
                &principal("observer", "tenant-a"),
                Action::RunInference,
                Some(1),
            )
            .expect("authorization should run");

        assert!(matches!(decision, AuthorizationDecision::Deny { .. }));
    }

    #[test]
    fn lists_authorized_tiers_deterministically() {
        let tiers = controller().authorized_tiers(&principal("admin", "tenant-a"));
        assert_eq!(tiers, vec![1, 2]);
    }
}
