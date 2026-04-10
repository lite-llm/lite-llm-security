use std::collections::{BTreeMap, BTreeSet};

use crate::error::{SecurityError, SecurityResult};
use crate::types::fnv64_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    ReadTensor,
    RouteToken,
    AccessKvCache,
    LoadExpert,
    Filesystem,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token_id: String,
    pub plugin_id: String,
    pub capabilities: BTreeSet<Capability>,
    pub issued_step: u64,
    pub expires_step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    pub allowed_syscalls: BTreeSet<String>,
    pub max_memory_bytes: u64,
    pub max_cpu_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_millis: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SandboxRuntime {
    config: Option<SandboxConfig>,
    tokens: BTreeMap<String, CapabilityToken>,
    plugin_usage: BTreeMap<String, ResourceUsage>,
}

impl SandboxRuntime {
    pub fn configure(&mut self, config: SandboxConfig) -> SecurityResult<()> {
        if config.max_memory_bytes == 0 || config.max_cpu_millis == 0 {
            return Err(SecurityError::InvalidConfig(
                "sandbox resource limits must be greater than zero".to_owned(),
            ));
        }
        self.config = Some(config);
        Ok(())
    }

    pub fn grant_capabilities(
        &mut self,
        plugin_id: &str,
        capabilities: BTreeSet<Capability>,
        now_step: u64,
        ttl_steps: u64,
        seed: u64,
    ) -> SecurityResult<CapabilityToken> {
        if plugin_id.trim().is_empty() {
            return Err(SecurityError::InvalidInput("plugin_id must not be empty"));
        }
        if ttl_steps == 0 {
            return Err(SecurityError::InvalidInput(
                "ttl_steps must be greater than zero",
            ));
        }

        let token_id =
            fnv64_hex(format!("{}|{}|{}|{}", plugin_id, now_step, ttl_steps, seed).as_bytes());

        let token = CapabilityToken {
            token_id: token_id.clone(),
            plugin_id: plugin_id.to_owned(),
            capabilities,
            issued_step: now_step,
            expires_step: now_step + ttl_steps,
        };

        self.tokens.insert(token_id, token.clone());
        Ok(token)
    }

    pub fn validate_capability(
        &self,
        token_id: &str,
        plugin_id: &str,
        capability: Capability,
        now_step: u64,
    ) -> SecurityResult<()> {
        let token = self
            .tokens
            .get(token_id)
            .ok_or_else(|| SecurityError::SandboxDenied("unknown capability token".to_owned()))?;

        if token.plugin_id != plugin_id {
            return Err(SecurityError::SandboxDenied(
                "token does not belong to plugin".to_owned(),
            ));
        }
        if now_step > token.expires_step {
            return Err(SecurityError::SandboxDenied(
                "capability token is expired".to_owned(),
            ));
        }
        if !token.capabilities.contains(&capability) {
            return Err(SecurityError::SandboxDenied(format!(
                "missing capability {:?}",
                capability
            )));
        }

        Ok(())
    }

    pub fn validate_syscall(&self, syscall: &str) -> SecurityResult<()> {
        let config = self
            .config
            .as_ref()
            .ok_or(SecurityError::InvalidState("sandbox not configured"))?;

        if !config.allowed_syscalls.contains(syscall) {
            return Err(SecurityError::SandboxDenied(format!(
                "syscall '{}' not allowed",
                syscall
            )));
        }

        Ok(())
    }

    pub fn record_usage(&mut self, plugin_id: &str, usage: ResourceUsage) -> SecurityResult<()> {
        let config = self
            .config
            .as_ref()
            .ok_or(SecurityError::InvalidState("sandbox not configured"))?;

        if usage.memory_bytes > config.max_memory_bytes {
            return Err(SecurityError::SandboxDenied(
                "memory limit exceeded".to_owned(),
            ));
        }
        if usage.cpu_millis > config.max_cpu_millis {
            return Err(SecurityError::SandboxDenied(
                "cpu limit exceeded".to_owned(),
            ));
        }

        self.plugin_usage.insert(plugin_id.to_owned(), usage);
        Ok(())
    }

    pub fn revoke_token(&mut self, token_id: &str) {
        self.tokens.remove(token_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Capability, ResourceUsage, SandboxConfig, SandboxRuntime};

    fn runtime() -> SandboxRuntime {
        let mut runtime = SandboxRuntime::default();
        runtime
            .configure(SandboxConfig {
                allowed_syscalls: BTreeSet::from(["read".to_owned(), "write".to_owned()]),
                max_memory_bytes: 1024,
                max_cpu_millis: 500,
            })
            .expect("sandbox should configure");
        runtime
    }

    #[test]
    fn capability_tokens_enforce_expiry_and_scope() {
        let mut runtime = runtime();
        let token = runtime
            .grant_capabilities(
                "plugin-a",
                BTreeSet::from([Capability::ReadTensor, Capability::RouteToken]),
                10,
                5,
                42,
            )
            .expect("token should be granted");

        assert!(runtime
            .validate_capability(&token.token_id, "plugin-a", Capability::RouteToken, 12)
            .is_ok());
        assert!(runtime
            .validate_capability(&token.token_id, "plugin-a", Capability::AccessKvCache, 12)
            .is_err());
        assert!(runtime
            .validate_capability(&token.token_id, "plugin-a", Capability::RouteToken, 20)
            .is_err());
    }

    #[test]
    fn syscall_filter_blocks_disallowed_calls() {
        let runtime = runtime();
        assert!(runtime.validate_syscall("read").is_ok());
        assert!(runtime.validate_syscall("socket").is_err());
    }

    #[test]
    fn resource_limits_are_enforced() {
        let mut runtime = runtime();
        assert!(runtime
            .record_usage(
                "plugin-a",
                ResourceUsage {
                    memory_bytes: 100,
                    cpu_millis: 50,
                },
            )
            .is_ok());

        assert!(runtime
            .record_usage(
                "plugin-a",
                ResourceUsage {
                    memory_bytes: 5000,
                    cpu_millis: 50,
                },
            )
            .is_err());
    }
}
