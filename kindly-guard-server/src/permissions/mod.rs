// Copyright 2025 Kindly Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Tool-level permission system with trait-based architecture
//! Enables fine-grained control over tool access

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[cfg(any(test, feature = "test-utils"))]
use mockall::{automock, predicate::*};

#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod standard;

#[cfg(feature = "enhanced")]
pub use enhanced::EnhancedPermissionManager;
pub use standard::StandardPermissionManager;

/// Permission decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    Allow,
    Deny(String), // Reason for denial
}

/// Tool permission trait
#[async_trait]
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait ToolPermissionManager: Send + Sync {
    /// Check if a client has permission to use a tool
    async fn check_permission(
        &self,
        client_id: &str,
        tool_name: &str,
        context: &PermissionContext,
    ) -> Result<Permission>;

    /// Get list of allowed tools for a client
    async fn get_allowed_tools(&self, client_id: &str) -> Result<Vec<String>>;

    /// Update permissions for a client
    async fn update_permissions(
        &self,
        client_id: &str,
        permissions: ClientPermissions,
    ) -> Result<()>;

    /// Get permission stats
    fn get_stats(&self) -> PermissionStats;
}

/// Permission check context
#[derive(Debug, Clone)]
pub struct PermissionContext {
    pub auth_token: Option<String>,
    pub scopes: Vec<String>,
    pub threat_level: ThreatLevel,
    pub request_metadata: HashMap<String, String>,
}

/// Client threat level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

/// Client permissions configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPermissions {
    pub allowed_tools: HashSet<String>,
    pub denied_tools: HashSet<String>,
    pub rate_limit_override: Option<u32>,
    pub require_signing: bool,
    pub max_threat_level: ThreatLevel,
}

impl Default for ClientPermissions {
    fn default() -> Self {
        Self {
            allowed_tools: HashSet::new(),
            denied_tools: HashSet::new(),
            rate_limit_override: None,
            require_signing: false,
            max_threat_level: ThreatLevel::Medium,
        }
    }
}

/// Permission statistics
#[derive(Debug, Clone, Serialize)]
pub struct PermissionStats {
    pub total_checks: u64,
    pub allowed: u64,
    pub denied: u64,
    pub denied_by_reason: HashMap<String, u64>,
}

/// Tool categories for permission grouping
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    Security,
    Information,
    Diagnostic,
    Administrative,
    Custom(String),
}

/// Tool definition with permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub category: ToolCategory,
    pub required_scopes: Vec<String>,
    pub min_threat_level: ThreatLevel,
    pub require_signing: bool,
}

/// Permission rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRules {
    /// Default permissions for new clients
    pub default_permissions: ClientPermissions,

    /// Tool definitions
    pub tools: HashMap<String, ToolDefinition>,

    /// Category-based rules
    pub category_rules: HashMap<ToolCategory, CategoryRule>,

    /// Global deny list
    pub global_deny_list: HashSet<String>,
}

/// Category-specific rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRule {
    pub allowed_by_default: bool,
    pub required_scopes: Vec<String>,
    pub max_threat_level: ThreatLevel,
}

/// Factory for creating permission managers
pub trait PermissionManagerFactory: Send + Sync {
    /// Create a permission manager
    fn create(&self, rules: PermissionRules) -> Arc<dyn ToolPermissionManager>;
}

/// Standard factory
pub struct StandardPermissionFactory;

impl PermissionManagerFactory for StandardPermissionFactory {
    fn create(&self, rules: PermissionRules) -> Arc<dyn ToolPermissionManager> {
        Arc::new(StandardPermissionManager::new(rules))
    }
}

/// Enhanced factory (with advanced features)
#[cfg(feature = "enhanced")]
pub struct EnhancedPermissionFactory;

#[cfg(feature = "enhanced")]
impl PermissionManagerFactory for EnhancedPermissionFactory {
    fn create(&self, rules: PermissionRules) -> Arc<dyn ToolPermissionManager> {
        Arc::new(EnhancedPermissionManager::new(rules))
    }
}

// Implement serde for ThreatLevel
impl Serialize for ThreatLevel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Safe => "safe",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for ThreatLevel {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "safe" => Ok(Self::Safe),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(serde::de::Error::custom("invalid threat level")),
        }
    }
}

/// Default tool definitions
pub fn default_tool_definitions() -> HashMap<String, ToolDefinition> {
    let mut tools = HashMap::new();

    // Security tools
    tools.insert(
        "scan_text".to_string(),
        ToolDefinition {
            name: "scan_text".to_string(),
            category: ToolCategory::Security,
            required_scopes: vec!["security:scan".to_string()],
            min_threat_level: ThreatLevel::Safe,
            require_signing: false,
        },
    );

    tools.insert(
        "verify_signature".to_string(),
        ToolDefinition {
            name: "verify_signature".to_string(),
            category: ToolCategory::Security,
            required_scopes: vec!["security:verify".to_string()],
            min_threat_level: ThreatLevel::Safe,
            require_signing: true,
        },
    );

    // Information tools
    tools.insert(
        "get_security_info".to_string(),
        ToolDefinition {
            name: "get_security_info".to_string(),
            category: ToolCategory::Information,
            required_scopes: vec!["info:read".to_string()],
            min_threat_level: ThreatLevel::Safe,
            require_signing: false,
        },
    );

    // Administrative tools
    tools.insert(
        "update_config".to_string(),
        ToolDefinition {
            name: "update_config".to_string(),
            category: ToolCategory::Administrative,
            required_scopes: vec!["admin:write".to_string()],
            min_threat_level: ThreatLevel::Safe,
            require_signing: true,
        },
    );

    tools
}
