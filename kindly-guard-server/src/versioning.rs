// Copyright 2025 Kindly-Software
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
//! API versioning for `KindlyGuard`
//! Provides version management and stability guarantees
#![allow(missing_docs)] // Simple DTOs with self-explanatory fields

use serde::{Deserialize, Serialize};

/// Current API version
pub const API_VERSION: &str = "v1-beta";

/// Server version (from Cargo.toml)
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// MCP protocol version supported
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// API stability levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiStability {
    /// Experimental features that may change or be removed
    Experimental,
    /// Beta features that are mostly stable but may have minor changes
    Beta,
    /// Stable features with backward compatibility guarantees
    Stable,
    /// Deprecated features that will be removed in future versions
    Deprecated,
}

/// API endpoint metadata
#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: &'static str,
    pub stability: ApiStability,
    pub since_version: &'static str,
    pub deprecated_in: Option<&'static str>,
    pub removed_in: Option<&'static str>,
}

/// Version information for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub api_version: String,
    pub server_version: String,
    pub protocol_version: String,
    pub stability: String,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            server_version: SERVER_VERSION.to_string(),
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            stability: "beta".to_string(),
        }
    }
}

/// Registry of API endpoints and their stability
pub struct ApiRegistry;

impl ApiRegistry {
    /// Get all registered API endpoints
    pub fn endpoints() -> Vec<ApiEndpoint> {
        vec![
            // Core MCP methods (stable)
            ApiEndpoint {
                method: "initialize",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "initialized",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "shutdown",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "tools/list",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "tools/call",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "resources/list",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "resources/read",
                stability: ApiStability::Stable,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "prompts/list",
                stability: ApiStability::Beta,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            // Security extensions (experimental)
            ApiEndpoint {
                method: "security/status",
                stability: ApiStability::Experimental,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "security/threats",
                stability: ApiStability::Experimental,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            ApiEndpoint {
                method: "security/rate_limit_status",
                stability: ApiStability::Experimental,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
            // Admin methods (experimental)
            ApiEndpoint {
                method: "admin/update_config",
                stability: ApiStability::Experimental,
                since_version: "0.1.0",
                deprecated_in: None,
                removed_in: None,
            },
        ]
    }

    /// Check if a method is stable
    pub fn is_stable(method: &str) -> bool {
        Self::endpoints()
            .iter()
            .find(|e| e.method == method)
            .is_some_and(|e| e.stability == ApiStability::Stable)
    }

    /// Get stability for a method
    pub fn get_stability(method: &str) -> Option<ApiStability> {
        Self::endpoints()
            .iter()
            .find(|e| e.method == method)
            .map(|e| e.stability)
    }

    /// Check if experimental features are enabled
    pub fn experimental_enabled() -> bool {
        // Could be controlled by environment variable or config
        std::env::var("KINDLYGUARD_EXPERIMENTAL")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
    }
}

/// Add version metadata to responses
pub fn add_version_metadata(response: &mut serde_json::Value) {
    if let Some(obj) = response.as_object_mut() {
        let version_info = VersionInfo::default();
        obj.insert(
            "_meta".to_string(),
            serde_json::json!({
                "api_version": version_info.api_version,
                "server_version": version_info.server_version,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }
}

/// Version negotiation for protocol compatibility
pub struct VersionNegotiator;

impl VersionNegotiator {
    /// Supported protocol versions in order of preference
    pub const SUPPORTED_PROTOCOLS: &'static [&'static str] = &[
        "2024-11-05", // Current
        "2024-10-01", // Previous (if we supported it)
    ];

    /// Check if a protocol version is supported
    pub fn is_supported(version: &str) -> bool {
        Self::SUPPORTED_PROTOCOLS.contains(&version)
    }

    /// Get the best matching version
    pub fn negotiate(requested: &str) -> Option<&'static str> {
        // Find exact match in our supported versions
        Self::SUPPORTED_PROTOCOLS
            .iter()
            .find(|&&v| v == requested)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_registry() {
        assert!(ApiRegistry::is_stable("initialize"));
        assert!(ApiRegistry::is_stable("tools/list"));
        assert!(!ApiRegistry::is_stable("security/status"));

        assert_eq!(
            ApiRegistry::get_stability("security/status"),
            Some(ApiStability::Experimental)
        );
    }

    #[test]
    fn test_version_negotiation() {
        assert!(VersionNegotiator::is_supported("2024-11-05"));
        assert!(!VersionNegotiator::is_supported("2023-01-01"));

        assert_eq!(
            VersionNegotiator::negotiate("2024-11-05"),
            Some("2024-11-05")
        );
    }

    #[test]
    fn test_version_metadata() {
        let mut response = serde_json::json!({
            "result": "test"
        });

        add_version_metadata(&mut response);

        assert!(response.get("_meta").is_some());
        let meta = response.get("_meta").unwrap();
        assert!(meta.get("api_version").is_some());
        assert!(meta.get("server_version").is_some());
    }
}
