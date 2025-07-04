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
//! Premium features for KindlyGuard
//!
//! This module contains advanced features and integrations that enhance
//! the KindlyGuard experience with visual feedback, Claude Code integration,
//! and advanced monitoring capabilities.

#[cfg(feature = "enhanced")]
pub mod claude_integration;

#[cfg(feature = "enhanced")]
pub mod terminal;

#[cfg(feature = "enhanced")]
pub mod lightning_shield;

// Create type aliases for the expected types
#[cfg(feature = "enhanced")]
pub use claude_integration::SecurityAssistant as ClaudeCodeIntegration;

#[cfg(feature = "enhanced")]
pub use claude_integration::ClaudeConfig as ClaudeIntegrationConfig;

// Define SecurityStats as it doesn't exist in claude_integration
#[derive(Debug, Clone)]
pub struct SecurityStats {
    pub threats_blocked: u64,
    pub scans_performed: u64,
    pub active_sessions: u64,
}

// Provide stub implementations when enhanced feature is not enabled
#[cfg(not(feature = "enhanced"))]
pub struct ClaudeCodeIntegration;

#[cfg(not(feature = "enhanced"))]
pub struct ClaudeIntegrationConfig;

/// Check if premium features are available
pub fn is_premium_available() -> bool {
    // Check for license or feature flags
    cfg!(feature = "premium") || std::env::var("KINDLYGUARD_PREMIUM").is_ok()
}

/// Initialize premium features
pub fn initialize_premium() -> anyhow::Result<()> {
    if !is_premium_available() {
        anyhow::bail!("Premium features not available");
    }
    
    // Initialize any premium subsystems
    tracing::info!("Premium features initialized");
    Ok(())
}