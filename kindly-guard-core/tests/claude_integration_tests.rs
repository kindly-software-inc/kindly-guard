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
//! Tests for Claude Code integration module

use kindly_guard_core::premium::{
    ClaudeCodeIntegration,
    ClaudeIntegrationConfig,
    claude_integration::{
        animations::AnimationType,
        commands::{CommandParser, ClaudeCommand},
        display::{DisplayMode, ShieldDashboard, MiniStatus},
        injector::{ResponseInjector, InjectionPoint},
    },
};
use std::time::Duration;

#[test]
fn test_integration_creation() {
    let config = ClaudeIntegrationConfig::default();
    let integration = ClaudeCodeIntegration::new(config);
    assert!(integration.is_ok());
}

#[test]
fn test_config_defaults() {
    let config = ClaudeIntegrationConfig::default();
    assert!(config.show_launch_animation);
    assert!(config.enable_mini_status);
    assert!(config.inject_headers);
    assert_eq!(config.update_interval, Duration::from_secs(1));
}

#[test]
fn test_command_parsing() {
    let parser = CommandParser::new();
    
    // Test valid commands
    assert_eq!(
        parser.parse("claude shield").unwrap(),
        Some(ClaudeCommand::Shield)
    );
    assert_eq!(
        parser.parse("claude status").unwrap(),
        Some(ClaudeCommand::Status)
    );
    assert_eq!(
        parser.parse("claude animate").unwrap(),
        Some(ClaudeCommand::Animate)
    );
    assert_eq!(
        parser.parse("claude theme matrix").unwrap(),
        Some(ClaudeCommand::Theme("matrix".to_string()))
    );
    
    // Test invalid commands
    assert_eq!(parser.parse("random text").unwrap(), None);
    assert_eq!(parser.parse("").unwrap(), None);
}

#[test]
fn test_response_injection() {
    let injector = ResponseInjector::new();
    
    // Test top injection
    let mut response = "Original content".to_string();
    injector.inject_at_point(
        &mut response,
        "Header".to_string(),
        InjectionPoint::Top
    ).unwrap();
    assert!(response.starts_with("Header\n"));
    
    // Test bottom injection
    let mut response = "Original content".to_string();
    injector.inject_at_point(
        &mut response,
        "Footer".to_string(),
        InjectionPoint::Bottom
    ).unwrap();
    assert!(response.ends_with("\nFooter"));
    
    // Test badge injection
    let mut response = "Test".to_string();
    injector.inject_badge(&mut response, 5).unwrap();
    assert!(response.contains("5 threats neutralized"));
}

#[test]
fn test_mini_status_render() {
    use kindly_guard_core::premium::SecurityStats;
    
    let stats = SecurityStats {
        threats_blocked: 100,
        active_connections: 5,
        requests_processed: 1000,
        uptime: Duration::from_secs(3600),
        threat_types: vec![
            ("Unicode Attacks".to_string(), 50),
            ("Injection Attempts".to_string(), 30),
            ("XSS Attempts".to_string(), 20),
        ],
    };
    
    let mini_status = MiniStatus::new();
    let output = mini_status.render(&stats).unwrap();
    
    assert!(output.contains("100 threats blocked"));
    assert!(output.contains("5 active"));
    assert!(output.contains("🟢")); // Active indicator
}

#[test]
fn test_dashboard_render_modes() {
    use kindly_guard_core::premium::SecurityStats;
    
    let stats = SecurityStats {
        threats_blocked: 42,
        active_connections: 3,
        requests_processed: 999,
        uptime: Duration::from_secs(7200),
        threat_types: vec![],
    };
    
    // Test full mode
    let dashboard = ShieldDashboard::new(DisplayMode::Full);
    let full_output = dashboard.render(&stats).unwrap();
    assert!(full_output.contains("KINDLYGUARD SHIELD"));
    assert!(full_output.contains("Security Statistics"));
    assert!(full_output.contains("Protection Status"));
    
    // Test compact mode
    let dashboard = ShieldDashboard::new(DisplayMode::Compact);
    let compact_output = dashboard.render(&stats).unwrap();
    assert!(compact_output.contains("KindlyGuard Shield"));
    assert!(compact_output.len() < full_output.len());
    
    // Test minimal mode
    let dashboard = ShieldDashboard::new(DisplayMode::Minimal);
    let minimal_output = dashboard.render(&stats).unwrap();
    assert!(minimal_output.contains("42"));
    assert!(minimal_output.len() < compact_output.len());
}

#[tokio::test]
async fn test_process_command() {
    let integration = ClaudeCodeIntegration::with_defaults().unwrap();
    
    // Test shield command
    let response = integration.process_command("claude shield").await.unwrap();
    assert!(response.is_some());
    assert!(response.unwrap().contains("SHIELD"));
    
    // Test status command
    let response = integration.process_command("claude status").await.unwrap();
    assert!(response.is_some());
    assert!(response.unwrap().contains("threats blocked"));
    
    // Test invalid command
    let response = integration.process_command("invalid").await.unwrap();
    assert!(response.is_none());
}

#[test]
fn test_environment_detection() {
    // Set test environment variable
    std::env::set_var("CLAUDE_CODE_SESSION", "test");
    assert!(ClaudeCodeIntegration::is_claude_code_environment());
    std::env::remove_var("CLAUDE_CODE_SESSION");
    
    // Without env var, should be false (unless other conditions met)
    let is_claude = ClaudeCodeIntegration::is_claude_code_environment();
    assert!(!is_claude || std::env::args().any(|arg| arg.contains("--stdio")));
}

#[test]
fn test_theme_configuration() {
    use kindly_guard_core::premium::claude_integration::{ThemeConfig, BackgroundStyle};
    
    let theme = ThemeConfig::default();
    assert_eq!(theme.primary_color, "#00ff00");
    assert!(matches!(theme.background_style, BackgroundStyle::Matrix));
}

#[tokio::test]
async fn test_metrics_tracking() {
    let integration = ClaudeCodeIntegration::with_defaults().unwrap();
    
    // Process some commands
    integration.process_command("claude shield").await.unwrap();
    integration.process_command("claude status").await.unwrap();
    
    let metrics = integration.get_metrics();
    assert_eq!(metrics.commands_processed, 2);
    
    // Reset and check
    integration.reset_session();
    let metrics = integration.get_metrics();
    assert_eq!(metrics.commands_processed, 0);
}