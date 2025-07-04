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
//! Example demonstrating Claude Code integration

use anyhow::Result;
use kindly_guard_core::premium::{
    ClaudeCodeIntegration, 
    ClaudeIntegrationConfig,
    SecurityStats,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Check if running in Claude Code environment
    if ClaudeCodeIntegration::is_claude_code_environment() {
        println!("🎉 Running in Claude Code environment!");
    } else {
        println!("ℹ️  Not running in Claude Code (demo mode)");
    }
    
    // Create integration with custom config
    let mut config = ClaudeIntegrationConfig::default();
    config.animation_type = kindly_guard_core::premium::claude_integration::animations::AnimationType::Shield;
    config.display_mode = kindly_guard_core::premium::claude_integration::display::DisplayMode::Full;
    
    let integration = ClaudeCodeIntegration::new(config)?;
    
    // Initialize session
    println!("\n🚀 Initializing Claude Code session...");
    integration.initialize_session().await?;
    
    // Simulate some commands
    println!("\n📝 Testing command parsing...");
    
    let commands = vec![
        "claude shield",
        "claude status",
        "claude theme matrix",
        "claude help",
    ];
    
    for cmd in commands {
        println!("\n> {}", cmd);
        if let Some(response) = integration.process_command(cmd).await? {
            println!("{}", response);
        }
    }
    
    // Test response injection
    println!("\n💉 Testing response injection...");
    let mut response = "This is a test response from KindlyGuard.".to_string();
    integration.inject_shield_header(&mut response)?;
    println!("\nInjected response:\n{}", response);
    
    // Display metrics
    let metrics = integration.get_metrics();
    println!("\n📊 Integration Metrics:");
    println!("  Commands processed: {}", metrics.commands_processed);
    println!("  Frames rendered: {}", metrics.frames_rendered);
    println!("  Injections performed: {}", metrics.injections_performed);
    println!("  Avg render time: {:.2}ms", metrics.avg_render_time_ms);
    
    Ok(())
}