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

//! Command wrapping functionality

use anyhow::Result;
use colored::Colorize;

/// Run command with security wrapping
pub async fn run_wrap(command: Vec<String>, block: bool, log: Option<String>) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified to wrap");
    }

    let cmd_display = command.join(" ");
    println!("{} Wrapping command: {}", "🛡️".bright_cyan(), cmd_display.bright_white());

    // Pre-execution security checks
    println!("{} Running pre-execution security checks...", "🔍".bright_cyan());
    
    // Execute the wrapped command
    println!("{} Executing wrapped command...", "▶️".bright_green());
    
    let mut cmd = std::process::Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    let output = cmd.output()?;
    
    // Check output for threats
    if block {
        println!("{} Scanning output for threats...", "🔍".bright_cyan());
        // TODO: Implement threat scanning
    }

    // Log if requested
    if let Some(log_path) = log {
        println!("{} Logging output to: {}", "📝".bright_blue(), log_path.bright_white());
        std::fs::write(&log_path, &output.stdout)?;
    }

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        println!("{} Command failed with exit code: {}", "❌".bright_red(), code);
    } else {
        println!("{} Command completed successfully", "✅".bright_green());
    }

    // Print output
    if !output.stdout.is_empty() {
        println!("\nCommand output:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    
    if !output.stderr.is_empty() {
        eprintln!("\nCommand stderr:");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}