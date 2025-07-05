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

//! Monitor command for real-time KindlyGuard server status

use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

/// Run the monitor command
pub async fn run(url: String, interval: u64) -> Result<()> {
    println!(
        "{}",
        format!("Monitoring KindlyGuard server at {url}").green()
    );
    println!("Press Ctrl+C to stop\n");

    loop {
        match fetch_server_status(&url).await {
            Ok(status) => {
                print_server_status(&status);
            }
            Err(e) => {
                println!("{}: {}", "Error".red(), e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

async fn fetch_server_status(_url: &str) -> Result<Value> {
    // For now, return a placeholder
    // TODO: Implement actual HTTP request to server
    Ok(serde_json::json!({
        "active": true,
        "uptime_seconds": 3600,
        "threats_blocked": 42,
        "scanner_stats": {
            "unicode_threats": 23,
            "injection_threats": 15,
            "total_scans": 1000,
        }
    }))
}

fn print_server_status(status: &Value) {
    use chrono::Duration;

    let active = status["active"].as_bool().unwrap_or(false);
    let uptime_secs = status["uptime_seconds"].as_u64().unwrap_or(0);
    let threats_blocked = status["threats_blocked"].as_u64().unwrap_or(0);

    // Clear screen
    print!("\x1B[2J\x1B[1;1H");

    println!("{}", "╭──────────────────────────────────────╮".cyan());
    println!("{}", "│ 🛡️  KindlyGuard Server Status        │".cyan());
    println!("{}", "├──────────────────────────────────────┤".cyan());

    let status_text = if active {
        "● Active".green()
    } else {
        "○ Inactive".red()
    };
    println!("│ Status: {status_text:28} │");

    let duration = Duration::seconds(uptime_secs as i64);
    let hours = duration.num_hours();
    let minutes = (duration.num_minutes() % 60) as u64;
    let seconds = (duration.num_seconds() % 60) as u64;
    let uptime_str = format!("{hours}h {minutes}m {seconds}s");
    println!("│ Uptime: {uptime_str:28} │");
    println!("│ Threats Blocked: {threats_blocked:19} │");

    if let Some(stats) = status["scanner_stats"].as_object() {
        println!("{}", "├──────────────────────────────────────┤".cyan());
        println!("│ Scanner Statistics:                  │");
        println!(
            "│   Unicode threats: {:17} │",
            stats["unicode_threats"].as_u64().unwrap_or(0)
        );
        println!(
            "│   Injection threats: {:15} │",
            stats["injection_threats"].as_u64().unwrap_or(0)
        );
        println!(
            "│   Total scans: {:21} │",
            stats["total_scans"].as_u64().unwrap_or(0)
        );
    }

    println!("{}", "╰──────────────────────────────────────╯".cyan());
}