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
//! Universal shield display that works in any environment
//! No terminal control sequences, just plain ASCII text

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;

use super::Shield;
use crate::scanner::ThreatType;

/// Universal display options
#[derive(Debug, Clone)]
pub struct UniversalDisplayConfig {
    /// Enable color codes (ANSI)
    pub color: bool,
    /// Show detailed statistics
    pub detailed: bool,
    /// Output format
    pub format: DisplayFormat,
    /// Status file path (optional)
    pub status_file: Option<String>,
}

/// Display format for universal output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayFormat {
    /// Single line status
    Minimal,
    /// Multi-line compact status
    Compact,
    /// Full dashboard
    Dashboard,
    /// JSON output
    Json,
}

/// Status data for JSON/file output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalShieldStatus {
    pub active: bool,
    pub enhanced_mode: bool,
    pub threats_blocked: u64,
    pub uptime_seconds: u64,
    pub recent_threat_rate: f64,
    pub last_update: DateTime<Utc>,
    pub threat_breakdown: ThreatBreakdown,
    pub mode_name: String,
    pub status_emoji: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBreakdown {
    pub unicode_attacks: u64,
    pub injection_attempts: u64,
    pub path_traversal: u64,
    pub mcp_threats: u64,
}

/// Universal shield display
pub struct UniversalDisplay {
    shield: Arc<Shield>,
    config: UniversalDisplayConfig,
}

impl UniversalDisplay {
    /// Create new universal display
    pub const fn new(shield: Arc<Shield>, config: UniversalDisplayConfig) -> Self {
        Self { shield, config }
    }

    /// Get current status as structured data
    pub fn get_status(&self) -> UniversalShieldStatus {
        let info = self.shield.get_info();
        let stats = self.shield.get_threat_stats();
        let enhanced = self.shield.is_event_processor_enabled();

        // Count threats by category
        let unicode_count: u64 = stats
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k,
                    ThreatType::UnicodeInvisible
                        | ThreatType::UnicodeBiDi
                        | ThreatType::UnicodeHomograph
                        | ThreatType::UnicodeControl
                )
            })
            .map(|(_, v)| v)
            .sum();

        let injection_count: u64 = stats
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k,
                    ThreatType::PromptInjection
                        | ThreatType::CommandInjection
                        | ThreatType::SqlInjection
                )
            })
            .map(|(_, v)| v)
            .sum();

        let traversal_count = stats.get(&ThreatType::PathTraversal).copied().unwrap_or(0);

        let mcp_count: u64 = stats
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k,
                    ThreatType::SessionIdExposure
                        | ThreatType::ToolPoisoning
                        | ThreatType::TokenTheft
                )
            })
            .map(|(_, v)| v)
            .sum();

        UniversalShieldStatus {
            active: info.active,
            enhanced_mode: enhanced,
            threats_blocked: info.threats_blocked,
            uptime_seconds: info.uptime.as_secs(),
            recent_threat_rate: info.recent_threat_rate,
            last_update: Utc::now(),
            threat_breakdown: ThreatBreakdown {
                unicode_attacks: unicode_count,
                injection_attempts: injection_count,
                path_traversal: traversal_count,
                mcp_threats: mcp_count,
            },
            mode_name: if enhanced {
                "Enhanced".to_string()
            } else {
                "Standard".to_string()
            },
            status_emoji: if info.active {
                "🛡️".to_string()
            } else {
                "🔓".to_string()
            },
        }
    }

    /// Render the display
    pub fn render(&self) -> String {
        let status = self.get_status();

        match self.config.format {
            DisplayFormat::Minimal => self.render_minimal(&status),
            DisplayFormat::Compact => self.render_compact(&status),
            DisplayFormat::Dashboard => self.render_dashboard(&status),
            DisplayFormat::Json => serde_json::to_string_pretty(&status).unwrap_or_default(),
        }
    }

    /// Render minimal single-line format
    fn render_minimal(&self, status: &UniversalShieldStatus) -> String {
        let shield_icon = &status.status_emoji;
        let status_text = if status.active { "Active" } else { "Inactive" };
        let mode_indicator = if status.enhanced_mode { " ⚡" } else { "" };

        if self.config.color && status.enhanced_mode {
            // Purple color for enhanced mode
            format!(
                "{} KindlyGuard | Status: \x1b[35m{}{}\x1b[0m | Threats: {} | Uptime: {}",
                shield_icon,
                status_text,
                mode_indicator,
                status.threats_blocked,
                format_duration(status.uptime_seconds)
            )
        } else if self.config.color {
            // Standard blue color
            format!(
                "{} KindlyGuard | Status: \x1b[34m{}\x1b[0m | Threats: {} | Uptime: {}",
                shield_icon,
                status_text,
                status.threats_blocked,
                format_duration(status.uptime_seconds)
            )
        } else {
            // No color
            format!(
                "{} KindlyGuard | Status: {}{} | Threats: {} | Uptime: {}",
                shield_icon,
                status_text,
                mode_indicator,
                status.threats_blocked,
                format_duration(status.uptime_seconds)
            )
        }
    }

    /// Render compact multi-line format
    fn render_compact(&self, status: &UniversalShieldStatus) -> String {
        let mut output = String::new();

        // Header with mode indication
        if status.enhanced_mode {
            if self.config.color {
                output.push_str("\x1b[35mKindlyGuard Security Status [Enhanced]\x1b[0m\n");
                output.push_str("\x1b[35m─────────────────────────────────────\x1b[0m\n");
            } else {
                output.push_str("KindlyGuard Security Status [Enhanced]\n");
                output.push_str("─────────────────────────────────────\n");
            }
        } else if self.config.color {
            output.push_str("\x1b[34mKindlyGuard Security Status\x1b[0m\n");
            output.push_str("\x1b[34m─────────────────────────\x1b[0m\n");
        } else {
            output.push_str("KindlyGuard Security Status\n");
            output.push_str("─────────────────────────\n");
        }

        // Status line
        let status_symbol = if status.active { "●" } else { "○" };
        let status_text = if status.active { "Active" } else { "Inactive" };
        let mode_indicator = if status.enhanced_mode { " ⚡" } else { "" };

        if self.config.color && status.active {
            output.push_str(&format!(
                "{status_symbol} Protection: \x1b[32m{status_text}{mode_indicator}\x1b[0m\n"
            ));
        } else if self.config.color {
            output.push_str(&format!(
                "{status_symbol} Protection: \x1b[31m{status_text}\x1b[0m\n"
            ));
        } else {
            output.push_str(&format!(
                "{status_symbol} Protection: {status_text}{mode_indicator}\n"
            ));
        }

        // Stats
        output.push_str(&format!("● Threats Blocked: {}\n", status.threats_blocked));
        output.push_str(&format!(
            "● Uptime: {}\n",
            format_duration(status.uptime_seconds)
        ));
        output.push_str(&format!("● Mode: {}\n", status.mode_name));

        // Recent activity for enhanced mode
        if status.enhanced_mode {
            output.push_str("\nRecent Activity:\n");
            if self.config.color {
                output.push_str("• \x1b[35mAdvanced analytics enabled\x1b[0m\n");
                output.push_str("• \x1b[35mCorrelation engine active\x1b[0m\n");
                output.push_str("• \x1b[35mReal-time threat analysis\x1b[0m\n");
            } else {
                output.push_str("• Advanced analytics enabled\n");
                output.push_str("• Correlation engine active\n");
                output.push_str("• Real-time threat analysis\n");
            }
        } else {
            output.push_str("\nRecent Activity:\n");
            output.push_str("• System initialized\n");
            output.push_str("• Monitoring active\n");
        }

        output
    }

    /// Render full dashboard format
    fn render_dashboard(&self, status: &UniversalShieldStatus) -> String {
        let mut output = String::new();

        // Title
        if status.enhanced_mode && self.config.color {
            output.push_str("\x1b[35m╔═══════════════════════════════════════════════╗\x1b[0m\n");
            output.push_str("\x1b[35m║       🛡️  KindlyGuard Security Shield ⚡       ║\x1b[0m\n");
            output.push_str("\x1b[35m╠═══════════════════════════════════════════════╣\x1b[0m\n");
        } else if self.config.color {
            output.push_str("\x1b[34m╔═══════════════════════════════════════════════╗\x1b[0m\n");
            output.push_str("\x1b[34m║       🛡️  KindlyGuard Security Shield         ║\x1b[0m\n");
            output.push_str("\x1b[34m╠═══════════════════════════════════════════════╣\x1b[0m\n");
        } else {
            output.push_str("╔═══════════════════════════════════════════════╗\n");
            output.push_str("║       🛡️  KindlyGuard Security Shield         ║\n");
            output.push_str("╠═══════════════════════════════════════════════╣\n");
        }

        // Status section
        let status_line = format!(
            "║ Status: {:37} ║",
            format!(
                "{} {} {}",
                if status.active {
                    "✅ ACTIVE"
                } else {
                    "❌ INACTIVE"
                },
                if status.enhanced_mode {
                    "[Enhanced Mode]"
                } else {
                    ""
                },
                format_duration(status.uptime_seconds)
            )
        );
        output.push_str(&status_line);
        output.push('\n');

        output.push_str(&format!(
            "║ Threats Blocked: {:28} ║\n",
            status.threats_blocked
        ));
        output.push_str(&format!(
            "║ Threat Rate: {:32} ║\n",
            format!("{:.1}/min", status.recent_threat_rate)
        ));

        // Separator
        if self.config.color && status.enhanced_mode {
            output.push_str("\x1b[35m╠═══════════════════════════════════════════════╣\x1b[0m\n");
        } else if self.config.color {
            output.push_str("\x1b[34m╠═══════════════════════════════════════════════╣\x1b[0m\n");
        } else {
            output.push_str("╠═══════════════════════════════════════════════╣\n");
        }

        // Threat breakdown
        output.push_str("║ Threat Breakdown:                             ║\n");
        output.push_str(&format!(
            "║   • Unicode Attacks:     {:20} ║\n",
            status.threat_breakdown.unicode_attacks
        ));
        output.push_str(&format!(
            "║   • Injection Attempts:  {:20} ║\n",
            status.threat_breakdown.injection_attempts
        ));
        output.push_str(&format!(
            "║   • Path Traversal:      {:20} ║\n",
            status.threat_breakdown.path_traversal
        ));
        output.push_str(&format!(
            "║   • MCP Threats:         {:20} ║\n",
            status.threat_breakdown.mcp_threats
        ));

        // Footer
        if self.config.color && status.enhanced_mode {
            output.push_str("\x1b[35m╚═══════════════════════════════════════════════╝\x1b[0m\n");
        } else if self.config.color {
            output.push_str("\x1b[34m╚═══════════════════════════════════════════════╝\x1b[0m\n");
        } else {
            output.push_str("╚═══════════════════════════════════════════════╝\n");
        }

        output
    }

    /// Write status to file if configured
    pub fn write_status_file(&self) -> io::Result<()> {
        if let Some(ref path) = self.config.status_file {
            let status = self.get_status();
            let json = serde_json::to_string_pretty(&status)?;
            fs::write(path, json)?;
        }
        Ok(())
    }

    /// Print to stdout
    pub fn print(&self) -> io::Result<()> {
        let output = self.render();
        print!("{output}");
        io::stdout().flush()?;

        // Also write to status file if configured
        self.write_status_file()
    }
}

/// Format duration as human-readable string
fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Create a universal display with sensible defaults
pub fn create_universal_display(shield: Arc<Shield>) -> UniversalDisplay {
    let config = UniversalDisplayConfig {
        color: supports_color(),
        detailed: false,
        format: DisplayFormat::Compact,
        status_file: Some("/tmp/kindlyguard-status.json".to_string()),
    };

    UniversalDisplay::new(shield, config)
}

/// Check if terminal supports color
fn supports_color() -> bool {
    // Check common environment variables
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }

    // Default to true for most environments
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_display_formats() {
        let shield = Arc::new(Shield::new());
        let config = UniversalDisplayConfig {
            color: false,
            detailed: false,
            format: DisplayFormat::Minimal,
            status_file: None,
        };

        let display = UniversalDisplay::new(shield, config);
        let output = display.render();

        assert!(output.contains("KindlyGuard"));
        assert!(output.contains("Status:"));
    }

    #[test]
    fn test_json_output() {
        let shield = Arc::new(Shield::new());
        let config = UniversalDisplayConfig {
            color: false,
            detailed: false,
            format: DisplayFormat::Json,
            status_file: None,
        };

        let display = UniversalDisplay::new(shield, config);
        let output = display.render();

        // Should be valid JSON
        let parsed: Result<UniversalShieldStatus, _> = serde_json::from_str(&output);
        assert!(parsed.is_ok());
    }
}
