//! CLI Shield Integration - Always-present security status display

use crossterm::terminal;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scanner::ScannerStats;
use crate::shield::Shield;

/// Compact shield display for CLI integration
pub struct CliShield {
    shield: Arc<Shield>,
    format: DisplayFormat,
    last_update: Instant,
    update_interval: Duration,
    enabled: AtomicBool,
    /// For shell integration - tracks if we're in a command
    in_command: AtomicBool,
}

/// Display format options for the shield
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayFormat {
    /// Compact single-line format for prompts
    Compact,
    /// Status bar format for tmux/screen
    StatusBar,
    /// Inline format that preserves cursor position
    Inline,
    /// Minimal format with just icon and status
    Minimal,
}

/// Shield status for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldStatus {
    pub active: bool,
    pub threats_blocked: u64,
    pub uptime_seconds: u64,
    pub last_threat: Option<String>,
    pub scanner_stats: ScannerStats,
}

impl CliShield {
    pub fn new(shield: Arc<Shield>, format: DisplayFormat) -> Self {
        Self {
            shield,
            format,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(1000),
            enabled: AtomicBool::new(true),
            in_command: AtomicBool::new(false),
        }
    }

    /// Get the current shield status
    pub fn status(&self) -> ShieldStatus {
        let stats = self.shield.stats();
        let uptime = self.shield.start_time().elapsed().as_secs();

        ShieldStatus {
            active: self.shield.is_active(),
            threats_blocked: stats.threats_blocked,
            uptime_seconds: uptime,
            last_threat: self.shield.last_threat_type(),
            scanner_stats: self.shield.scanner_stats(),
        }
    }

    /// Render the shield display to a string
    pub fn render(&self) -> String {
        if !self.enabled.load(Ordering::Relaxed) {
            return String::new();
        }

        let status = self.status();

        match self.format {
            DisplayFormat::Compact => self.render_compact(&status),
            DisplayFormat::StatusBar => self.render_status_bar(&status),
            DisplayFormat::Inline => self.render_inline(&status),
            DisplayFormat::Minimal => self.render_minimal(&status),
        }
    }

    /// Render compact format for shell prompts
    fn render_compact(&self, status: &ShieldStatus) -> String {
        let shield_icon = if status.active { "🛡️" } else { "🔓" };
        let status_icon = if status.active { "✓" } else { "✗" };
        let threat_count = status.threats_blocked;
        let uptime = format_duration(status.uptime_seconds);

        if threat_count > 0 {
            format!(
                "[{shield_icon} KindlyGuard: {status_icon} Protected | ⚡ {threat_count} blocked | ⏱ {uptime}]"
            )
        } else {
            format!("[{shield_icon} KindlyGuard: {status_icon} Protected | ⏱ {uptime}]")
        }
    }

    /// Render status bar format for tmux/screen
    fn render_status_bar(&self, status: &ShieldStatus) -> String {
        let shield_icon = if status.active { "🛡️" } else { "🔓" };
        let threats = status.threats_blocked;

        if let Some(last_threat) = &status.last_threat {
            format!("{shield_icon} {last_threat} ⚡{threats}")
        } else {
            format!("{shield_icon} Safe ⚡{threats}")
        }
    }

    /// Render inline format that preserves cursor
    fn render_inline(&self, status: &ShieldStatus) -> String {
        let shield_icon = if status.active { "🛡️" } else { "🔓" };
        let status_text = if status.active { "ON" } else { "OFF" };

        format!("\r{shield_icon} {status_text}")
    }

    /// Render minimal format
    fn render_minimal(&self, status: &ShieldStatus) -> String {
        if status.active {
            if status.threats_blocked > 0 {
                format!("🛡️⚡{}", status.threats_blocked)
            } else {
                "🛡️".to_string()
            }
        } else {
            "🔓".to_string()
        }
    }

    /// Update the display if needed
    pub fn update(&mut self) -> io::Result<()> {
        if !self.should_update() {
            return Ok(());
        }

        let display = self.render();
        if !display.is_empty() {
            self.write_display(&display)?;
        }

        self.last_update = Instant::now();
        Ok(())
    }

    /// Check if display should be updated
    fn should_update(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
            && self.last_update.elapsed() >= self.update_interval
            && !self.in_command.load(Ordering::Relaxed)
    }

    /// Write display to terminal
    fn write_display(&self, display: &str) -> io::Result<()> {
        let mut stdout = io::stdout();

        if self.format == DisplayFormat::Inline {
            // Save cursor position, write at top-right, restore
            write!(stdout, "\x1b7")?; // Save cursor
            write!(
                stdout,
                "\x1b[1;{}H",
                terminal::size()?.0.saturating_sub(display.len() as u16)
            )?;
            write!(stdout, "{display}")?;
            write!(stdout, "\x1b8")?; // Restore cursor
            stdout.flush()?;
        } else {
            // For other formats, just write to stdout
            write!(stdout, "{display}")?;
            stdout.flush()?;
        }

        Ok(())
    }

    /// Enable/disable the shield display
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Set whether we're currently in a command (for shell integration)
    pub fn set_in_command(&self, in_command: bool) {
        self.in_command.store(in_command, Ordering::Relaxed);
    }

    /// Get shell initialization script
    pub fn shell_init_script(shell: &str) -> String {
        match shell {
            "bash" => include_str!("../../scripts/shell-init.bash").to_string(),
            "zsh" => include_str!("../../scripts/shell-init.zsh").to_string(),
            "fish" => include_str!("../../scripts/shell-init.fish").to_string(),
            _ => String::new(),
        }
    }
}

/// Format duration for display
fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;

    if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

/// Shell hook commands for integration
pub mod hooks {

    /// Pre-command hook (called before each command)
    pub const fn pre_command_hook() -> &'static str {
        r"
        if command -v kindly-guard >/dev/null 2>&1; then
            kindly-guard shield pre-command
        fi
        "
    }

    /// Post-command hook (called after each command)
    pub const fn post_command_hook() -> &'static str {
        r"
        if command -v kindly-guard >/dev/null 2>&1; then
            kindly-guard shield post-command
        fi
        "
    }

    /// Prompt command for bash/zsh
    pub const fn prompt_command() -> &'static str {
        r#"
        if command -v kindly-guard >/dev/null 2>&1; then
            KINDLY_GUARD_STATUS="$(kindly-guard shield status --format=compact)"
            if [ -n "$KINDLY_GUARD_STATUS" ]; then
                echo -e "\033[1;34m$KINDLY_GUARD_STATUS\033[0m"
            fi
        fi
        "#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_formats() {
        let shield = Arc::new(Shield::new());
        let cli_shield = CliShield::new(shield.clone(), DisplayFormat::Compact);

        let display = cli_shield.render();
        assert!(display.contains("KindlyGuard"));
        assert!(display.contains("Protected"));
    }

    #[test]
    fn test_status_serialization() {
        let shield = Arc::new(Shield::new());
        let cli_shield = CliShield::new(shield, DisplayFormat::Minimal);

        let status = cli_shield.status();
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("active"));
        assert!(json.contains("threats_blocked"));
    }
}
