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
//! Lightning Shield Renderer
//!
//! Renders the animated shield to the terminal with various display modes
//! including full dashboard, compact view, and mini status bar.

#![cfg(feature = "enhanced")]

use std::fmt::Write;
use super::{Intensity, easing};

/// Color codes for terminal rendering
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    
    // Shield colors
    pub const SHIELD_IDLE: &str = "\x1b[38;5;33m";      // Blue
    pub const SHIELD_ALERT: &str = "\x1b[38;5;220m";    // Yellow
    pub const SHIELD_ACTIVE: &str = "\x1b[38;5;196m";   // Red
    pub const SHIELD_VICTORY: &str = "\x1b[38;5;46m";   // Green
    
    // Lightning colors
    pub const LIGHTNING_PRIMARY: &str = "\x1b[38;5;226m";   // Bright yellow
    pub const LIGHTNING_SECONDARY: &str = "\x1b[38;5;51m";  // Cyan
    
    // Background colors
    pub const BG_DARK: &str = "\x1b[48;5;233m";
    pub const BG_SHIELD: &str = "\x1b[48;5;234m";
}

/// Box drawing characters for Unicode borders
pub mod box_chars {
    pub const TOP_LEFT: char = '╔';
    pub const TOP_RIGHT: char = '╗';
    pub const BOTTOM_LEFT: char = '╚';
    pub const BOTTOM_RIGHT: char = '╝';
    pub const HORIZONTAL: char = '═';
    pub const VERTICAL: char = '║';
    pub const CROSS: char = '╬';
    pub const T_DOWN: char = '╦';
    pub const T_UP: char = '╩';
    pub const T_RIGHT: char = '╠';
    pub const T_LEFT: char = '╣';
}

/// Shield display configuration
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Terminal width
    pub width: usize,
    /// Terminal height  
    pub height: usize,
    /// Enable color output
    pub color_enabled: bool,
    /// Enable Unicode characters
    pub unicode_enabled: bool,
    /// Animation frame rate
    pub fps: u32,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            width: 80,
            height: 24,
            color_enabled: true,
            unicode_enabled: true,
            fps: 30,
        }
    }
}

/// Shield statistics for display
#[derive(Debug, Clone, Default)]
pub struct ShieldStats {
    /// Total threats blocked
    pub threats_blocked: u64,
    /// Current session duration in seconds
    pub session_duration: u64,
    /// Average response time in microseconds
    pub avg_response_time: u64,
    /// Current protection level
    pub protection_level: String,
    /// Active scanners count
    pub active_scanners: u32,
}

/// Initialize rendering backend
pub fn initialize_backend() -> anyhow::Result<()> {
    // Terminal capability checks would go here
    Ok(())
}

/// Main Lightning Shield renderer
pub struct LightningRenderer {
    config: RenderConfig,
    animation_phase: f32,
    frame_counter: u64,
}

impl LightningRenderer {
    /// Create a new renderer with the given configuration
    pub fn new(config: RenderConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            animation_phase: 0.0,
            frame_counter: 0,
        })
    }
    
    /// Create a new renderer with default configuration
    pub fn default() -> Self {
        Self::with_config(RenderConfig::default())
    }
    
    /// Create a new renderer with custom configuration (infallible version)
    pub fn with_config(config: RenderConfig) -> Self {
        Self {
            config,
            animation_phase: 0.0,
            frame_counter: 0,
        }
    }
    
    /// Update animation state
    pub fn update(&mut self, delta_time: f32) {
        self.animation_phase += delta_time;
        if self.animation_phase > std::f32::consts::TAU {
            self.animation_phase -= std::f32::consts::TAU;
        }
        self.frame_counter += 1;
    }
    
    /// Render effects to the terminal
    pub fn render(&self, effects: &[super::effects::LightningEffect]) -> anyhow::Result<()> {
        // In a real implementation, this would render effects
        // For now, just validate we can process them
        for effect in effects {
            let _ = effect.progress();
            let _ = effect.alpha();
        }
        Ok(())
    }
    
    /// Render the full dashboard display
    pub fn render_dashboard(&self, stats: &ShieldStats, intensity: Intensity) -> String {
        let mut output = String::with_capacity(4096);
        
        // Clear screen and move cursor to top
        output.push_str("\x1b[2J\x1b[H");
        
        // Render header box
        self.render_header(&mut output, intensity);
        
        // Render animated shield
        output.push_str("\n");
        self.render_shield(&mut output, intensity, true);
        
        // Render statistics
        output.push_str("\n");
        self.render_stats(&mut output, stats);
        
        // Render footer
        self.render_footer(&mut output, &stats.protection_level);
        
        output
    }
    
    /// Render compact shield view
    pub fn render_compact(&self, intensity: Intensity) -> String {
        let mut output = String::with_capacity(1024);
        self.render_shield(&mut output, intensity, false);
        output
    }
    
    /// Render mini status bar (single line)
    pub fn render_status_bar(&self, stats: &ShieldStats, intensity: Intensity) -> String {
        let mut output = String::with_capacity(256);
        
        let shield_icon = self.get_shield_icon(intensity);
        let color = self.get_intensity_color(intensity);
        
        if self.config.color_enabled {
            write!(
                &mut output,
                "{}{} KindlyGuard {} | Threats: {} | Time: {}s | {} {}",
                color,
                shield_icon,
                colors::DIM,
                stats.threats_blocked,
                stats.session_duration,
                stats.protection_level,
                colors::RESET
            ).unwrap();
        } else {
            write!(
                &mut output,
                "{} KindlyGuard | Threats: {} | Time: {}s | {}",
                shield_icon,
                stats.threats_blocked,
                stats.session_duration,
                stats.protection_level
            ).unwrap();
        }
        
        output
    }
    
    /// Render threat detection alert
    pub fn render_threat_alert(&self, threat_type: &str, threat_details: &str) -> String {
        let mut output = String::with_capacity(512);
        
        let width = self.config.width.min(60);
        let padding = " ".repeat((width - threat_type.len() - 6) / 2);
        
        if self.config.color_enabled {
            output.push_str(colors::SHIELD_ACTIVE);
            output.push_str(colors::BOLD);
        }
        
        // Top border
        output.push_str(&self.create_box_top(width));
        output.push('\n');
        
        // Alert header
        output.push(box_chars::VERTICAL);
        output.push_str(&padding);
        output.push_str("⚠️  ");
        output.push_str(threat_type);
        output.push_str("  ⚠️");
        output.push_str(&padding);
        if padding.len() * 2 + threat_type.len() + 6 < width - 2 {
            output.push(' ');
        }
        output.push(box_chars::VERTICAL);
        output.push('\n');
        
        // Separator
        output.push(box_chars::T_RIGHT);
        for _ in 0..width-2 {
            output.push(box_chars::HORIZONTAL);
        }
        output.push(box_chars::T_LEFT);
        output.push('\n');
        
        // Threat details
        self.render_wrapped_text(&mut output, threat_details, width - 4);
        
        // Bottom border
        output.push_str(&self.create_box_bottom(width));
        
        if self.config.color_enabled {
            output.push_str(colors::RESET);
        }
        
        output
    }
    
    // Helper methods
    
    fn render_header(&self, output: &mut String, intensity: Intensity) {
        let width = self.config.width.min(60);
        let title = "⚡ KINDLYGUARD PREMIUM ACTIVE ⚡";
        let padding = " ".repeat((width - title.len() - 2) / 2);
        
        if self.config.color_enabled {
            output.push_str(colors::LIGHTNING_PRIMARY);
            output.push_str(colors::BOLD);
        }
        
        // Top border
        output.push_str(&self.create_box_top(width));
        output.push('\n');
        
        // Title line
        output.push(box_chars::VERTICAL);
        output.push_str(&padding);
        output.push_str(title);
        output.push_str(&padding);
        if padding.len() * 2 + title.len() < width - 2 {
            output.push(' ');
        }
        output.push(box_chars::VERTICAL);
        output.push('\n');
        
        // Status line
        let status = match intensity {
            Intensity::Idle => "Protection: ENHANCED MODE",
            Intensity::Alert => "Protection: ALERT MODE",
            Intensity::Active => "Protection: ACTIVE DEFENSE",
            Intensity::Victory => "Protection: THREAT NEUTRALIZED",
        };
        
        let status_padding = " ".repeat((width - status.len() - 2) / 2);
        output.push(box_chars::VERTICAL);
        
        if self.config.color_enabled {
            output.push_str(self.get_intensity_color(intensity));
        }
        
        output.push_str(&status_padding);
        output.push_str(status);
        output.push_str(&status_padding);
        if status_padding.len() * 2 + status.len() < width - 2 {
            output.push(' ');
        }
        
        if self.config.color_enabled {
            output.push_str(colors::LIGHTNING_PRIMARY);
        }
        
        output.push(box_chars::VERTICAL);
        output.push('\n');
        
        // Bottom border
        output.push_str(&self.create_box_bottom(width));
        
        if self.config.color_enabled {
            output.push_str(colors::RESET);
        }
    }
    
    fn render_shield(&self, output: &mut String, intensity: Intensity, large: bool) {
        let shield_art = if large {
            self.get_large_shield_art()
        } else {
            self.get_small_shield_art()
        };
        
        let breath_scale = self.calculate_breathing_scale(intensity);
        let color = self.get_intensity_color(intensity);
        
        for (i, line) in shield_art.iter().enumerate() {
            // Apply breathing effect to middle lines
            let line_scale = if i > 0 && i < shield_art.len() - 1 {
                breath_scale
            } else {
                1.0
            };
            
            // Calculate padding for centering
            let effective_width = (line.len() as f32 * line_scale) as usize;
            let padding = " ".repeat((self.config.width - effective_width) / 2);
            
            output.push_str(&padding);
            
            if self.config.color_enabled {
                output.push_str(color);
                
                // Add glow effect for active states
                if intensity == Intensity::Active || intensity == Intensity::Victory {
                    output.push_str(colors::BOLD);
                }
            }
            
            // Render line with optional scaling
            if line_scale > 1.0 {
                // Stretch the line for breathing effect
                for ch in line.chars() {
                    output.push(ch);
                    if ch != ' ' && line_scale > 1.1 {
                        output.push(ch); // Double characters for expansion
                    }
                }
            } else {
                output.push_str(line);
            }
            
            if self.config.color_enabled {
                output.push_str(colors::RESET);
            }
            
            output.push('\n');
        }
    }
    
    fn render_stats(&self, output: &mut String, stats: &ShieldStats) {
        let width = self.config.width.min(60);
        
        // Create stats box
        output.push_str(&self.create_box_top(width));
        output.push('\n');
        
        // Threats blocked with animated counter
        let threats_display = self.format_animated_number(stats.threats_blocked);
        self.render_stat_line(output, "Threats Blocked", &threats_display, width);
        
        // Session duration
        let duration_display = self.format_duration(stats.session_duration);
        self.render_stat_line(output, "Session Time", &duration_display, width);
        
        // Response time with progress bar
        let response_display = format!("{} μs", stats.avg_response_time);
        self.render_stat_line(output, "Avg Response", &response_display, width);
        
        // Active scanners with indicator
        let scanners_display = format!("{} active", stats.active_scanners);
        self.render_stat_line(output, "Scanners", &scanners_display, width);
        
        output.push_str(&self.create_box_bottom(width));
    }
    
    fn render_footer(&self, output: &mut String, protection_level: &str) {
        output.push('\n');
        
        let footer_text = format!("Current Protection: {}", protection_level);
        let padding = " ".repeat((self.config.width - footer_text.len()) / 2);
        
        if self.config.color_enabled {
            output.push_str(colors::DIM);
        }
        
        output.push_str(&padding);
        output.push_str(&footer_text);
        
        if self.config.color_enabled {
            output.push_str(colors::RESET);
        }
    }
    
    fn render_stat_line(&self, output: &mut String, label: &str, value: &str, width: usize) {
        let dots = ".".repeat(width - label.len() - value.len() - 6);
        
        output.push(box_chars::VERTICAL);
        output.push(' ');
        output.push_str(label);
        output.push(' ');
        
        if self.config.color_enabled {
            output.push_str(colors::DIM);
        }
        
        output.push_str(&dots);
        
        if self.config.color_enabled {
            output.push_str(colors::RESET);
            output.push_str(colors::BOLD);
        }
        
        output.push(' ');
        output.push_str(value);
        output.push(' ');
        
        if self.config.color_enabled {
            output.push_str(colors::RESET);
        }
        
        output.push(box_chars::VERTICAL);
        output.push('\n');
    }
    
    fn render_wrapped_text(&self, output: &mut String, text: &str, max_width: usize) {
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut current_line = String::new();
        
        for word in words {
            if current_line.len() + word.len() + 1 > max_width {
                // Render current line
                output.push(box_chars::VERTICAL);
                output.push(' ');
                output.push_str(&current_line);
                output.push_str(&" ".repeat(max_width - current_line.len()));
                output.push(' ');
                output.push(box_chars::VERTICAL);
                output.push('\n');
                
                current_line.clear();
            }
            
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
        
        // Render last line
        if !current_line.is_empty() {
            output.push(box_chars::VERTICAL);
            output.push(' ');
            output.push_str(&current_line);
            output.push_str(&" ".repeat(max_width - current_line.len()));
            output.push(' ');
            output.push(box_chars::VERTICAL);
            output.push('\n');
        }
    }
    
    fn calculate_breathing_scale(&self, intensity: Intensity) -> f32 {
        let amplitude = intensity.amplitude();
        let base_scale = 1.0 + amplitude * easing::sine_in_out(self.animation_phase / std::f32::consts::TAU);
        base_scale
    }
    
    fn get_shield_icon(&self, intensity: Intensity) -> &'static str {
        match intensity {
            Intensity::Idle => "🛡️",
            Intensity::Alert => "⚠️",
            Intensity::Active => "🔥",
            Intensity::Victory => "✨",
        }
    }
    
    fn get_intensity_color(&self, intensity: Intensity) -> &'static str {
        match intensity {
            Intensity::Idle => colors::SHIELD_IDLE,
            Intensity::Alert => colors::SHIELD_ALERT,
            Intensity::Active => colors::SHIELD_ACTIVE,
            Intensity::Victory => colors::SHIELD_VICTORY,
        }
    }
    
    fn get_large_shield_art(&self) -> Vec<&'static str> {
        vec![
            "    ╔═══════════════╗    ",
            "   ╔╝               ╚╗   ",
            "  ║    ⚡ GUARD ⚡    ║  ",
            " ║                   ║ ",
            "║    ╔═════════╗     ║",
            "║    ║ KINDLY  ║     ║",
            "║    ║ SECURE  ║     ║",
            "║    ╚═════════╝     ║",
            " ║                   ║ ",
            "  ╚═════════════════╝  ",
            "         ╚═══╝         ",
        ]
    }
    
    fn get_small_shield_art(&self) -> Vec<&'static str> {
        vec![
            "  ╔═══╗  ",
            " ║ ⚡ ║ ",
            "║ KG  ║",
            " ╚═══╝ ",
        ]
    }
    
    fn create_box_top(&self, width: usize) -> String {
        let mut line = String::with_capacity(width);
        line.push(box_chars::TOP_LEFT);
        for _ in 0..width-2 {
            line.push(box_chars::HORIZONTAL);
        }
        line.push(box_chars::TOP_RIGHT);
        line
    }
    
    fn create_box_bottom(&self, width: usize) -> String {
        let mut line = String::with_capacity(width);
        line.push(box_chars::BOTTOM_LEFT);
        for _ in 0..width-2 {
            line.push(box_chars::HORIZONTAL);
        }
        line.push(box_chars::BOTTOM_RIGHT);
        line
    }
    
    fn format_animated_number(&self, num: u64) -> String {
        // Add commas for readability
        let num_str = num.to_string();
        let mut result = String::new();
        
        for (i, ch) in num_str.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(ch);
        }
        
        result.chars().rev().collect()
    }
    
    fn format_duration(&self, seconds: u64) -> String {
        if seconds < 60 {
            format!("{}s", seconds)
        } else if seconds < 3600 {
            format!("{}m {}s", seconds / 60, seconds % 60)
        } else {
            format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
        }
    }
}

impl Default for LightningRenderer {
    fn default() -> Self {
        Self::with_config(RenderConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_renderer_creation() {
        let renderer = LightningRenderer::default();
        assert_eq!(renderer.frame_counter, 0);
    }
    
    #[test]
    fn test_status_bar_rendering() {
        let renderer = LightningRenderer::default();
        let stats = ShieldStats {
            threats_blocked: 42,
            session_duration: 3661,
            protection_level: "Enhanced".to_string(),
            ..Default::default()
        };
        
        let output = renderer.render_status_bar(&stats, Intensity::Idle);
        assert!(output.contains("KindlyGuard"));
        assert!(output.contains("42"));
        assert!(output.contains("3661s"));
    }
    
    #[test]
    fn test_threat_alert_rendering() {
        let renderer = LightningRenderer::default();
        let alert = renderer.render_threat_alert(
            "SQL Injection Detected",
            "Malicious SQL pattern found in user input"
        );
        
        assert!(alert.contains("SQL Injection"));
        assert!(alert.contains("Malicious"));
    }
    
    #[test]
    fn test_duration_formatting() {
        let renderer = LightningRenderer::default();
        assert_eq!(renderer.format_duration(45), "45s");
        assert_eq!(renderer.format_duration(125), "2m 5s");
        assert_eq!(renderer.format_duration(7265), "2h 1m");
    }
    
    #[test]
    fn test_number_formatting() {
        let renderer = LightningRenderer::default();
        assert_eq!(renderer.format_animated_number(1234567), "1,234,567");
        assert_eq!(renderer.format_animated_number(999), "999");
        assert_eq!(renderer.format_animated_number(1000), "1,000");
    }
}