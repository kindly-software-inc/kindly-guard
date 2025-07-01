//! Terminal-based shield display using ratatui

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

use super::Shield;
use crate::config::ShieldConfig;
use crate::scanner::ThreatType;

/// Shield display for terminal UI
pub struct ShieldDisplay {
    shield: Arc<Shield>,
    config: ShieldConfig,
}

impl ShieldDisplay {
    /// Create a new shield display
    pub const fn new(shield: Arc<Shield>, config: ShieldConfig) -> Self {
        Self { shield, config }
    }

    /// Run the shield display
    pub async fn run(&self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        stdout.execute(EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create update interval
        let mut ticker = interval(Duration::from_millis(self.config.update_interval_ms));

        loop {
            // Draw UI
            terminal.draw(|f| self.draw_ui(f))?;

            // Handle events
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }

            ticker.tick().await;
        }

        // Restore terminal
        disable_raw_mode()?;
        terminal.backend_mut().execute(LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    /// Draw the UI
    fn draw_ui(&self, frame: &mut Frame) {
        let size = frame.area();

        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(5),  // Status
                Constraint::Length(10), // Threat stats
                Constraint::Length(5),  // Performance
                Constraint::Min(0),     // Recent threats
            ])
            .split(size);

        // Get shield info
        let info = self.shield.get_info();
        let threat_stats = self.shield.get_threat_stats();

        // Title block - Purple if event processor enabled
        let enhanced_mode = self.shield.is_event_processor_enabled();
        let title_color = if enhanced_mode {
            Color::Magenta
        } else {
            Color::Cyan
        };
        let title_text = if enhanced_mode {
            "🛡️  KindlyGuard Security Shield ⚡ Enhanced Protection Active"
        } else {
            "🛡️  KindlyGuard Security Shield"
        };

        let title = Paragraph::new(title_text)
            .style(
                Style::default()
                    .fg(title_color)
                    .add_modifier(Modifier::BOLD),
            )
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(title_color)),
            );
        frame.render_widget(title, chunks[0]);

        // Status block - Purple when enhanced and active
        let status_color = if enhanced_mode && info.active {
            Color::Magenta
        } else if info.active {
            Color::Green
        } else {
            Color::Red
        };
        let status_text = if info.active {
            "● Protected"
        } else {
            "○ Inactive"
        };

        let uptime = format_duration(info.uptime);
        let status = vec![
            Line::from(vec![
                Span::raw("Status: "),
                Span::styled(status_text, Style::default().fg(status_color)),
            ]),
            Line::from(format!("Uptime: {uptime}")),
            Line::from(format!("Total Threats Blocked: {}", info.threats_blocked)),
        ];

        let border_color = if enhanced_mode {
            Color::Magenta
        } else {
            Color::Reset
        };
        let status_widget = Paragraph::new(status).block(
            Block::default()
                .title("Status")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );
        frame.render_widget(status_widget, chunks[1]);

        // Threat statistics
        let mut threat_items = vec![Line::from("Threats Blocked by Type:"), Line::from("")];

        // Count threats by category
        let unicode_count: u64 = threat_stats
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

        let injection_count: u64 = threat_stats
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

        let traversal_count = threat_stats
            .get(&ThreatType::PathTraversal)
            .copied()
            .unwrap_or(0);

        let mcp_count: u64 = threat_stats
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

        threat_items.push(Line::from(format!(
            "├─ Unicode Attacks:     {unicode_count}"
        )));
        threat_items.push(Line::from(format!(
            "├─ Injection Attempts:  {injection_count}"
        )));
        threat_items.push(Line::from(format!(
            "├─ Path Traversal:      {traversal_count}"
        )));
        threat_items.push(Line::from(format!("├─ MCP Threats:         {mcp_count}")));
        threat_items.push(Line::from(format!(
            "└─ Total:              {}",
            info.threats_blocked
        )));

        let threats_widget = Paragraph::new(threat_items).block(
            Block::default()
                .title("Threat Statistics")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );
        frame.render_widget(threats_widget, chunks[2]);

        // Performance metrics
        let mut perf_items = vec![
            Line::from("Performance:"),
            Line::from(""),
            Line::from(format!(
                "├─ Threat Rate: {:.1} /min",
                info.recent_threat_rate
            )),
        ];

        if enhanced_mode {
            perf_items.push(
                Line::from("├─ Pattern Recognition: Active")
                    .style(Style::default().fg(Color::Magenta)),
            );
            perf_items.push(
                Line::from("├─ Advanced Analytics: Enabled")
                    .style(Style::default().fg(Color::Magenta)),
            );
        }

        perf_items.push(Line::from(format!(
            "└─ Shield Active: {}",
            if info.active { "Yes" } else { "No" }
        )));

        let perf_widget = Paragraph::new(perf_items).block(
            Block::default()
                .title("Performance")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );
        frame.render_widget(perf_widget, chunks[3]);

        // Recent threats
        if self.config.detailed_stats && chunks.len() > 4 {
            let recent_threats = self.shield.get_recent_threats(10);
            let threat_items: Vec<ListItem> = recent_threats
                .iter()
                .map(|threat| {
                    let style = match threat.severity {
                        crate::scanner::Severity::Critical => Style::default().fg(Color::Red),
                        crate::scanner::Severity::High => Style::default().fg(Color::Yellow),
                        crate::scanner::Severity::Medium => Style::default().fg(Color::Blue),
                        crate::scanner::Severity::Low => Style::default().fg(Color::Gray),
                    };

                    ListItem::new(format!(
                        "[{}] {}: {}",
                        threat.severity,
                        threat.threat_type,
                        shorten_string(&threat.description, 50)
                    ))
                    .style(style)
                })
                .collect();

            let threats_list = List::new(threat_items).block(
                Block::default()
                    .title("Recent Threats")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            );
            frame.render_widget(threats_list, chunks[4]);
        }
    }
}

/// Format duration as human-readable string
fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Shorten string to max length
fn shorten_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
