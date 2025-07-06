//! TUI dashboard for real-time CI monitoring

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

use super::{MonitorSnapshot, PipelineStatus};

/// TUI Dashboard for CI monitoring
pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Dashboard {
    /// Create a new dashboard
    pub fn new() -> Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        
        Ok(Self { terminal })
    }
    
    /// Run the dashboard
    pub async fn run(&mut self, _snapshot_rx: tokio::sync::mpsc::Receiver<MonitorSnapshot>) -> Result<()> {
        // TODO: Implement full TUI event loop
        // For now, just a placeholder
        Ok(())
    }
    
    /// Draw the dashboard
    fn draw(&mut self, f: &mut Frame, snapshot: &MonitorSnapshot) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // System metrics
                Constraint::Min(10),    // Pipeline status
                Constraint::Length(3),  // Footer
            ])
            .split(f.area());
        
        // Header
        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::raw("╔══════════════════════ "),
                Span::styled("KindlyGuard Parallel CI", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(" ══════════════════════╗"),
            ]),
            Line::from(vec![
                Span::raw("║ "),
                Span::styled("Maximizing Hardware Power", Style::default().fg(Color::Green)),
                Span::raw(format!(" | Elapsed: {} ", format_duration(snapshot.elapsed))),
                Span::raw("║"),
            ]),
        ])
        .alignment(Alignment::Center);
        f.render_widget(header, chunks[0]);
        
        // System metrics
        let metrics_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ])
            .split(chunks[1]);
        
        let cpu_gauge = Gauge::default()
            .block(Block::default().title("CPU").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Yellow))
            .percent(snapshot.system_metrics.cpu_usage as u16)
            .label(format!("{}%", snapshot.system_metrics.cpu_usage as u16));
        f.render_widget(cpu_gauge, metrics_layout[0]);
        
        let mem_gauge = Gauge::default()
            .block(Block::default().title("Memory").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Blue))
            .percent(snapshot.system_metrics.memory_usage as u16)
            .label(format!("{}%", snapshot.system_metrics.memory_usage as u16));
        f.render_widget(mem_gauge, metrics_layout[1]);
        
        let io_gauge = Gauge::default()
            .block(Block::default().title("Disk I/O").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Magenta))
            .percent(snapshot.system_metrics.disk_io as u16)
            .label(format!("{}%", snapshot.system_metrics.disk_io as u16));
        f.render_widget(io_gauge, metrics_layout[2]);
        
        // Pipeline status
        let pipeline_items: Vec<ListItem> = snapshot.pipelines.iter()
            .map(|(name, pipeline)| {
                let (icon, color) = match pipeline.status {
                    PipelineStatus::Pending => ("⏸", Color::Gray),
                    PipelineStatus::Running => ("⟳", Color::Yellow),
                    PipelineStatus::Completed => ("✓", Color::Green),
                    PipelineStatus::Failed => ("✗", Color::Red),
                };
                
                let progress_bar = create_progress_bar(pipeline.progress_percent);
                let duration = pipeline.duration
                    .map(|d| format_duration(d))
                    .unwrap_or_else(|| "—".to_string());
                
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", icon), Style::default().fg(color)),
                    Span::styled(format!("{:<15}", name), Style::default().fg(Color::White)),
                    Span::raw(format!(" {} ", progress_bar)),
                    Span::raw(format!("{:>8} ", duration)),
                    Span::styled(&pipeline.message, Style::default().fg(Color::Gray)),
                ]))
            })
            .collect();
        
        let pipelines_list = List::new(pipeline_items)
            .block(Block::default().title("Pipelines").borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(pipelines_list, chunks[2]);
        
        // Footer
        let footer = Paragraph::new(Line::from(vec![
            Span::raw("║ Press "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" to quit | "),
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::raw(" to refresh | "),
            Span::styled("Space", Style::default().fg(Color::Yellow)),
            Span::raw(" to pause ║"),
        ]))
        .alignment(Alignment::Center);
        f.render_widget(footer, chunks[3]);
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        // Restore terminal
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{}m{}s", mins, secs)
    }
}

fn create_progress_bar(percent: f32) -> String {
    let width = 20;
    let filled = ((percent / 100.0) * width as f32) as usize;
    let empty = width - filled;
    
    format!("[{}{}] {:>5.1}%",
        "█".repeat(filled),
        "░".repeat(empty),
        percent
    )
}