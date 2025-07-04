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

//! Performance demonstration application
//!
//! Shows real-time performance metrics while scanning files and content.

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use kindly_guard_server::scanner::{SecurityScanner, ThreatType};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Sparkline},
    Frame, Terminal,
};
use std::{
    collections::VecDeque,
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{fs, sync::Mutex, time::sleep};

const SAMPLE_DATA_DIR: &str = "test_data";
const UPDATE_INTERVAL: Duration = Duration::from_millis(100);
const SPARKLINE_WINDOW: usize = 50;

#[derive(Default)]
struct PerformanceMetrics {
    bytes_scanned: AtomicU64,
    files_scanned: AtomicUsize,
    threats_detected: AtomicUsize,
    scan_time_ns: AtomicU64,
    throughput_history: Arc<Mutex<VecDeque<f64>>>,
    latency_history: Arc<Mutex<VecDeque<f64>>>,
    threat_types: Arc<Mutex<std::collections::HashMap<String, usize>>>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            throughput_history: Arc::new(Mutex::new(VecDeque::with_capacity(SPARKLINE_WINDOW))),
            latency_history: Arc::new(Mutex::new(VecDeque::with_capacity(SPARKLINE_WINDOW))),
            threat_types: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ..Default::default()
        }
    }
    
    fn record_scan(&self, bytes: usize, duration: Duration, threats: usize) {
        self.bytes_scanned.fetch_add(bytes as u64, Ordering::Relaxed);
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
        self.threats_detected.fetch_add(threats, Ordering::Relaxed);
        self.scan_time_ns.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }
    
    async fn update_throughput(&self, mbps: f64) {
        let mut history = self.throughput_history.lock().await;
        if history.len() >= SPARKLINE_WINDOW {
            history.pop_front();
        }
        history.push_back(mbps);
    }
    
    async fn update_latency(&self, ms: f64) {
        let mut history = self.latency_history.lock().await;
        if history.len() >= SPARKLINE_WINDOW {
            history.pop_front();
        }
        history.push_back(ms);
    }
    
    async fn record_threat_type(&self, threat_type: &str) {
        let mut types = self.threat_types.lock().await;
        *types.entry(threat_type.to_string()).or_insert(0) += 1;
    }
    
    fn get_average_throughput(&self) -> f64 {
        let bytes = self.bytes_scanned.load(Ordering::Relaxed) as f64;
        let time_s = self.scan_time_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
        if time_s > 0.0 {
            (bytes / 1_024_576.0) / time_s // MB/s
        } else {
            0.0
        }
    }
    
    fn get_average_latency(&self) -> f64 {
        let files = self.files_scanned.load(Ordering::Relaxed) as f64;
        let time_ms = self.scan_time_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        if files > 0.0 {
            time_ms / files
        } else {
            0.0
        }
    }
}

/// Generate sample data files for testing
async fn generate_sample_data() -> Result<()> {
    fs::create_dir_all(SAMPLE_DATA_DIR).await?;
    
    // Clean text file
    fs::write(
        format!("{}/clean.txt", SAMPLE_DATA_DIR),
        "This is a clean text file with no security threats. ".repeat(1000)
    ).await?;
    
    // File with unicode threats
    fs::write(
        format!("{}/unicode_threats.txt", SAMPLE_DATA_DIR),
        format!("Hello\u{200B}World\nAdmin\u{202E}txt.exe\n{}", "Normal text ".repeat(500))
    ).await?;
    
    // File with injection patterns
    fs::write(
        format!("{}/injections.log", SAMPLE_DATA_DIR),
        r#"[2025-01-01] User query: SELECT * FROM users
[2025-01-01] Error: '; DROP TABLE users; --
[2025-01-01] Path requested: ../../../etc/passwd
Normal log entry"#.repeat(100)
    ).await?;
    
    // HTML file with XSS
    fs::write(
        format!("{}/webpage.html", SAMPLE_DATA_DIR),
        r#"<html>
<body>
<h1>Welcome</h1>
<script>alert('xss')</script>
<img src=x onerror='alert(1)'>
<p>Normal content</p>
</body>
</html>"#.repeat(50)
    ).await?;
    
    // JSON API data
    fs::write(
        format!("{}/api_data.json", SAMPLE_DATA_DIR),
        serde_json::to_string_pretty(&serde_json::json!({
            "users": [
                {"name": "Alice", "bio": "Software developer"},
                {"name": "Bob\u{200C}", "bio": "'; DELETE FROM users; --"},
                {"name": "Charlie", "bio": "<script>alert(1)</script>"}
            ]
        }))?
    ).await?;
    
    // Large mixed content file
    let mut large_content = String::new();
    for i in 0..1000 {
        large_content.push_str(&format!("Line {}: ", i));
        match i % 10 {
            0 => large_content.push_str("Clean content here\n"),
            3 => large_content.push_str("Invisible\u{200B}character\n"),
            5 => large_content.push_str("SQL: ' OR '1'='1\n"),
            7 => large_content.push_str("<img src=x onerror=alert(1)>\n"),
            _ => large_content.push_str("Normal text content\n"),
        }
    }
    fs::write(format!("{}/large_mixed.txt", SAMPLE_DATA_DIR), large_content).await?;
    
    Ok(())
}

/// Scan files continuously
async fn scanner_loop(
    scanner: Arc<SecurityScanner>,
    metrics: Arc<PerformanceMetrics>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let files = vec![
        format!("{}/clean.txt", SAMPLE_DATA_DIR),
        format!("{}/unicode_threats.txt", SAMPLE_DATA_DIR),
        format!("{}/injections.log", SAMPLE_DATA_DIR),
        format!("{}/webpage.html", SAMPLE_DATA_DIR),
        format!("{}/api_data.json", SAMPLE_DATA_DIR),
        format!("{}/large_mixed.txt", SAMPLE_DATA_DIR),
    ];
    
    while running.load(Ordering::Relaxed) {
        for file_path in &files {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            
            if let Ok(content) = fs::read_to_string(file_path).await {
                let start = Instant::now();
                let threats = scanner.scan_text(&content);
                let duration = start.elapsed();
                
                metrics.record_scan(content.len(), duration, threats.len());
                
                // Record threat types
                for threat in &threats {
                    let threat_type_str = match &threat.threat_type {
                        ThreatType::UnicodeInvisible => "Unicode Invisible",
                        ThreatType::UnicodeBiDi => "Unicode BiDi",
                        ThreatType::UnicodeHomograph => "Unicode Homograph",
                        ThreatType::SqlInjection => "SQL Injection",
                        ThreatType::CommandInjection => "Command Injection",
                        ThreatType::PathTraversal => "Path Traversal",
                        ThreatType::XssScript => "XSS Script",
                        ThreatType::XssEventHandler => "XSS Event",
                        ThreatType::PromptInjection => "Prompt Injection",
                        _ => "Other",
                    };
                    metrics.record_threat_type(threat_type_str).await;
                }
                
                // Update real-time metrics
                let mbps = (content.len() as f64 / 1_024_576.0) / duration.as_secs_f64();
                let latency_ms = duration.as_secs_f64() * 1000.0;
                
                metrics.update_throughput(mbps).await;
                metrics.update_latency(latency_ms).await;
                
                // Small delay to make the demo more visible
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
    
    Ok(())
}

/// Draw the UI
async fn draw_ui(frame: &mut Frame, metrics: &PerformanceMetrics) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(5),
        ])
        .split(frame.area());
    
    // Title
    let title = Paragraph::new("KindlyGuard Performance Demo - Press 'q' to quit")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);
    
    // Main metrics
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25); 4])
        .split(chunks[1]);
    
    // Files scanned
    let files = metrics.files_scanned.load(Ordering::Relaxed);
    let files_widget = Paragraph::new(vec![
        Line::from(Span::styled("Files Scanned", Style::default().fg(Color::Yellow))),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            format!("{}", files),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);
    frame.render_widget(files_widget, main_chunks[0]);
    
    // Data processed
    let mb_scanned = metrics.bytes_scanned.load(Ordering::Relaxed) as f64 / 1_024_576.0;
    let data_widget = Paragraph::new(vec![
        Line::from(Span::styled("Data Processed", Style::default().fg(Color::Yellow))),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            format!("{:.2} MB", mb_scanned),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);
    frame.render_widget(data_widget, main_chunks[1]);
    
    // Threats detected
    let threats = metrics.threats_detected.load(Ordering::Relaxed);
    let threat_color = if threats > 0 { Color::Red } else { Color::Green };
    let threats_widget = Paragraph::new(vec![
        Line::from(Span::styled("Threats Detected", Style::default().fg(Color::Yellow))),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            format!("{}", threats),
            Style::default().fg(threat_color).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);
    frame.render_widget(threats_widget, main_chunks[2]);
    
    // Average metrics
    let avg_throughput = metrics.get_average_throughput();
    let avg_latency = metrics.get_average_latency();
    let avg_widget = Paragraph::new(vec![
        Line::from(Span::styled("Performance", Style::default().fg(Color::Yellow))),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::raw("Throughput: "),
            Span::styled(
                format!("{:.2} MB/s", avg_throughput),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::raw("Latency: "),
            Span::styled(
                format!("{:.2} ms", avg_latency),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);
    frame.render_widget(avg_widget, main_chunks[3]);
    
    // Performance graphs
    let graph_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);
    
    // Throughput sparkline
    let throughput_data: Vec<u64> = metrics
        .throughput_history
        .lock()
        .await
        .iter()
        .map(|&v| (v * 10.0) as u64)
        .collect();
    
    let throughput_sparkline = Sparkline::default()
        .block(
            Block::default()
                .title("Throughput (MB/s)")
                .borders(Borders::ALL),
        )
        .data(&throughput_data)
        .style(Style::default().fg(Color::Green));
    frame.render_widget(throughput_sparkline, graph_chunks[0]);
    
    // Latency sparkline
    let latency_data: Vec<u64> = metrics
        .latency_history
        .lock()
        .await
        .iter()
        .map(|&v| v as u64)
        .collect();
    
    let latency_sparkline = Sparkline::default()
        .block(
            Block::default()
                .title("Latency (ms)")
                .borders(Borders::ALL),
        )
        .data(&latency_data)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(latency_sparkline, graph_chunks[1]);
    
    // Threat breakdown
    let threat_types = metrics.threat_types.lock().await;
    let mut threat_lines = vec![
        Line::from(Span::styled(
            "Threat Type Breakdown:",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    
    for (threat_type, count) in threat_types.iter() {
        threat_lines.push(Line::from(vec![
            Span::raw(format!("{:<20} ", threat_type)),
            Span::styled(
                format!("{:>5}", count),
                Style::default().fg(Color::Red),
            ),
        ]));
    }
    
    let threat_breakdown = Paragraph::new(threat_lines)
        .block(Block::default().title("Threat Analysis").borders(Borders::ALL));
    frame.render_widget(threat_breakdown, chunks[3]);
}

/// Main UI loop
async fn run_ui(metrics: Arc<PerformanceMetrics>, running: Arc<AtomicBool>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    let mut last_draw = Instant::now();
    
    loop {
        // Draw UI at regular intervals
        if last_draw.elapsed() >= UPDATE_INTERVAL {
            terminal.draw(|f| {
                tokio::runtime::Handle::current().block_on(async {
                    draw_ui(f, &metrics).await;
                });
            })?;
            last_draw = Instant::now();
        }
        
        // Check for quit
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Generate sample data
    println!("Generating sample data...");
    generate_sample_data().await?;
    
    // Initialize scanner and metrics
    let scanner = Arc::new(SecurityScanner::new(Default::default())?);
    let metrics = Arc::new(PerformanceMetrics::new());
    let running = Arc::new(AtomicBool::new(true));
    
    // Spawn scanner task
    let scanner_task = {
        let scanner = scanner.clone();
        let metrics = metrics.clone();
        let running = running.clone();
        tokio::spawn(async move {
            if let Err(e) = scanner_loop(scanner, metrics, running).await {
                eprintln!("Scanner error: {}", e);
            }
        })
    };
    
    // Run UI
    run_ui(metrics.clone(), running.clone()).await?;
    
    // Wait for scanner to finish
    scanner_task.await?;
    
    // Print final statistics
    println!("\n=== Final Performance Statistics ===");
    println!("Files scanned: {}", metrics.files_scanned.load(Ordering::Relaxed));
    println!("Data processed: {:.2} MB", 
        metrics.bytes_scanned.load(Ordering::Relaxed) as f64 / 1_024_576.0);
    println!("Threats detected: {}", metrics.threats_detected.load(Ordering::Relaxed));
    println!("Average throughput: {:.2} MB/s", metrics.get_average_throughput());
    println!("Average latency: {:.2} ms/file", metrics.get_average_latency());
    
    println!("\nThreat breakdown:");
    let threat_types = metrics.threat_types.lock().await;
    for (threat_type, count) in threat_types.iter() {
        println!("  {}: {}", threat_type, count);
    }
    
    // Cleanup
    fs::remove_dir_all(SAMPLE_DATA_DIR).await.ok();
    
    Ok(())
}