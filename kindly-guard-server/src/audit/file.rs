//! File-based audit logger implementation with rotation support

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::{
    AuditConfig, AuditEvent, AuditEventId, AuditFilter, AuditLogger, AuditLoggerFactory,
    AuditSeverity, AuditStats, ExportFormat, IntegrityReport, RotationStrategy,
};

/// File-based audit logger with rotation
pub struct FileAuditLogger {
    config: AuditConfig,
    writer: Arc<Mutex<BufWriter<File>>>,
    file_path: PathBuf,
    current_size: Arc<Mutex<u64>>,
    rotation_count: Arc<Mutex<u32>>,
    last_rotation: Arc<Mutex<DateTime<Utc>>>,
}

impl FileAuditLogger {
    /// Create a new file-based audit logger
    pub fn new(config: AuditConfig) -> Result<Self> {
        let file_path = PathBuf::from(
            config
                .file_path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("File path required for file backend"))?,
        );

        // Create directory if needed
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        let current_size = file.metadata()?.len();

        Ok(Self {
            config,
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
            file_path,
            current_size: Arc::new(Mutex::new(current_size)),
            rotation_count: Arc::new(Mutex::new(0)),
            last_rotation: Arc::new(Mutex::new(Utc::now())),
        })
    }

    /// Check if rotation is needed
    async fn should_rotate(&self) -> Result<bool> {
        if let Some(rotation) = &self.config.rotation {
            let current_size = *self.current_size.lock().await;
            let last_rotation = *self.last_rotation.lock().await;
            let age_hours = (Utc::now() - last_rotation).num_hours() as u64;

            match rotation.strategy {
                RotationStrategy::Size => Ok(current_size >= rotation.max_size_mb * 1024 * 1024),
                RotationStrategy::Time => Ok(age_hours >= rotation.max_age_hours),
                RotationStrategy::Both => Ok(current_size >= rotation.max_size_mb * 1024 * 1024
                    || age_hours >= rotation.max_age_hours),
            }
        } else {
            Ok(false)
        }
    }

    /// Perform log rotation
    async fn rotate(&self) -> Result<()> {
        let mut rotation_count = self.rotation_count.lock().await;
        *rotation_count += 1;

        let rotation_path = self
            .file_path
            .with_extension(format!("log.{rotation_count}"));

        // Close current file and rename
        {
            let mut writer = self.writer.lock().await;
            writer.flush()?;
        }

        std::fs::rename(&self.file_path, &rotation_path)?;
        info!("Rotated audit log to {:?}", rotation_path);

        // Create new file
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        {
            let mut writer = self.writer.lock().await;
            *writer = BufWriter::new(new_file);
        }

        // Reset counters
        *self.current_size.lock().await = 0;
        *self.last_rotation.lock().await = Utc::now();

        // Clean up old files
        if let Some(rotation) = &self.config.rotation {
            self.cleanup_old_files(rotation.max_backups).await?;
        }

        Ok(())
    }

    /// Clean up old rotation files
    async fn cleanup_old_files(&self, max_backups: u32) -> Result<()> {
        let parent = self
            .file_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("No parent directory"))?;

        let base_name = self
            .file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;

        let mut rotation_files: Vec<(PathBuf, u32)> = Vec::new();

        // Find all rotation files
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.starts_with(base_name) && name.contains(".log.") {
                    if let Some(num_str) = name.split(".log.").nth(1) {
                        if let Ok(num) = num_str.parse::<u32>() {
                            rotation_files.push((path, num));
                        }
                    }
                }
            }
        }

        // Sort by rotation number (newest first)
        rotation_files.sort_by(|a, b| b.1.cmp(&a.1));

        // Remove old files
        for (path, _) in rotation_files.iter().skip(max_backups as usize) {
            match std::fs::remove_file(path) {
                Ok(()) => debug!("Removed old audit log: {:?}", path),
                Err(e) => warn!("Failed to remove old audit log {:?}: {}", path, e),
            }
        }

        Ok(())
    }

    /// Write event to file
    async fn write_event(&self, event: &AuditEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        let line = format!("{json}\n");
        let bytes = line.as_bytes();

        {
            let mut writer = self.writer.lock().await;
            writer.write_all(bytes)?;
            writer.flush()?;
        }

        let mut size = self.current_size.lock().await;
        *size += bytes.len() as u64;

        Ok(())
    }
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log(&self, event: AuditEvent) -> Result<AuditEventId> {
        let id = event.id.clone();

        // Check rotation
        if self.should_rotate().await? {
            self.rotate().await?;
        }

        // Write event
        self.write_event(&event).await?;

        Ok(id)
    }

    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>> {
        let mut ids = Vec::with_capacity(events.len());

        // Check rotation before batch
        if self.should_rotate().await? {
            self.rotate().await?;
        }

        // Write all events
        for event in events {
            ids.push(event.id.clone());
            self.write_event(&event).await?;
        }

        Ok(ids)
    }

    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        // Read from current file and rotated files
        let mut all_events = Vec::new();
        let mut files_to_read = vec![self.file_path.clone()];

        // Add rotated files
        if let Some(parent) = self.file_path.parent() {
            let base_name = self
                .file_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("audit");

            for entry in std::fs::read_dir(parent)? {
                let entry = entry?;
                let path = entry.path();

                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with(base_name) && name.contains(".log.") {
                        files_to_read.push(path);
                    }
                }
            }
        }

        // Read events from all files
        for file_path in files_to_read {
            if let Ok(file) = File::open(&file_path) {
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    if let Ok(line) = line {
                        if let Ok(event) = serde_json::from_str::<AuditEvent>(&line) {
                            all_events.push(event);
                        }
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply filters
        let mut results = Vec::new();
        let mut checked = 0;

        for event in all_events {
            if let Some(limit) = filter.limit {
                if results.len() >= limit {
                    break;
                }
            }

            if let Some(offset) = filter.offset {
                if checked < offset {
                    checked += 1;
                    continue;
                }
            }

            // Apply same filters as memory implementation
            if let Some(min_severity) = &filter.min_severity {
                // Info=0, Warning=1, Error=2, Critical=3 - skip if less severe than minimum
                if (event.severity as u8) < (*min_severity as u8) {
                    continue;
                }
            }

            if let Some(pattern) = &filter.event_type_pattern {
                let type_str = format!("{:?}", event.event_type);
                if !type_str.contains(pattern) {
                    continue;
                }
            }

            if let Some(client_id) = &filter.client_id {
                if event.client_id.as_ref() != Some(client_id) {
                    continue;
                }
            }

            if let Some(ip) = &filter.ip_address {
                if event.ip_address.as_ref() != Some(ip) {
                    continue;
                }
            }

            if let Some(start) = filter.start_time {
                if event.timestamp < start {
                    continue;
                }
            }

            if let Some(end) = filter.end_time {
                if event.timestamp > end {
                    continue;
                }
            }

            if !filter.tags.is_empty() {
                let has_tag = filter.tags.iter().any(|tag| event.tags.contains(tag));
                if !has_tag {
                    continue;
                }
            }

            results.push(event);
            checked += 1;
        }

        Ok(results)
    }

    async fn get_event(&self, id: &AuditEventId) -> Result<Option<AuditEvent>> {
        // Simple linear search through files
        let filter = AuditFilter {
            limit: Some(1),
            ..Default::default()
        };

        let events = self.query(filter).await?;
        Ok(events.into_iter().find(|e| &e.id == id))
    }

    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64> {
        // This implementation doesn't support deletion
        // Would need to rewrite files
        warn!("File audit logger doesn't support deletion; use retention policies instead");
        Ok(0)
    }

    async fn get_stats(&self) -> Result<AuditStats> {
        let events = self.query(AuditFilter::default()).await?;

        let mut stats = AuditStats {
            total_events: events.len() as u64,
            ..Default::default()
        };

        for event in &events {
            let severity_key = format!("{:?}", event.severity);
            *stats.events_by_severity.entry(severity_key).or_insert(0) += 1;

            let type_key = format!("{:?}", event.event_type);
            *stats.events_by_type.entry(type_key).or_insert(0) += 1;
        }

        if let Some(oldest) = events.last() {
            stats.oldest_event = Some(oldest.timestamp);
        }

        if let Some(newest) = events.first() {
            stats.newest_event = Some(newest.timestamp);
        }

        stats.storage_size_bytes = *self.current_size.lock().await;

        Ok(stats)
    }

    async fn export(&self, filter: AuditFilter, format: ExportFormat) -> Result<Vec<u8>> {
        // Use same implementation as memory logger
        let events = self.query(filter).await?;

        match format {
            ExportFormat::Json => {
                let json = serde_json::to_string_pretty(&events)?;
                Ok(json.into_bytes())
            }
            ExportFormat::Csv => {
                let mut wtr = csv::Writer::from_writer(vec![]);

                wtr.write_record([
                    "id",
                    "timestamp",
                    "event_type",
                    "severity",
                    "client_id",
                    "ip_address",
                    "user_agent",
                    "tags",
                ])?;

                for event in events {
                    wtr.write_record([
                        &event.id.0,
                        &event.timestamp.to_rfc3339(),
                        &format!("{:?}", event.event_type),
                        &format!("{:?}", event.severity),
                        &event.client_id.unwrap_or_default(),
                        &event.ip_address.unwrap_or_default(),
                        &event.user_agent.unwrap_or_default(),
                        &event.tags.join(","),
                    ])?;
                }

                Ok(wtr.into_inner()?)
            }
            ExportFormat::Syslog => {
                // Same as memory implementation
                let mut output = Vec::new();

                for event in events {
                    let severity = match event.severity {
                        AuditSeverity::Critical => 2,
                        AuditSeverity::Error => 3,
                        AuditSeverity::Warning => 4,
                        AuditSeverity::Info => 6,
                    };

                    let msg = format!(
                        "<{}>{} kindly-guard[{}]: event_type={:?} client={} ip={}\n",
                        16 * 8 + severity,
                        event.timestamp.to_rfc3339(),
                        std::process::id(),
                        event.event_type,
                        event.client_id.as_ref().unwrap_or(&"none".to_string()),
                        event.ip_address.as_ref().unwrap_or(&"none".to_string())
                    );

                    output.extend_from_slice(msg.as_bytes());
                }

                Ok(output)
            }
            ExportFormat::Cef => {
                // Same as memory implementation
                let mut output = Vec::new();

                for event in events {
                    let severity = match event.severity {
                        AuditSeverity::Info => 0,
                        AuditSeverity::Warning => 3,
                        AuditSeverity::Error => 7,
                        AuditSeverity::Critical => 10,
                    };

                    let msg = format!(
                        "CEF:0|KindlyGuard|SecurityServer|1.0|{:?}|{:?}|{}|client={} ip={}\n",
                        event.event_type,
                        event.event_type,
                        severity,
                        event.client_id.as_ref().unwrap_or(&"none".to_string()),
                        event.ip_address.as_ref().unwrap_or(&"none".to_string())
                    );

                    output.extend_from_slice(msg.as_bytes());
                }

                Ok(output)
            }
        }
    }

    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut issues = Vec::new();
        let mut events_checked = 0;

        // Check current file
        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);

            for (line_num, line) in reader.lines().enumerate() {
                match line {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<AuditEvent>(&line) {
                            Ok(_) => events_checked += 1,
                            Err(e) => {
                                issues.push(format!(
                                    "Line {} in {:?}: Invalid JSON: {}",
                                    line_num + 1,
                                    self.file_path.file_name(),
                                    e
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        issues.push(format!(
                            "Line {} in {:?}: Read error: {}",
                            line_num + 1,
                            self.file_path.file_name(),
                            e
                        ));
                    }
                }
            }
        }

        Ok(IntegrityReport {
            intact: issues.is_empty(),
            events_checked,
            issues,
            verified_at: Utc::now(),
        })
    }
}
