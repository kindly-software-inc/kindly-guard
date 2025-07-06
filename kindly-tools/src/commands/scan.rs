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

//! Scan command implementation for KindlyTools

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

use kindly_guard_server::{Config as ServerConfig, ScannerConfig, SecurityScanner, Threat};

use crate::output::{print_scan_results, OutputFormat};

/// Execute the scan command
pub async fn execute(
    path: String,
    format: String,
    recursive: bool,
    extensions: Option<String>,
    max_size_mb: u64,
    config_path: Option<String>,
) -> Result<()> {
    let start_time = Instant::now();
    let path = Path::new(&path);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    // Parse output format
    let output_format = OutputFormat::from_str(&format)?;

    // Parse extensions if provided
    let allowed_extensions: Option<Vec<String>> =
        extensions.map(|ext| ext.split(',').map(|s| s.trim().to_lowercase()).collect());

    // Create scanner with optional config file
    let scanner = if let Some(config_file) = config_path {
        // Load full configuration from file
        let server_config = ServerConfig::load_from_file(&config_file)
            .context("Failed to load configuration file")?;

        // Create scanner with config
        let mut scanner = SecurityScanner::new(server_config.scanner.clone())
            .context("Failed to create security scanner")?;

        // Set up plugins if enabled
        if server_config.plugins.enabled {
            use kindly_guard_server::component_selector::ComponentManager;
            use std::sync::Arc;

            // Create component manager to get plugin manager
            let component_manager = Arc::new(
                ComponentManager::new(&server_config)
                    .context("Failed to create component manager")?,
            );

            scanner.set_plugin_manager(component_manager.plugin_manager().clone());
        }

        scanner
    } else {
        // Use default config
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(true),
            crypto_detection: true,
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            max_content_size: 5 * 1024 * 1024,      // 5MB default
            max_input_size: Some(10 * 1024 * 1024), // 10MB default
            allow_text_control_chars: false,
        };

        SecurityScanner::new(config).context("Failed to create security scanner")?
    };

    // Collect files to scan
    let files_to_scan = collect_files(path, recursive, &allowed_extensions, max_size_mb)?;

    if files_to_scan.is_empty() {
        println!("{}", "No files found to scan".yellow());
        return Ok(());
    }

    // Create progress bar
    let progress = if output_format == OutputFormat::Json {
        None
    } else {
        let pb = ProgressBar::new(files_to_scan.len() as u64);
        // Use unwrap_or_else to fall back to default style if template parsing fails
        let style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-");
        pb.set_style(style);
        Some(pb)
    };

    // Scan files
    let mut all_results = Vec::new();
    let mut total_threats = 0;

    for file_path in &files_to_scan {
        if let Some(pb) = &progress {
            pb.set_message(format!(
                "Scanning {}",
                file_path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        match scan_file(&scanner, file_path).await {
            Ok(threats) => {
                if !threats.is_empty() {
                    total_threats += threats.len();
                    all_results.push((file_path.clone(), threats));
                }
            },
            Err(e) => {
                tracing::warn!("Failed to scan {}: {}", file_path.display(), e);
            },
        }

        if let Some(pb) = &progress {
            pb.inc(1);
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("Scan complete");
    }

    // Print results
    let duration = start_time.elapsed();
    print_scan_results(
        &all_results,
        files_to_scan.len(),
        total_threats,
        duration,
        output_format,
    );

    Ok(())
}

async fn scan_file(scanner: &SecurityScanner, path: &Path) -> Result<Vec<Threat>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read file")?;

    scanner
        .scan_text(&content)
        .context("Failed to scan file content")
}

fn collect_files(
    path: &Path,
    recursive: bool,
    allowed_extensions: &Option<Vec<String>>,
    max_size_mb: u64,
) -> Result<Vec<PathBuf>> {
    let max_size = max_size_mb * 1024 * 1024;
    let mut files = Vec::new();

    if path.is_file() {
        // Check file size
        let metadata = path.metadata()?;
        if metadata.len() <= max_size {
            files.push(path.to_path_buf());
        } else {
            tracing::warn!(
                "Skipping large file: {} ({} MB)",
                path.display(),
                metadata.len() / 1024 / 1024
            );
        }
    } else if path.is_dir() {
        let walker = if recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        for entry in walker {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                // Check extension
                if let Some(ref extensions) = allowed_extensions {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if !extensions.contains(&ext_str) {
                            continue;
                        }
                    } else {
                        continue; // Skip files without extension
                    }
                }

                // Check file size
                let metadata = entry.metadata()?;
                if metadata.len() <= max_size {
                    files.push(path.to_path_buf());
                } else {
                    tracing::debug!(
                        "Skipping large file: {} ({} MB)",
                        path.display(),
                        metadata.len() / 1024 / 1024
                    );
                }
            }
        }
    }

    Ok(files)
}
