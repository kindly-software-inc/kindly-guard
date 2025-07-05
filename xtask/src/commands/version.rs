use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use regex::Regex;
use semver::Version;
use std::collections::HashMap;
use std::path::Path;

use crate::{config::VersionLocations, utils::Context};

#[derive(Args)]
pub struct VersionCmd {
    /// New version to set
    #[arg(value_name = "VERSION")]
    version: Option<String>,

    /// Check version consistency across files
    #[arg(long)]
    check: bool,

    /// Show current versions
    #[arg(long)]
    show: bool,

    /// Update changelog with new version
    #[arg(long)]
    changelog: bool,

    /// Commit version changes
    #[arg(long)]
    commit: bool,
}

pub async fn run(cmd: VersionCmd, ctx: Context) -> Result<()> {
    if cmd.show {
        show_versions(&ctx)?;
    } else if cmd.check {
        check_version_consistency(&ctx)?;
    } else if let Some(version_str) = cmd.version {
        let version = Version::parse(&version_str)
            .context("Invalid version format")?;
        
        update_all_versions(&ctx, &version)?;
        
        if cmd.changelog {
            update_changelog(&ctx, &version)?;
        }
        
        if cmd.commit && !ctx.dry_run {
            commit_version_changes(&ctx, &version)?;
        }
        
        ctx.success(&format!("Updated version to {}", version));
    } else {
        // Default: show current versions
        show_versions(&ctx)?;
    }

    Ok(())
}

pub fn update_all_versions(ctx: &Context, version: &Version) -> Result<()> {
    let locations = load_version_locations()?;
    let version_str = version.to_string();
    
    ctx.info(&format!("Updating version to {} in {} files", 
        version_str.bold(), 
        locations.files.len()
    ));

    for file in &locations.files {
        update_version_in_file(&file.path, &file.pattern, &file.replacement, &version_str, ctx)?;
    }

    Ok(())
}

fn load_version_locations() -> Result<VersionLocations> {
    let config_path = "version-locations.json";
    
    if Path::new(config_path).exists() {
        let content = std::fs::read_to_string(config_path)
            .context("Failed to read version locations")?;
        
        serde_json::from_str(&content)
            .context("Failed to parse version locations")
    } else {
        // Use default locations
        Ok(VersionLocations::default())
    }
}

fn update_version_in_file(
    path: &str,
    pattern: &str,
    replacement: &str,
    version: &str,
    ctx: &Context,
) -> Result<()> {
    let file_path = crate::utils::workspace_root()?.join(path);
    
    if !file_path.exists() {
        ctx.warn(&format!("File not found: {}", path));
        return Ok(());
    }

    let content = std::fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read {}", path))?;

    let regex = Regex::new(pattern)
        .with_context(|| format!("Invalid regex pattern: {}", pattern))?;

    let new_content = if replacement.contains("{VERSION}") {
        let replacement_str = replacement.replace("{VERSION}", version);
        regex.replace_all(&content, replacement_str.as_str()).to_string()
    } else {
        regex.replace_all(&content, replacement).to_string()
    };

    if content != new_content {
        if ctx.dry_run {
            ctx.info(&format!("[dry-run] Would update {}", path));
        } else {
            std::fs::write(&file_path, new_content)
                .with_context(|| format!("Failed to write {}", path))?;
            ctx.debug(&format!("Updated {}", path));
        }
    }

    Ok(())
}

fn show_versions(ctx: &Context) -> Result<()> {
    ctx.info("Current versions:");
    
    let versions = collect_versions()?;
    
    // Group by version
    let mut version_groups: HashMap<String, Vec<String>> = HashMap::new();
    for (file, version) in versions {
        version_groups.entry(version).or_default().push(file);
    }

    // Display grouped versions
    for (version, files) in version_groups {
        println!("\n  {} {}", version.green().bold(), format!("({} files)", files.len()).dimmed());
        for file in files {
            println!("    - {}", file);
        }
    }

    Ok(())
}

pub fn check_version_consistency(ctx: &Context) -> Result<()> {
    ctx.info("Checking version consistency...");
    
    let versions = collect_versions()?;
    
    // Check if all versions are the same
    let unique_versions: std::collections::HashSet<_> = versions.values().collect();
    
    if unique_versions.len() == 1 {
        let version = unique_versions.iter().next().unwrap();
        ctx.success(&format!("All files have consistent version: {}", version.green()));
    } else {
        ctx.error("Version mismatch detected!");
        
        // Group files by version
        let mut version_groups: HashMap<String, Vec<String>> = HashMap::new();
        for (file, version) in &versions {
            version_groups.entry(version.clone()).or_default().push(file.clone());
        }
        
        // Show mismatches
        for (version, files) in version_groups {
            println!("\n  Version {}: {}", version.yellow(), files.len());
            for file in files {
                println!("    - {}", file);
            }
        }
        
        anyhow::bail!("Version inconsistency found");
    }

    Ok(())
}

fn collect_versions() -> Result<HashMap<String, String>> {
    let mut versions = HashMap::new();
    
    // Check Cargo.toml files
    let cargo_files = [
        "Cargo.toml",
        "kindly-guard-server/Cargo.toml",
        "kindly-guard-cli/Cargo.toml",
        "kindly-guard-shield/Cargo.toml",
    ];

    for cargo_file in &cargo_files {
        if let Ok(version) = get_cargo_version(cargo_file) {
            versions.insert(cargo_file.to_string(), version);
        }
    }

    // Check package.json
    if let Ok(version) = get_package_json_version("package.json") {
        versions.insert("package.json".to_string(), version);
    }

    Ok(versions)
}

fn get_cargo_version(path: &str) -> Result<String> {
    let file_path = crate::utils::workspace_root()?.join(path);
    
    if !file_path.exists() {
        // Skip if file doesn't exist
        return Err(anyhow::anyhow!("File not found: {}", path));
    }

    let content = std::fs::read_to_string(&file_path)?;
    let manifest: toml::Value = toml::from_str(&content)?;
    
    // Handle both workspace and package manifests
    if let Some(version) = manifest.get("package").and_then(|p| p.get("version")).and_then(|v| v.as_str()) {
        Ok(version.to_string())
    } else if let Some(version) = manifest.get("workspace").and_then(|w| w.get("package")).and_then(|p| p.get("version")).and_then(|v| v.as_str()) {
        Ok(version.to_string())
    } else {
        Err(anyhow::anyhow!("No version found in {}", path))
    }
}

fn get_package_json_version(path: &str) -> Result<String> {
    let file_path = crate::utils::workspace_root()?.join(path);
    
    if !file_path.exists() {
        anyhow::bail!("File not found: {}", path);
    }

    let content = std::fs::read_to_string(&file_path)?;
    let package: serde_json::Value = serde_json::from_str(&content)?;
    
    package["version"]
        .as_str()
        .map(|s| s.to_string())
        .context("No version found in package.json")
}

fn update_changelog(ctx: &Context, version: &Version) -> Result<()> {
    let changelog_path = crate::utils::workspace_root()?.join("CHANGELOG.md");
    
    if !changelog_path.exists() {
        ctx.warn("CHANGELOG.md not found");
        return Ok(());
    }

    let content = std::fs::read_to_string(&changelog_path)?;
    
    // Check if version already exists
    let version_heading = format!("## [{}]", version);
    if content.contains(&version_heading) {
        ctx.info("Version already in CHANGELOG.md");
        return Ok(());
    }

    // Find the insertion point (after "# Changelog" or at the beginning)
    let insertion_point = if let Some(pos) = content.find("## [") {
        pos
    } else if let Some(pos) = content.find("# Changelog") {
        content[pos..].find('\n').map(|n| pos + n + 1).unwrap_or(content.len())
    } else {
        0
    };

    // Create new version section
    let date = chrono::Local::now().format("%Y-%m-%d");
    let new_section = format!(
        "\n## [{}] - {}\n\n### Added\n\n### Changed\n\n### Fixed\n\n### Security\n\n",
        version, date
    );

    // Insert new section
    let mut new_content = String::new();
    new_content.push_str(&content[..insertion_point]);
    new_content.push_str(&new_section);
    new_content.push_str(&content[insertion_point..]);

    if ctx.dry_run {
        ctx.info("[dry-run] Would update CHANGELOG.md");
    } else {
        std::fs::write(&changelog_path, new_content)?;
        ctx.success("Updated CHANGELOG.md");
    }

    Ok(())
}

fn commit_version_changes(ctx: &Context, version: &Version) -> Result<()> {
    ctx.info("Committing version changes...");
    
    // Stage all version files
    ctx.run_command("git", &["add", "Cargo.toml", "*/Cargo.toml", "package.json", "CHANGELOG.md"])?;
    
    // Create commit
    let commit_message = format!("chore: Bump version to {}", version);
    ctx.run_command("git", &["commit", "-m", &commit_message])?;
    
    ctx.success("Version changes committed");
    Ok(())
}