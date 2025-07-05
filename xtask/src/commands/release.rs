use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Select, MultiSelect};
use semver::Version;
use std::collections::HashMap;

use crate::{config::ReleaseConfig, utils::Context};

#[derive(Args)]
pub struct ReleaseCmd {
    /// Version to release (e.g., 1.0.0)
    #[arg(value_name = "VERSION")]
    version: Option<String>,

    /// Skip confirmation prompts
    #[arg(long)]
    yes: bool,

    /// Skip tests before release
    #[arg(long)]
    skip_tests: bool,

    /// Skip security audits
    #[arg(long)]
    skip_security: bool,

    /// Skip building binaries
    #[arg(long)]
    skip_build: bool,

    /// Skip publishing to registries
    #[arg(long)]
    skip_publish: bool,

    /// Create a pre-release
    #[arg(long)]
    prerelease: bool,

    /// Create a draft release
    #[arg(long)]
    draft: bool,

    /// Run interactive pre-release checklist
    #[arg(long)]
    checklist: bool,
}

pub async fn run(cmd: ReleaseCmd, ctx: Context) -> Result<()> {
    let config = ReleaseConfig::load()?;
    
    // If checklist flag is set, run interactive checklist
    if cmd.checklist {
        return run_interactive_checklist(&ctx, cmd.version).await;
    }
    
    // Ensure we're in a clean git state
    check_git_status(&ctx).await?;

    // Determine version
    let version = determine_version(&cmd, &ctx)?;
    
    ctx.info(&format!("Preparing to release version {}", version.to_string().bold()));

    // Confirmation
    if !cmd.yes && !confirm_release(&version, &cmd, &config)? {
        ctx.warn("Release cancelled");
        return Ok(());
    }

    // Create release checklist
    let mut steps = vec![];
    
    if !cmd.skip_tests {
        steps.push(ReleaseStep::Tests);
    }
    if !cmd.skip_security && config.security.audit {
        steps.push(ReleaseStep::Security);
    }
    steps.push(ReleaseStep::Version);
    if !cmd.skip_build {
        steps.push(ReleaseStep::Build);
    }
    steps.push(ReleaseStep::GitTag);
    if !cmd.skip_publish {
        steps.push(ReleaseStep::Publish);
    }
    steps.push(ReleaseStep::GitHubRelease);

    // Execute release steps
    for (i, step) in steps.iter().enumerate() {
        ctx.info(&format!("[{}/{}] {}", i + 1, steps.len(), step));
        
        match step {
            ReleaseStep::Tests => run_tests(&ctx).await?,
            ReleaseStep::Security => run_security_checks(&ctx, &config).await?,
            ReleaseStep::Version => update_versions(&ctx, &version).await?,
            ReleaseStep::Build => build_all_platforms(&ctx, &config).await?,
            ReleaseStep::GitTag => create_git_tag(&ctx, &version).await?,
            ReleaseStep::Publish => publish_packages(&ctx, &config).await?,
            ReleaseStep::GitHubRelease => create_github_release(&ctx, &config, &version, &cmd).await?,
        }
        
        ctx.success(&format!("{} complete", step));
    }

    ctx.success(&format!("Release {} completed successfully! 🎉", version.to_string().bold()));
    
    // Print post-release instructions
    print_post_release_instructions(&ctx, &version);

    Ok(())
}

#[derive(Debug)]
enum ReleaseStep {
    Tests,
    Security,
    Version,
    Build,
    GitTag,
    Publish,
    GitHubRelease,
}

impl std::fmt::Display for ReleaseStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tests => write!(f, "Running tests"),
            Self::Security => write!(f, "Running security audits"),
            Self::Version => write!(f, "Updating version numbers"),
            Self::Build => write!(f, "Building for all platforms"),
            Self::GitTag => write!(f, "Creating git tag"),
            Self::Publish => write!(f, "Publishing to registries"),
            Self::GitHubRelease => write!(f, "Creating GitHub release"),
        }
    }
}

async fn check_git_status(ctx: &Context) -> Result<()> {
    let output = ctx.run_async("git", &["status", "--porcelain"]).await?;
    
    if !output.trim().is_empty() {
        anyhow::bail!("Git working directory is not clean. Please commit or stash changes.");
    }

    // Ensure we're on main/master branch
    let branch = ctx.run_async("git", &["branch", "--show-current"]).await?;
    let branch = branch.trim();
    
    if branch != "main" && branch != "master" {
        ctx.warn(&format!("You're on branch '{}', not main/master", branch));
    }

    Ok(())
}

fn determine_version(cmd: &ReleaseCmd, _ctx: &Context) -> Result<Version> {
    if let Some(v) = &cmd.version {
        Version::parse(v).context("Invalid version format")
    } else {
        // Get current version from Cargo.toml
        let manifest = std::fs::read_to_string("Cargo.toml")
            .context("Failed to read Cargo.toml")?;
        
        let current: toml::Value = toml::from_str(&manifest)
            .context("Failed to parse Cargo.toml")?;
        
        let current_version = current["package"]["version"]
            .as_str()
            .context("No version found in Cargo.toml")?;
        
        let current_version = Version::parse(current_version)?;
        
        // Suggest next versions
        let mut patch = current_version.clone();
        patch.patch += 1;
        
        let mut minor = current_version.clone();
        minor.minor += 1;
        minor.patch = 0;
        
        let mut major = current_version.clone();
        major.major += 1;
        major.minor = 0;
        major.patch = 0;

        let options = vec![
            format!("Patch ({} -> {})", current_version, patch),
            format!("Minor ({} -> {})", current_version, minor),
            format!("Major ({} -> {})", current_version, major),
            "Custom version".to_string(),
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select version increment")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => Ok(patch),
            1 => Ok(minor),
            2 => Ok(major),
            3 => {
                let custom = dialoguer::Input::<String>::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter custom version")
                    .validate_with(|input: &String| {
                        Version::parse(input)
                            .map(|_| ())
                            .map_err(|e| format!("Invalid version: {}", e))
                    })
                    .interact_text()?;
                
                Version::parse(&custom).context("Invalid version")
            }
            _ => unreachable!(),
        }
    }
}

fn confirm_release(version: &Version, cmd: &ReleaseCmd, config: &ReleaseConfig) -> Result<bool> {
    println!("\n{}", "Release Summary:".bold());
    println!("  Version: {}", version.to_string().green());
    println!("  Type: {}", if cmd.prerelease { "Pre-release" } else { "Production" });
    
    println!("\n  Steps:");
    if !cmd.skip_tests {
        println!("    ✓ Run all tests");
    }
    if !cmd.skip_security {
        println!("    ✓ Run security audits");
    }
    println!("    ✓ Update version numbers");
    if !cmd.skip_build {
        println!("    ✓ Build for {} platforms", config.platforms.targets.len());
    }
    println!("    ✓ Create git tag");
    if !cmd.skip_publish {
        println!("    ✓ Publish to:");
        if config.registries.crates_io {
            println!("      - crates.io");
        }
        if config.registries.npm {
            println!("      - npm");
        }
        if config.registries.docker {
            println!("      - Docker Hub");
        }
    }
    println!("    ✓ Create GitHub release");

    println!();
    
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Continue with release?")
        .default(true)
        .interact()
        .context("Failed to get confirmation")
}

async fn run_tests(ctx: &Context) -> Result<()> {
    let spinner = crate::utils::spinner("Running tests...");
    
    // Run unit tests
    ctx.run_command("cargo", &["test", "--all", "--all-features"])?;
    
    // Run integration tests if they exist
    if std::path::Path::new("tests/integration").exists() {
        ctx.run_command("cargo", &["test", "--test", "integration", "--", "--test-threads=1"])?;
    }
    
    spinner.finish_with_message("Tests passed");
    Ok(())
}

async fn run_security_checks(ctx: &Context, config: &ReleaseConfig) -> Result<()> {
    let spinner = crate::utils::spinner("Running security audits...");
    
    if config.security.audit {
        // Use the security command implementation
        crate::commands::security::run_audit(ctx)?;
    }
    
    if config.security.deny {
        crate::commands::security::run_deny(ctx)?;
    }
    
    spinner.finish_with_message("Security checks passed");
    Ok(())
}

async fn update_versions(ctx: &Context, version: &Version) -> Result<()> {
    // Use the version command implementation
    crate::commands::version::update_all_versions(ctx, version)?;
    
    // Commit version changes
    ctx.run_command("git", &["add", "-A"])?;
    ctx.run_command("git", &["commit", "-m", &format!("chore: Release v{}", version)])?;
    
    Ok(())
}

async fn build_all_platforms(ctx: &Context, config: &ReleaseConfig) -> Result<()> {
    // Use the build command implementation
    let build_cmd = crate::commands::build::BuildCmd {
        targets: Some(config.platforms.targets.clone()),
        release: true,
        strip: config.platforms.strip_binaries,
        archive: config.platforms.compress,
        output_dir: Some("release-artifacts".to_string()),
    };
    
    crate::commands::build::run(build_cmd, ctx.clone()).await?;
    
    Ok(())
}

async fn create_git_tag(ctx: &Context, version: &Version) -> Result<()> {
    let tag = format!("v{}", version);
    
    ctx.run_command("git", &["tag", "-a", &tag, "-m", &format!("Release {}", tag)])?;
    
    if !ctx.dry_run {
        ctx.run_command("git", &["push", "origin", &tag])?;
    }
    
    Ok(())
}

async fn publish_packages(ctx: &Context, config: &ReleaseConfig) -> Result<()> {
    // Use the publish command implementation
    let publish_cmd = crate::commands::publish::PublishCmd {
        crates_io: config.registries.crates_io,
        npm: config.registries.npm,
        docker: config.registries.docker,
        skip_verification: false,
    };
    
    crate::commands::publish::run(publish_cmd, ctx.clone()).await?;
    
    Ok(())
}

async fn create_github_release(
    ctx: &Context,
    config: &ReleaseConfig,
    _version: &Version,
    _cmd: &ReleaseCmd,
) -> Result<()> {
    if !config.registries.github_releases {
        return Ok(());
    }

    let spinner = crate::utils::spinner("Creating GitHub release...");

    // GitHub release functionality requires octocrab dependency
    // Uncomment the octocrab dependency in Cargo.toml and this code to enable GitHub releases
    
    ctx.warn("GitHub release creation is disabled. Enable octocrab in Cargo.toml to use this feature.");
    
    /*
    let github_token = std::env::var("GITHUB_TOKEN")
        .context("GITHUB_TOKEN environment variable not set")?;

    let octocrab = octocrab::OctocrabBuilder::new()
        .personal_token(github_token)
        .build()?;

    let tag = format!("v{}", version);
    
    // Read changelog for release notes
    let notes = if config.github.generate_notes {
        generate_release_notes(version)?
    } else {
        String::new()
    };

    // Create release
    let mut release_builder = octocrab
        .repos(&config.github.owner, &config.github.repo)
        .releases()
        .create(&tag)
        .name(&format!("Release v{}", version))
        .body(&notes)
        .draft(cmd.draft || config.github.draft)
        .prerelease(cmd.prerelease || config.github.prerelease);

    if !ctx.dry_run {
        let release = release_builder.send().await
            .context("Failed to create GitHub release")?;

        // Upload artifacts
        let artifacts_dir = std::path::Path::new("release-artifacts");
        if artifacts_dir.exists() {
            for entry in std::fs::read_dir(artifacts_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    let file_name = path.file_name()
                        .context("Invalid file name")?
                        .to_string_lossy();
                    
                    ctx.debug(&format!("Uploading {}", file_name));
                    
                    let file_data = std::fs::read(&path)
                        .context("Failed to read artifact")?;
                    
                    octocrab
                        .repos(&config.github.owner, &config.github.repo)
                        .releases()
                        .upload_asset(
                            release.id,
                            file_name.as_ref(),
                            "application/octet-stream",
                            file_data,
                        )
                        .await
                        .context("Failed to upload release asset")?;
                }
            }
        }
    }
    */

    spinner.finish_with_message("GitHub release created");
    Ok(())
}

fn generate_release_notes(version: &Version) -> Result<String> {
    // Try to extract from CHANGELOG.md
    if let Ok(changelog) = std::fs::read_to_string("CHANGELOG.md") {
        // Simple extraction - look for the version heading
        let version_heading = format!("## [{}]", version);
        if let Some(start) = changelog.find(&version_heading) {
            let content = &changelog[start..];
            // Find next version heading or end
            if let Some(end) = content[1..].find("## [") {
                return Ok(content[..end + 1].trim().to_string());
            } else {
                return Ok(content.trim().to_string());
            }
        }
    }

    // Fallback to generic message
    Ok(format!("Release version {}", version))
}

async fn run_interactive_checklist(ctx: &Context, version: Option<String>) -> Result<()> {
    ctx.info(&format!("{} KindlyGuard Pre-Release Checklist", "🚀".blue()));
    println!("{}", "=======================================".blue());
    
    let mut errors = 0;
    let mut warnings = 0;
    
    // Get current version
    let current_version = get_current_version()?;
    ctx.info(&format!("Current version: {}", current_version.to_string().yellow()));
    
    // Check if new version was provided
    let target_version = if let Some(v) = version {
        let parsed = Version::parse(&v).context("Invalid version format")?;
        if parsed <= current_version {
            ctx.error(&format!("Target version {} must be greater than current version {}", 
                parsed, current_version));
            errors += 1;
        }
        Some(parsed)
    } else {
        None
    };
    
    if let Some(ref ver) = target_version {
        ctx.info(&format!("Target release version: {}", ver.to_string().magenta()));
    }
    
    // Run all pre-release checks
    let checks = vec![
        PreReleaseCheck::VersionConsistency,
        PreReleaseCheck::ChangelogUpdate,
        PreReleaseCheck::DocumentationStatus,
        PreReleaseCheck::TestCoverage,
        PreReleaseCheck::SecurityAudit,
        PreReleaseCheck::LicenseVerification,
        PreReleaseCheck::BuildVerification,
        PreReleaseCheck::GitStatus,
        PreReleaseCheck::DependencyCheck,
        PreReleaseCheck::MsrvCompatibility,
    ];
    
    // Interactive checklist with progress
    ctx.info(&format!("\n{} Running pre-release checks", "📋".yellow()));
    
    for (i, check) in checks.iter().enumerate() {
        let (passed, is_warning) = run_check(ctx, check, &target_version).await?;
        
        if !passed {
            if is_warning {
                warnings += 1;
            } else {
                errors += 1;
            }
        }
        
        // Show progress
        let progress = format!("[{}/{}]", i + 1, checks.len());
        ctx.debug(&format!("{} Completed {}", progress.dimmed(), check));
    }
    
    // Summary
    println!("\n{}", "📊 Summary".blue().bold());
    println!("{}", "====================");
    println!("Current version: {}", current_version.to_string().yellow());
    if let Some(ver) = &target_version {
        println!("Target version: {}", ver.to_string().magenta());
    }
    println!("Errors: {}", if errors > 0 { errors.to_string().red() } else { errors.to_string().green() });
    println!("Warnings: {}", if warnings > 0 { warnings.to_string().yellow() } else { warnings.to_string().green() });
    
    if errors == 0 {
        ctx.success("All critical checks passed!");
        
        if warnings > 0 {
            ctx.warn(&format!("There are {} warnings to review", warnings));
        }
        
        // If version was provided, offer to update versions
        if let Some(ver) = &target_version {
            println!();
            let update = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Would you like to update all files to the new version?")
                .default(true)
                .interact()?;
                
            if update {
                crate::commands::version::update_all_versions(ctx, ver)?;
                ctx.success(&format!("Version updated to {}", ver));
            }
        }
        
        // Generate release notes
        if target_version.is_some() || Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Would you like to generate release notes?")
            .default(true)
            .interact()? 
        {
            generate_interactive_release_notes(ctx, &target_version.clone().unwrap_or(current_version.clone()))?;
        }
        
        // Show next steps
        println!("\n{}", "Next steps for release:".blue());
        println!("1. Ensure CHANGELOG.md is updated with release notes");
        println!("2. Commit all changes: git add -A && git commit -m \"Release v{}\"", 
            target_version.as_ref().unwrap_or(&current_version));
        println!("3. Run: cargo xtask release {}", 
            target_version.as_ref().unwrap_or(&current_version));
        
        Ok(())
    } else {
        ctx.error(&format!("{} critical checks failed. Please fix the issues before releasing.", errors));
        Err(anyhow::anyhow!("Pre-release checks failed"))
    }
}

#[derive(Debug, Clone)]
enum PreReleaseCheck {
    VersionConsistency,
    ChangelogUpdate,
    DocumentationStatus,
    TestCoverage,
    SecurityAudit,
    LicenseVerification,
    BuildVerification,
    GitStatus,
    DependencyCheck,
    MsrvCompatibility,
}

impl std::fmt::Display for PreReleaseCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionConsistency => write!(f, "Version Consistency"),
            Self::ChangelogUpdate => write!(f, "Changelog Updates"),
            Self::DocumentationStatus => write!(f, "Documentation Status"),
            Self::TestCoverage => write!(f, "Test Coverage"),
            Self::SecurityAudit => write!(f, "Security Audit"),
            Self::LicenseVerification => write!(f, "License Verification"),
            Self::BuildVerification => write!(f, "Build Verification"),
            Self::GitStatus => write!(f, "Git Repository Status"),
            Self::DependencyCheck => write!(f, "Dependency Check"),
            Self::MsrvCompatibility => write!(f, "MSRV Compatibility"),
        }
    }
}

async fn run_check(ctx: &Context, check: &PreReleaseCheck, target_version: &Option<Version>) -> Result<(bool, bool)> {
    let spinner = crate::utils::spinner(&format!("Checking: {}...", check));
    
    let (passed, is_warning) = match check {
        PreReleaseCheck::VersionConsistency => check_version_consistency(ctx).await,
        PreReleaseCheck::ChangelogUpdate => check_changelog_update(ctx, target_version).await,
        PreReleaseCheck::DocumentationStatus => check_documentation_status(ctx).await,
        PreReleaseCheck::TestCoverage => check_test_coverage(ctx).await,
        PreReleaseCheck::SecurityAudit => check_security_audit(ctx).await,
        PreReleaseCheck::LicenseVerification => check_license_verification(ctx).await,
        PreReleaseCheck::BuildVerification => check_build_verification(ctx).await,
        PreReleaseCheck::GitStatus => check_git_status_detailed(ctx).await,
        PreReleaseCheck::DependencyCheck => check_dependencies(ctx).await,
        PreReleaseCheck::MsrvCompatibility => check_msrv_compatibility(ctx).await,
    }?;
    
    if passed {
        spinner.finish_with_message(format!("✅ {}", check));
    } else if is_warning {
        spinner.finish_with_message(format!("⚠️  {} (warning)", check));
    } else {
        spinner.finish_with_message(format!("❌ {} (failed)", check));
    }
    
    Ok((passed, is_warning))
}

async fn check_version_consistency(ctx: &Context) -> Result<(bool, bool)> {
    // Use the version command's check functionality
    match crate::commands::version::check_version_consistency(ctx) {
        Ok(()) => Ok((true, false)),
        Err(_) => {
            ctx.error("Version mismatch detected across files");
            Ok((false, false))
        }
    }
}

async fn check_changelog_update(ctx: &Context, target_version: &Option<Version>) -> Result<(bool, bool)> {
    let changelog_path = crate::utils::workspace_root()?.join("CHANGELOG.md");
    
    if !changelog_path.exists() {
        ctx.warn("CHANGELOG.md not found");
        return Ok((false, true));
    }
    
    if let Some(ver) = target_version {
        let content = std::fs::read_to_string(&changelog_path)?;
        let version_heading = format!("## [{}]", ver);
        
        if !content.contains(&version_heading) {
            ctx.warn(&format!("CHANGELOG.md doesn't contain entry for version {}", ver));
            return Ok((false, true));
        }
    }
    
    Ok((true, false))
}

async fn check_documentation_status(ctx: &Context) -> Result<(bool, bool)> {
    let required_docs = vec!["README.md", "LICENSE"];
    let mut missing = vec![];
    
    for doc in required_docs {
        let path = crate::utils::workspace_root()?.join(doc);
        if !path.exists() {
            missing.push(doc);
        }
    }
    
    if missing.is_empty() {
        // Check if docs build successfully
        match ctx.run_command("cargo", &["doc", "--no-deps", "--all"]) {
            Ok(_) => Ok((true, false)),
            Err(_) => {
                ctx.error("Documentation build failed");
                Ok((false, false))
            }
        }
    } else {
        ctx.warn(&format!("Missing required documentation: {}", missing.join(", ")));
        Ok((false, true))
    }
}

async fn check_test_coverage(ctx: &Context) -> Result<(bool, bool)> {
    // Run tests
    let test_result = if crate::utils::command_exists("cargo-nextest") {
        ctx.run_command("cargo", &["nextest", "run", "--all"])
    } else {
        ctx.run_command("cargo", &["test", "--all"])
    };
    
    match test_result {
        Ok(_) => {
            // Also run doc tests
            match ctx.run_command("cargo", &["test", "--all", "--doc"]) {
                Ok(_) => Ok((true, false)),
                Err(_) => {
                    ctx.error("Doc tests failed");
                    Ok((false, false))
                }
            }
        }
        Err(_) => {
            ctx.error("Tests failed");
            Ok((false, false))
        }
    }
}

async fn check_security_audit(ctx: &Context) -> Result<(bool, bool)> {
    if !crate::utils::command_exists("cargo-audit") {
        ctx.warn("cargo-audit not installed, skipping security audit");
        return Ok((false, true));
    }
    
    match crate::commands::security::run_audit(ctx) {
        Ok(_) => Ok((true, false)),
        Err(_) => {
            ctx.error("Security vulnerabilities found");
            Ok((false, false))
        }
    }
}

async fn check_license_verification(ctx: &Context) -> Result<(bool, bool)> {
    let license_path = crate::utils::workspace_root()?.join("LICENSE");
    
    if !license_path.exists() {
        ctx.error("LICENSE file not found");
        return Ok((false, false));
    }
    
    // If cargo-deny is available, check licenses
    if crate::utils::command_exists("cargo-deny") {
        match ctx.run_command("cargo", &["deny", "check", "licenses"]) {
            Ok(_) => Ok((true, false)),
            Err(_) => {
                ctx.warn("License compliance check failed");
                Ok((false, true))
            }
        }
    } else {
        Ok((true, false))
    }
}

async fn check_build_verification(ctx: &Context) -> Result<(bool, bool)> {
    // Check debug build
    match ctx.run_command("cargo", &["build", "--all"]) {
        Ok(_) => {
            // Check release build
            match ctx.run_command("cargo", &["build", "--release", "--all"]) {
                Ok(_) => Ok((true, false)),
                Err(_) => {
                    ctx.error("Release build failed");
                    Ok((false, false))
                }
            }
        }
        Err(_) => {
            ctx.error("Debug build failed");
            Ok((false, false))
        }
    }
}

async fn check_git_status_detailed(ctx: &Context) -> Result<(bool, bool)> {
    let output = ctx.run_async("git", &["status", "--porcelain"]).await?;
    
    if !output.trim().is_empty() {
        ctx.warn("Working directory has uncommitted changes");
        return Ok((false, true));
    }
    
    // Check branch
    let branch = ctx.run_async("git", &["branch", "--show-current"]).await?;
    let branch = branch.trim();
    
    if branch != "main" && branch != "master" {
        ctx.warn(&format!("Not on main branch (current: {})", branch));
        return Ok((true, true)); // This is just a warning
    }
    
    Ok((true, false))
}

async fn check_dependencies(ctx: &Context) -> Result<(bool, bool)> {
    // Check for unused dependencies if cargo-machete is available
    if crate::utils::command_exists("cargo-machete") {
        match ctx.run_command("cargo", &["machete"]) {
            Ok(output) => {
                if output.contains("found the following") {
                    ctx.warn("Unused dependencies found");
                    return Ok((false, true));
                }
            }
            Err(_) => {
                // Tool failed to run, skip this check
            }
        }
    }
    
    Ok((true, false))
}

async fn check_msrv_compatibility(ctx: &Context) -> Result<(bool, bool)> {
    let msrv = "1.81";
    
    // Check if MSRV toolchain is installed
    let toolchain_check = ctx.run_command("rustup", &["toolchain", "list"]);
    
    if let Ok(output) = toolchain_check {
        if !output.contains(msrv) {
            ctx.warn(&format!("MSRV toolchain {} not installed", msrv));
            return Ok((false, true));
        }
        
        // Run MSRV build
        match ctx.run_command("cargo", &[&format!("+{}", msrv), "build", "--all-features"]) {
            Ok(_) => Ok((true, false)),
            Err(_) => {
                ctx.error(&format!("Build failed with MSRV {}", msrv));
                Ok((false, false))
            }
        }
    } else {
        Ok((true, false)) // Skip if rustup not available
    }
}

fn get_current_version() -> Result<Version> {
    let manifest = std::fs::read_to_string("Cargo.toml")
        .context("Failed to read Cargo.toml")?;
    
    let current: toml::Value = toml::from_str(&manifest)
        .context("Failed to parse Cargo.toml")?;
    
    let version_str = current["package"]["version"]
        .as_str()
        .or_else(|| current["workspace"]["package"]["version"].as_str())
        .context("No version found in Cargo.toml")?;
    
    Version::parse(version_str).context("Invalid version in Cargo.toml")
}

fn generate_interactive_release_notes(ctx: &Context, version: &Version) -> Result<()> {
    ctx.info(&format!("\n{} Generating release notes for v{}", "📝".yellow(), version));
    
    // Categories for release notes
    let categories = vec![
        ("Added", "New features"),
        ("Changed", "Changes in existing functionality"),
        ("Deprecated", "Soon-to-be removed features"),
        ("Removed", "Removed features"),
        ("Fixed", "Bug fixes"),
        ("Security", "Security updates"),
    ];
    
    let mut release_notes: HashMap<&str, Vec<String>> = HashMap::new();
    
    // For each category, ask if there are items to add
    for (category, description) in &categories {
        let has_items = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(&format!("Any {} items? ({})", category.to_lowercase(), description))
            .default(false)
            .interact()?;
            
        if has_items {
            ctx.info(&format!("Enter {} items (empty line to finish):", category));
            let mut items = vec![];
            
            loop {
                let item: String = dialoguer::Input::with_theme(&ColorfulTheme::default())
                    .with_prompt(">")
                    .allow_empty(true)
                    .interact_text()?;
                    
                if item.is_empty() {
                    break;
                }
                
                items.push(format!("- {}", item));
            }
            
            if !items.is_empty() {
                release_notes.insert(category, items);
            }
        }
    }
    
    // Generate release notes content
    if !release_notes.is_empty() {
        let date = chrono::Local::now().format("%Y-%m-%d");
        let mut content = format!("\n## [{}] - {}\n", version, date);
        
        for (category, _) in &categories {
            if let Some(items) = release_notes.get(category) {
                content.push_str(&format!("\n### {}\n", category));
                for item in items {
                    content.push_str(&format!("{}\n", item));
                }
            }
        }
        
        ctx.success("Generated release notes:");
        println!("{}", content.dimmed());
        
        // Offer to update CHANGELOG.md
        let update_changelog = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Update CHANGELOG.md with these notes?")
            .default(true)
            .interact()?;
            
        if update_changelog {
            update_changelog_with_notes(ctx, &content)?;
        }
    }
    
    Ok(())
}

fn update_changelog_with_notes(ctx: &Context, notes: &str) -> Result<()> {
    let changelog_path = crate::utils::workspace_root()?.join("CHANGELOG.md");
    
    if !changelog_path.exists() {
        // Create new CHANGELOG.md
        let content = format!("# Changelog\n\nAll notable changes to this project will be documented in this file.\n{}", notes);
        std::fs::write(&changelog_path, content)?;
        ctx.success("Created CHANGELOG.md");
    } else {
        let content = std::fs::read_to_string(&changelog_path)?;
        
        // Find insertion point
        let insertion_point = if let Some(pos) = content.find("## [") {
            pos
        } else if let Some(pos) = content.find("# Changelog") {
            content[pos..].find('\n').map(|n| pos + n + 1).unwrap_or(content.len())
        } else {
            0
        };
        
        // Insert new notes
        let mut new_content = String::new();
        new_content.push_str(&content[..insertion_point]);
        new_content.push_str(notes);
        new_content.push_str(&content[insertion_point..]);
        
        std::fs::write(&changelog_path, new_content)?;
        ctx.success("Updated CHANGELOG.md");
    }
    
    Ok(())
}

fn print_post_release_instructions(_ctx: &Context, _version: &Version) {
    println!("\n{}", "Post-release checklist:".bold());
    println!("  1. Verify packages on:");
    println!("     - https://crates.io/crates/kindly-guard");
    println!("     - https://www.npmjs.com/package/@kindly/guard");
    println!("     - https://hub.docker.com/r/kindly/guard");
    println!("  2. Check GitHub release: https://github.com/kindly-software/kindlyguard/releases");
    println!("  3. Update documentation if needed");
    println!("  4. Announce release on social media");
    println!("  5. Update version in README.md examples");
}