//! Generate command implementation

use anyhow::Result;
use std::fs;
use std::process::Command;

use crate::utils::{git, version, Context};

/// Execute the generate command
pub async fn execute(
    ctx: Context,
    changelog: bool,
    release_notes: bool,
    docs: bool,
    completions: bool,
) -> Result<()> {
    if !changelog && !release_notes && !docs && !completions {
        ctx.warn("No generation target specified. Use --changelog, --release-notes, --docs, or --completions");
        return Ok(());
    }

    // Generate changelog
    if changelog {
        generate_changelog(&ctx).await?;
    }

    // Generate release notes
    if release_notes {
        generate_release_notes(&ctx).await?;
    }

    // Generate documentation
    if docs {
        generate_documentation(&ctx).await?;
    }

    // Generate shell completions
    if completions {
        generate_completions(&ctx).await?;
    }

    ctx.status("Success", "Generation completed");
    
    Ok(())
}

async fn generate_changelog(ctx: &Context) -> Result<()> {
    ctx.status("Changelog", "Generating changelog");

    // Use git cliff if available
    if crate::utils::command_exists("git-cliff") {
        let mut cmd = Command::new("git-cliff");
        cmd.args(&["-o", "CHANGELOG.md"]);
        ctx.run_command(&mut cmd)?;
    } else {
        // Fallback to simple git log
        let mut cmd = Command::new("git");
        cmd.args(&["log", "--pretty=format:- %s (%h)", "--no-merges"]);
        
        let output = ctx.run_command(&mut cmd)?;
        let log = String::from_utf8_lossy(&output.stdout);
        
        let changelog = format!(
            "# Changelog\n\n## Recent Changes\n\n{}\n",
            log
        );
        
        fs::write("CHANGELOG.md", changelog)?;
    }

    ctx.status("Created", "CHANGELOG.md");
    
    Ok(())
}

async fn generate_release_notes(ctx: &Context) -> Result<()> {
    ctx.status("Release", "Generating release notes");

    let version = version::get_current_version()?;
    let last_tag = git::latest_tag()?.unwrap_or_else(|| "HEAD".to_string());
    let commits = git::commits_since_tag(&last_tag)?;

    let mut notes = format!("# Release Notes - v{}\n\n", version);
    notes.push_str(&format!("**Date**: {}\n\n", chrono::Local::now().format("%Y-%m-%d")));

    // Group commits by type
    let mut features = Vec::new();
    let mut fixes = Vec::new();
    let mut security = Vec::new();
    let mut breaking = Vec::new();
    let mut other = Vec::new();

    for commit in commits {
        if commit.contains("BREAKING") {
            breaking.push(commit);
        } else if commit.starts_with("feat:") || commit.starts_with("feature:") {
            features.push(commit);
        } else if commit.starts_with("fix:") {
            fixes.push(commit);
        } else if commit.starts_with("security:") {
            security.push(commit);
        } else {
            other.push(commit);
        }
    }

    // Write sections
    if !breaking.is_empty() {
        notes.push_str("## ⚠️ Breaking Changes\n\n");
        for item in breaking {
            notes.push_str(&format!("- {}\n", item));
        }
        notes.push('\n');
    }

    if !security.is_empty() {
        notes.push_str("## 🔐 Security Updates\n\n");
        for item in security {
            notes.push_str(&format!("- {}\n", item));
        }
        notes.push('\n');
    }

    if !features.is_empty() {
        notes.push_str("## ✨ New Features\n\n");
        for item in features {
            notes.push_str(&format!("- {}\n", item));
        }
        notes.push('\n');
    }

    if !fixes.is_empty() {
        notes.push_str("## 🐛 Bug Fixes\n\n");
        for item in fixes {
            notes.push_str(&format!("- {}\n", item));
        }
        notes.push('\n');
    }

    if !other.is_empty() {
        notes.push_str("## 📝 Other Changes\n\n");
        for item in other {
            notes.push_str(&format!("- {}\n", item));
        }
        notes.push('\n');
    }

    let filename = format!("RELEASE_NOTES_v{}.md", version);
    fs::write(&filename, notes)?;
    
    ctx.status("Created", &filename);
    
    Ok(())
}

async fn generate_documentation(ctx: &Context) -> Result<()> {
    ctx.status("Docs", "Generating documentation");

    // Generate Rust docs
    crate::utils::cargo::run_cargo(ctx, &["doc", "--no-deps", "--all-features"])?;

    // Generate mdBook if available
    if crate::utils::command_exists("mdbook") && std::path::Path::new("book.toml").exists() {
        ctx.status("mdBook", "Building documentation book");
        let mut cmd = Command::new("mdbook");
        cmd.arg("build");
        ctx.run_command(&mut cmd)?;
    }

    ctx.status("Success", "Documentation generated in target/doc");
    
    Ok(())
}

async fn generate_completions(ctx: &Context) -> Result<()> {
    ctx.status("Completions", "Generating shell completions");

    // Create completions directory
    let comp_dir = "target/completions";
    fs::create_dir_all(comp_dir)?;

    // Generate for each binary
    let binaries = vec![
        ("kindly-guard", "kindly-guard-cli/src/main.rs"),
        ("kindly-guard-server", "kindly-guard-server/src/main.rs"),
    ];

    for (name, _path) in binaries {
        ctx.status("Generating", &format!("completions for {}", name));
        
        // This is a placeholder - actual implementation would use clap_complete
        // to generate real completions from the CLI definitions
        
        // Bash
        let bash_comp = format!("# Bash completion for {}\n# Add to ~/.bashrc", name);
        fs::write(format!("{}/{}.bash", comp_dir, name), bash_comp)?;
        
        // Zsh
        let zsh_comp = format!("# Zsh completion for {}\n# Add to ~/.zshrc", name);
        fs::write(format!("{}/_{}", comp_dir, name), zsh_comp)?;
        
        // Fish
        let fish_comp = format!("# Fish completion for {}\n# Add to ~/.config/fish/completions/", name);
        fs::write(format!("{}/{}.fish", comp_dir, name), fish_comp)?;
    }

    ctx.status("Created", &format!("Shell completions in {}", comp_dir));
    
    Ok(())
}