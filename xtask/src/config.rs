use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseConfig {
    pub registries: RegistryConfig,
    pub platforms: PlatformConfig,
    pub github: GitHubConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub crates_io: bool,
    pub npm: bool,
    pub docker: bool,
    pub github_releases: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformConfig {
    pub targets: Vec<String>,
    pub strip_binaries: bool,
    pub compress: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubConfig {
    pub owner: String,
    pub repo: String,
    pub draft: bool,
    pub prerelease: bool,
    pub generate_notes: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub audit: bool,
    pub deny: bool,
    pub sarif_report: bool,
    pub fail_on_warnings: bool,
}

impl Default for ReleaseConfig {
    fn default() -> Self {
        Self {
            registries: RegistryConfig {
                crates_io: true,
                npm: true,
                docker: true,
                github_releases: true,
            },
            platforms: PlatformConfig {
                targets: vec![
                    "x86_64-unknown-linux-gnu".to_string(),
                    "x86_64-unknown-linux-musl".to_string(),
                    "x86_64-apple-darwin".to_string(),
                    "aarch64-apple-darwin".to_string(),
                    "x86_64-pc-windows-msvc".to_string(),
                ],
                strip_binaries: true,
                compress: true,
            },
            github: GitHubConfig {
                owner: "kindly-software".to_string(),
                repo: "kindlyguard".to_string(),
                draft: false,
                prerelease: false,
                generate_notes: true,
            },
            security: SecurityConfig {
                audit: true,
                deny: true,
                sarif_report: true,
                fail_on_warnings: true,
            },
        }
    }
}

impl ReleaseConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read {}", config_path.display()))?;
            
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", config_path.display()))
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write {}", config_path.display()))?;

        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let root = crate::utils::workspace_root()?;
        Ok(root.join("release-config.toml"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionLocations {
    pub files: Vec<VersionFile>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionFile {
    pub path: String,
    pub pattern: String,
    pub replacement: String,
}

impl Default for VersionLocations {
    fn default() -> Self {
        Self {
            files: vec![
                VersionFile {
                    path: "Cargo.toml".to_string(),
                    pattern: r#"^version = ".*"$"#.to_string(),
                    replacement: r#"version = "{VERSION}""#.to_string(),
                },
                VersionFile {
                    path: "kindly-guard-server/Cargo.toml".to_string(),
                    pattern: r#"^version = ".*"$"#.to_string(),
                    replacement: r#"version = "{VERSION}""#.to_string(),
                },
                VersionFile {
                    path: "kindly-guard-cli/Cargo.toml".to_string(),
                    pattern: r#"^version = ".*"$"#.to_string(),
                    replacement: r#"version = "{VERSION}""#.to_string(),
                },
                VersionFile {
                    path: "kindly-guard-shield/Cargo.toml".to_string(),
                    pattern: r#"^version = ".*"$"#.to_string(),
                    replacement: r#"version = "{VERSION}""#.to_string(),
                },
                VersionFile {
                    path: "package.json".to_string(),
                    pattern: r#""version": ".*""#.to_string(),
                    replacement: r#""version": "{VERSION}""#.to_string(),
                },
            ],
        }
    }
}