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

//! Cross-platform installation command for KindlyGuard binaries

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Platform information
#[derive(Debug, Clone)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Platform {
    /// Detect the current platform
    pub fn detect() -> Result<Self> {
        let os = match env::consts::OS {
            "linux" => Os::Linux,
            "macos" => Os::MacOs,
            "windows" => Os::Windows,
            other => anyhow::bail!("Unsupported OS: {}", other),
        };

        let arch = match env::consts::ARCH {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Aarch64,
            other => anyhow::bail!("Unsupported architecture: {}", other),
        };

        Ok(Platform { os, arch })
    }

    /// Get the platform-specific binary suffix
    pub fn binary_suffix(&self) -> &'static str {
        match self.os {
            Os::Windows => ".exe",
            _ => "",
        }
    }

    /// Get the platform string for GitHub releases
    pub fn release_target(&self) -> String {
        let os_str = match self.os {
            Os::Linux => "unknown-linux-gnu",
            Os::MacOs => "apple-darwin",
            Os::Windows => "pc-windows-msvc",
        };

        let arch_str = match self.arch {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        };

        format!("{}-{}", arch_str, os_str)
    }

    /// Get the default installation directory
    pub fn install_dir(&self) -> Result<PathBuf> {
        match self.os {
            Os::Linux | Os::MacOs => {
                // Try to use ~/.local/bin first (user-writable)
                if let Ok(home) = env::var("HOME") {
                    let local_bin = PathBuf::from(home).join(".local").join("bin");
                    if local_bin.exists() || self.can_create_dir(&local_bin) {
                        return Ok(local_bin);
                    }
                }
                // Fall back to /usr/local/bin (may require sudo)
                Ok(PathBuf::from("/usr/local/bin"))
            }
            Os::Windows => {
                // Use %LOCALAPPDATA%\Programs\KindlyGuard
                env::var("LOCALAPPDATA")
                    .map(|p| PathBuf::from(p).join("Programs").join("KindlyGuard"))
                    .context("Failed to get LOCALAPPDATA")
            }
        }
    }

    /// Check if we can create a directory
    fn can_create_dir(&self, path: &Path) -> bool {
        if let Some(parent) = path.parent() {
            parent.exists() && parent.metadata().map(|m| !m.permissions().readonly()).unwrap_or(false)
        } else {
            false
        }
    }
}

/// Installation configuration
pub struct InstallConfig {
    pub platform: Platform,
    pub version: String,
    pub install_dir: PathBuf,
    pub force: bool,
    pub verify_checksum: bool,
}

/// Component to install
#[derive(Debug, Clone)]
pub struct Component {
    pub name: &'static str,
    pub binary_name: &'static str,
    pub description: &'static str,
}

impl Component {
    /// Get all available components
    pub fn all() -> Vec<Self> {
        vec![
            Component {
                name: "kindly-guard-cli",
                binary_name: "kindly-guard",
                description: "KindlyGuard command-line interface",
            },
            Component {
                name: "kindly-guard-server",
                binary_name: "kindly-guard-server",
                description: "KindlyGuard MCP server",
            },
            Component {
                name: "kindly-guard-shield",
                binary_name: "kindly-guard-shield",
                description: "KindlyGuard desktop shield UI",
            },
        ]
    }

    /// Get the release asset name for this component
    pub fn asset_name(&self, platform: &Platform) -> String {
        format!(
            "{}-{}-{}{}",
            self.name,
            platform.release_target(),
            "release",
            if platform.os == Os::Windows { ".zip" } else { ".tar.gz" }
        )
    }
}

/// Download progress callback
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send>;

/// Install manager
pub struct Installer {
    config: InstallConfig,
    client: reqwest::Client,
}

impl Installer {
    /// Create a new installer
    pub fn new(config: InstallConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("kindly-guard-installer/0.1.0")
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Installer { config, client })
    }

    /// Install all components
    pub async fn install_all(&self, progress: Option<ProgressCallback>) -> Result<()> {
        println!("🛡️  KindlyGuard Installer");
        println!("Platform: {:?}", self.config.platform);
        println!("Version: {}", self.config.version);
        println!("Install directory: {}", self.config.install_dir.display());
        println!();

        // Create install directory
        self.ensure_install_dir()?;

        // Install each component
        for component in Component::all() {
            println!("Installing {}...", component.name);
            self.install_component(&component, progress.as_ref()).await?;
            println!("✓ {} installed successfully", component.name);
        }

        // Update PATH if needed
        self.update_path()?;

        println!();
        println!("✅ Installation complete!");
        println!();
        println!("To get started:");
        println!("  kindly-guard --help");
        println!("  kindly-guard-server --help");

        Ok(())
    }

    /// Install a specific component
    pub async fn install_component(
        &self,
        component: &Component,
        progress: Option<&ProgressCallback>,
    ) -> Result<()> {
        // Get download URL
        let download_url = self.get_download_url(component)?;
        
        // Download to temporary file
        let temp_path = self.config.install_dir.join(format!(".{}.tmp", component.binary_name));
        self.download_file(&download_url, &temp_path, progress).await?;

        // Verify checksum if enabled
        if self.config.verify_checksum {
            self.verify_checksum(&temp_path, component).await?;
        }

        // Extract if archive
        let extracted_path = if self.config.platform.os == Os::Windows {
            self.extract_zip(&temp_path, component)?
        } else {
            self.extract_tar_gz(&temp_path, component)?
        };

        // Install binary
        let binary_name = format!("{}{}", component.binary_name, self.config.platform.binary_suffix());
        let target_path = self.config.install_dir.join(&binary_name);
        
        // Check if already exists
        if target_path.exists() && !self.config.force {
            anyhow::bail!(
                "{} already exists. Use --force to overwrite.",
                target_path.display()
            );
        }

        // Move to final location
        fs::rename(&extracted_path, &target_path)
            .context("Failed to install binary")?;

        // Set executable permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&target_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&target_path, perms)?;
        }

        // Clean up
        let _ = fs::remove_file(&temp_path);

        Ok(())
    }

    /// Get the download URL for a component
    fn get_download_url(&self, component: &Component) -> Result<String> {
        let asset_name = component.asset_name(&self.config.platform);
        
        // GitHub releases URL format
        Ok(format!(
            "https://github.com/kindlysoftware/kindlyguard/releases/download/v{}/{}",
            self.config.version,
            asset_name
        ))
    }

    /// Download a file with progress
    async fn download_file(
        &self,
        url: &str,
        path: &Path,
        progress: Option<&ProgressCallback>,
    ) -> Result<()> {
        let response = self.client
            .get(url)
            .send()
            .await
            .context("Failed to start download")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Download failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        let total_size = response
            .content_length()
            .unwrap_or(0);

        let mut file = fs::File::create(path)
            .context("Failed to create temporary file")?;

        let mut downloaded = 0u64;
        let mut stream = response.bytes_stream();

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Failed to download chunk")?;
            file.write_all(&chunk)
                .context("Failed to write to file")?;
            
            downloaded += chunk.len() as u64;
            
            if let Some(callback) = progress {
                callback(downloaded, total_size);
            }
        }

        file.flush()?;
        Ok(())
    }

    /// Verify checksum of downloaded file
    async fn verify_checksum(&self, path: &Path, component: &Component) -> Result<()> {
        // Download checksum file
        let checksum_url = format!("{}.sha256", self.get_download_url(component)?);
        let checksum_response = self.client
            .get(&checksum_url)
            .send()
            .await
            .context("Failed to download checksum")?;

        if !checksum_response.status().is_success() {
            // Checksum file might not exist, skip verification
            println!("⚠️  Checksum file not found, skipping verification");
            return Ok(());
        }

        let expected_checksum = checksum_response
            .text()
            .await?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();

        // Calculate actual checksum
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let mut file = fs::File::open(path)?;
        std::io::copy(&mut file, &mut hasher)?;
        let actual_checksum = format!("{:x}", hasher.finalize());

        if actual_checksum != expected_checksum {
            anyhow::bail!(
                "Checksum verification failed!\nExpected: {}\nActual: {}",
                expected_checksum,
                actual_checksum
            );
        }

        Ok(())
    }

    /// Extract tar.gz archive
    fn extract_tar_gz(&self, archive_path: &Path, component: &Component) -> Result<PathBuf> {
        use flate2::read::GzDecoder;
        use tar::Archive;

        let file = fs::File::open(archive_path)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        let extract_dir = self.config.install_dir.join(format!(".extract-{}", component.binary_name));
        fs::create_dir_all(&extract_dir)?;

        archive.unpack(&extract_dir)?;

        // Find the binary
        let binary_name = format!("{}{}", component.binary_name, self.config.platform.binary_suffix());
        let binary_path = extract_dir.join(&binary_name);
        
        if !binary_path.exists() {
            // Try in subdirectory
            for entry in fs::read_dir(&extract_dir)? {
                let entry = entry?;
                let candidate = entry.path().join(&binary_name);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            anyhow::bail!("Binary {} not found in archive", binary_name);
        }

        Ok(binary_path)
    }

    /// Extract zip archive (Windows)
    fn extract_zip(&self, archive_path: &Path, component: &Component) -> Result<PathBuf> {
        use zip::ZipArchive;

        let file = fs::File::open(archive_path)?;
        let mut archive = ZipArchive::new(file)?;

        let extract_dir = self.config.install_dir.join(format!(".extract-{}", component.binary_name));
        fs::create_dir_all(&extract_dir)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = extract_dir.join(file.name());

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    fs::create_dir_all(p)?;
                }
                let mut outfile = fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }

        // Find the binary
        let binary_name = format!("{}{}", component.binary_name, self.config.platform.binary_suffix());
        let binary_path = extract_dir.join(&binary_name);
        
        if !binary_path.exists() {
            anyhow::bail!("Binary {} not found in archive", binary_name);
        }

        Ok(binary_path)
    }

    /// Ensure install directory exists
    fn ensure_install_dir(&self) -> Result<()> {
        if !self.config.install_dir.exists() {
            fs::create_dir_all(&self.config.install_dir)
                .context("Failed to create install directory")?;
        }
        Ok(())
    }

    /// Update PATH environment variable if needed
    fn update_path(&self) -> Result<()> {
        let install_dir = &self.config.install_dir;
        
        // Check if already in PATH
        if let Ok(path_var) = env::var("PATH") {
            let paths: Vec<&str> = if cfg!(windows) {
                path_var.split(';').collect()
            } else {
                path_var.split(':').collect()
            };
            
            if paths.iter().any(|p| Path::new(p) == install_dir) {
                return Ok(()); // Already in PATH
            }
        }

        // Provide instructions for adding to PATH
        match self.config.platform.os {
            Os::Linux | Os::MacOs => {
                println!();
                println!("📝 To add KindlyGuard to your PATH, add this to your shell profile:");
                println!();
                println!("  export PATH=\"{}:$PATH\"", install_dir.display());
                println!();
                
                // Try to detect shell
                if let Ok(shell) = env::var("SHELL") {
                    let profile = if shell.contains("zsh") {
                        "~/.zshrc"
                    } else if shell.contains("bash") {
                        "~/.bashrc"
                    } else if shell.contains("fish") {
                        "~/.config/fish/config.fish"
                    } else {
                        "your shell profile"
                    };
                    
                    println!("For {}, add it to {}", shell, profile);
                }
            }
            Os::Windows => {
                println!();
                println!("📝 To add KindlyGuard to your PATH:");
                println!();
                println!("1. Open System Properties → Environment Variables");
                println!("2. Add {} to your PATH", install_dir.display());
                println!();
                println!("Or run this PowerShell command as Administrator:");
                println!();
                println!("  [Environment]::SetEnvironmentVariable(");
                println!("      'Path',");
                println!("      [Environment]::GetEnvironmentVariable('Path', 'User') + ';{}'",
                    install_dir.display());
                println!("      'User'");
                println!("  )");
            }
        }

        Ok(())
    }
}

/// Run the installation
pub async fn run(
    version: Option<String>,
    install_dir: Option<PathBuf>,
    components: Option<Vec<String>>,
    force: bool,
    no_verify: bool,
) -> Result<()> {
    // Detect platform
    let platform = Platform::detect()?;
    
    // Get version (use latest if not specified)
    let version = if let Some(v) = version {
        v
    } else {
        // TODO: Fetch latest release version from GitHub API
        "0.9.7".to_string()
    };

    // Get install directory
    let install_dir = if let Some(dir) = install_dir {
        dir
    } else {
        platform.install_dir()?
    };

    // Create config
    let config = InstallConfig {
        platform,
        version,
        install_dir,
        force,
        verify_checksum: !no_verify,
    };

    // Create installer
    let installer = Installer::new(config)?;

    // Progress bar
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-")
    );

    let progress = Some(Box::new(move |downloaded: u64, total: u64| {
        pb.set_length(total);
        pb.set_position(downloaded);
    }) as ProgressCallback);

    // Install components
    if let Some(component_names) = components {
        // Install specific components
        let all_components = Component::all();
        for name in component_names {
            if let Some(component) = all_components.iter().find(|c| c.name == name || c.binary_name == name) {
                installer.install_component(component, progress.as_ref()).await?;
            } else {
                anyhow::bail!("Unknown component: {}", name);
            }
        }
    } else {
        // Install all components
        installer.install_all(progress).await?;
    }

    Ok(())
}