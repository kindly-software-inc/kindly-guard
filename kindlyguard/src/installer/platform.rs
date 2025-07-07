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

//! Platform detection and environment analysis

use anyhow::Result;
use std::env;
use std::fs;
use std::path::Path;

/// Platform types
#[derive(Debug, Clone, PartialEq)]
pub enum Platform {
    Linux(LinuxDistro),
    MacOS,
    Windows,
    Unknown,
}

/// Linux distribution types
#[derive(Debug, Clone, PartialEq)]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    Fedora,
    CentOS,
    RHEL,
    Arch,
    OpenSUSE,
    Alpine,
    Unknown,
}

/// Environment information
#[derive(Debug, Default)]
pub struct EnvironmentInfo {
    pub docker: bool,
    pub wsl: bool,
    pub ci: bool,
    pub ssh: bool,
    pub proxy: Option<String>,
    pub sudo_available: bool,
    pub package_managers: Vec<String>,
}

/// Detect the current platform
pub fn detect_platform() -> Platform {
    match env::consts::OS {
        "linux" => Platform::Linux(detect_linux_distro()),
        "macos" => Platform::MacOS,
        "windows" => Platform::Windows,
        _ => Platform::Unknown,
    }
}

/// Detect Linux distribution
pub fn detect_linux_distro() -> LinuxDistro {
    // Check /etc/os-release first (standard)
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        let lower = content.to_lowercase();
        
        if lower.contains("ubuntu") {
            return LinuxDistro::Ubuntu;
        } else if lower.contains("debian") {
            return LinuxDistro::Debian;
        } else if lower.contains("fedora") {
            return LinuxDistro::Fedora;
        } else if lower.contains("centos") {
            return LinuxDistro::CentOS;
        } else if lower.contains("rhel") || lower.contains("red hat") {
            return LinuxDistro::RHEL;
        } else if lower.contains("arch") {
            return LinuxDistro::Arch;
        } else if lower.contains("opensuse") || lower.contains("suse") {
            return LinuxDistro::OpenSUSE;
        } else if lower.contains("alpine") {
            return LinuxDistro::Alpine;
        }
    }

    // Check for distro-specific files
    if Path::new("/etc/debian_version").exists() {
        LinuxDistro::Debian
    } else if Path::new("/etc/redhat-release").exists() {
        LinuxDistro::RHEL
    } else if Path::new("/etc/arch-release").exists() {
        LinuxDistro::Arch
    } else if Path::new("/etc/alpine-release").exists() {
        LinuxDistro::Alpine
    } else {
        LinuxDistro::Unknown
    }
}

/// Detect environment details
pub fn detect_environment() -> EnvironmentInfo {
    let mut info = EnvironmentInfo::default();

    // Check for Docker
    info.docker = Path::new("/.dockerenv").exists() 
        || env::var("DOCKER_CONTAINER").is_ok();

    // Check for WSL
    info.wsl = env::var("WSL_DISTRO_NAME").is_ok()
        || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists();

    // Check for CI/CD
    info.ci = env::var("CI").is_ok()
        || env::var("CONTINUOUS_INTEGRATION").is_ok()
        || env::var("GITHUB_ACTIONS").is_ok()
        || env::var("GITLAB_CI").is_ok()
        || env::var("JENKINS_URL").is_ok();

    // Check for SSH
    info.ssh = env::var("SSH_CLIENT").is_ok()
        || env::var("SSH_TTY").is_ok();

    // Check for proxy
    info.proxy = env::var("HTTP_PROXY")
        .or_else(|_| env::var("http_proxy"))
        .or_else(|_| env::var("HTTPS_PROXY"))
        .or_else(|_| env::var("https_proxy"))
        .ok();

    // Check for sudo
    info.sudo_available = which::which("sudo").is_ok();

    // Detect available package managers
    info.package_managers = detect_package_managers();

    info
}

/// Detect available package managers
fn detect_package_managers() -> Vec<String> {
    let mut managers = Vec::new();

    // Check common package managers
    let checks = vec![
        ("apt", "apt-get"),
        ("dnf", "dnf"),
        ("yum", "yum"),
        ("pacman", "pacman"),
        ("zypper", "zypper"),
        ("apk", "apk"),
        ("brew", "homebrew"),
        ("npm", "npm"),
        ("cargo", "cargo"),
        ("snap", "snap"),
        ("flatpak", "flatpak"),
    ];

    for (cmd, name) in checks {
        if which::which(cmd).is_ok() {
            managers.push(name.to_string());
        }
    }

    managers
}

/// Detect best installation method for the platform
pub fn detect_best_install_method(platform: &Platform) -> Result<String> {
    let env_info = detect_environment();

    // Check for preferred methods based on available tools
    if env_info.package_managers.contains(&"cargo".to_string()) {
        return Ok("cargo".to_string());
    }

    match platform {
        Platform::MacOS => {
            if env_info.package_managers.contains(&"homebrew".to_string()) {
                Ok("homebrew".to_string())
            } else if env_info.package_managers.contains(&"npm".to_string()) {
                Ok("npm".to_string())
            } else {
                Ok("binary".to_string())
            }
        }
        Platform::Linux(distro) => {
            match distro {
                LinuxDistro::Ubuntu | LinuxDistro::Debian => {
                    if env_info.package_managers.contains(&"snap".to_string()) {
                        Ok("snap".to_string())
                    } else if env_info.package_managers.contains(&"apt-get".to_string()) {
                        Ok("apt".to_string())
                    } else {
                        Ok("binary".to_string())
                    }
                }
                LinuxDistro::Fedora | LinuxDistro::CentOS | LinuxDistro::RHEL => {
                    if env_info.package_managers.contains(&"dnf".to_string()) {
                        Ok("dnf".to_string())
                    } else if env_info.package_managers.contains(&"yum".to_string()) {
                        Ok("yum".to_string())
                    } else {
                        Ok("binary".to_string())
                    }
                }
                LinuxDistro::Arch => {
                    if env_info.package_managers.contains(&"pacman".to_string()) {
                        Ok("aur".to_string())
                    } else {
                        Ok("binary".to_string())
                    }
                }
                LinuxDistro::Alpine => {
                    Ok("binary".to_string()) // Alpine typically uses static binaries
                }
                _ => Ok("binary".to_string()),
            }
        }
        Platform::Windows => {
            if env_info.package_managers.contains(&"npm".to_string()) {
                Ok("npm".to_string())
            } else {
                Ok("binary".to_string())
            }
        }
        Platform::Unknown => Ok("binary".to_string()),
    }
}

/// Get platform-specific binary name
pub fn get_platform_binary_name(base_name: &str) -> String {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let suffix = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc.exe",
        _ => return base_name.to_string(),
    };

    format!("{}-{}", base_name, suffix)
}