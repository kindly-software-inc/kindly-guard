use std::fmt;

/// Represents the detected platform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

impl Platform {
    /// Detect the current platform
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        return Platform::Linux;

        #[cfg(target_os = "macos")]
        return Platform::MacOS;

        #[cfg(target_os = "windows")]
        return Platform::Windows;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        return Platform::Unknown;
    }

    /// Get the platform's name
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Linux => "Linux",
            Platform::MacOS => "macOS",
            Platform::Windows => "Windows",
            Platform::Unknown => "Unknown",
        }
    }

    /// Get the platform's executable extension
    pub fn exe_extension(&self) -> &'static str {
        match self {
            Platform::Windows => ".exe",
            _ => "",
        }
    }

    /// Get the platform's dynamic library extension
    pub fn dylib_extension(&self) -> &'static str {
        match self {
            Platform::Linux => ".so",
            Platform::MacOS => ".dylib",
            Platform::Windows => ".dll",
            Platform::Unknown => "",
        }
    }

    /// Get the platform's static library extension
    pub fn staticlib_extension(&self) -> &'static str {
        match self {
            Platform::Windows => ".lib",
            _ => ".a",
        }
    }

    /// Check if the platform is Unix-like
    pub fn is_unix(&self) -> bool {
        matches!(self, Platform::Linux | Platform::MacOS)
    }

    /// Get shell command for the platform
    pub fn shell_command(&self) -> (&'static str, &'static [&'static str]) {
        match self {
            Platform::Windows => ("cmd", &["/C"]),
            _ => ("sh", &["-c"]),
        }
    }

    /// Get the platform's package manager
    pub fn package_manager(&self) -> Option<&'static str> {
        match self {
            Platform::Linux => {
                // Try to detect the specific Linux distribution
                if std::path::Path::new("/etc/debian_version").exists() {
                    Some("apt")
                } else if std::path::Path::new("/etc/redhat-release").exists() {
                    Some("yum")
                } else if std::path::Path::new("/etc/arch-release").exists() {
                    Some("pacman")
                } else if std::path::Path::new("/etc/alpine-release").exists() {
                    Some("apk")
                } else {
                    None
                }
            }
            Platform::MacOS => Some("brew"),
            Platform::Windows => Some("winget"),
            Platform::Unknown => None,
        }
    }

    /// Get common paths for the platform
    pub fn common_paths(&self) -> CommonPaths {
        match self {
            Platform::Linux => CommonPaths {
                config: "~/.config",
                cache: "~/.cache",
                data: "~/.local/share",
                temp: "/tmp",
            },
            Platform::MacOS => CommonPaths {
                config: "~/Library/Application Support",
                cache: "~/Library/Caches",
                data: "~/Library/Application Support",
                temp: "/tmp",
            },
            Platform::Windows => CommonPaths {
                config: "%APPDATA%",
                cache: "%LOCALAPPDATA%",
                data: "%APPDATA%",
                temp: "%TEMP%",
            },
            Platform::Unknown => CommonPaths {
                config: "~/.config",
                cache: "~/.cache",
                data: "~/.local/share",
                temp: "/tmp",
            },
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Common directory paths for different platforms
#[derive(Debug, Clone)]
pub struct CommonPaths {
    pub config: &'static str,
    pub cache: &'static str,
    pub data: &'static str,
    pub temp: &'static str,
}

/// Architecture detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown,
}

impl Architecture {
    /// Detect the current architecture
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86")]
        return Architecture::X86;

        #[cfg(target_arch = "x86_64")]
        return Architecture::X64;

        #[cfg(target_arch = "arm")]
        return Architecture::Arm;

        #[cfg(target_arch = "aarch64")]
        return Architecture::Arm64;

        #[cfg(not(any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64"
        )))]
        return Architecture::Unknown;
    }

    /// Get the architecture's name
    pub fn name(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Arm => "arm",
            Architecture::Arm64 => "arm64",
            Architecture::Unknown => "unknown",
        }
    }

    /// Check if the architecture is 64-bit
    pub fn is_64bit(&self) -> bool {
        matches!(self, Architecture::X64 | Architecture::Arm64)
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Get full platform information
pub struct PlatformInfo {
    pub platform: Platform,
    pub architecture: Architecture,
    pub hostname: Option<String>,
    pub username: Option<String>,
}

impl PlatformInfo {
    /// Gather all platform information
    pub fn gather() -> Self {
        Self {
            platform: Platform::detect(),
            architecture: Architecture::detect(),
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok()),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
        }
    }
}

impl fmt::Display for PlatformInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} (host: {}, user: {})",
            self.platform,
            self.architecture,
            self.hostname.as_deref().unwrap_or("unknown"),
            self.username.as_deref().unwrap_or("unknown")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::detect();
        assert_ne!(platform, Platform::Unknown);
    }

    #[test]
    fn test_architecture_detection() {
        let arch = Architecture::detect();
        assert_ne!(arch, Architecture::Unknown);
    }

    #[test]
    fn test_platform_info() {
        let info = PlatformInfo::gather();
        println!("Platform info: {}", info);
    }
}