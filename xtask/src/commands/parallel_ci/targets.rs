//! Target platform matrix for cross-compilation

use std::fmt;

/// Matrix of target platforms for building and testing
#[derive(Debug, Clone)]
pub struct TargetMatrix {
    targets: Vec<Target>,
}

/// A single target platform
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub triple: String,
    pub os: OS,
    pub arch: Arch,
    pub requires_cross: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    Linux,
    MacOS,
    Windows,
    Wasm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Wasm32,
}

impl TargetMatrix {
    /// Create default target matrix based on current platform
    pub fn default() -> Self {
        let mut targets = vec![
            // Always include current platform
            Target::current_platform(),
        ];
        
        // Add common cross-compilation targets
        #[cfg(target_os = "linux")]
        {
            targets.push(Target::linux_x64());
            targets.push(Target::linux_arm64());
            targets.push(Target::windows_x64());
        }
        
        #[cfg(target_os = "macos")]
        {
            targets.push(Target::macos_x64());
            targets.push(Target::macos_arm64());
        }
        
        #[cfg(target_os = "windows")]
        {
            targets.push(Target::windows_x64());
            targets.push(Target::linux_x64());
        }
        
        // Remove duplicates
        targets.dedup();
        
        Self { targets }
    }
    
    /// Create default set of platforms for CI
    pub fn default_platforms() -> Self {
        Self {
            targets: vec![
                Target::linux_x64(),
                Target::linux_arm64(),
                Target::macos_x64(),
                Target::macos_arm64(),
                Target::windows_x64(),
            ],
        }
    }
    
    /// Create from string list
    pub fn from_strings(targets: Vec<String>) -> Self {
        let targets = targets
            .into_iter()
            .filter_map(|s| Target::from_string(&s))
            .collect();
        
        Self { targets }
    }
    
    /// Get all target strings
    pub fn all_targets(&self) -> Vec<String> {
        self.targets.iter().map(|t| t.triple.clone()).collect()
    }
    
    /// Iterator over targets
    pub fn iter(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
    
    /// Number of targets
    pub fn len(&self) -> usize {
        self.targets.len()
    }
}

impl Target {
    /// Get current platform target
    pub fn current_platform() -> Self {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        return Self::linux_x64();
        
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return Self::linux_arm64();
        
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        return Self::macos_x64();
        
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return Self::macos_arm64();
        
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        return Self::windows_x64();
        
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "windows", target_arch = "x86_64"),
        )))]
        return Self {
            triple: "unknown".to_string(),
            os: OS::Linux,
            arch: Arch::X86_64,
            requires_cross: false,
        };
    }
    
    pub fn linux_x64() -> Self {
        Self {
            triple: "x86_64-unknown-linux-gnu".to_string(),
            os: OS::Linux,
            arch: Arch::X86_64,
            requires_cross: cfg!(not(all(target_os = "linux", target_arch = "x86_64"))),
        }
    }
    
    pub fn linux_arm64() -> Self {
        Self {
            triple: "aarch64-unknown-linux-gnu".to_string(),
            os: OS::Linux,
            arch: Arch::Aarch64,
            requires_cross: cfg!(not(all(target_os = "linux", target_arch = "aarch64"))),
        }
    }
    
    pub fn macos_x64() -> Self {
        Self {
            triple: "x86_64-apple-darwin".to_string(),
            os: OS::MacOS,
            arch: Arch::X86_64,
            requires_cross: cfg!(not(all(target_os = "macos", target_arch = "x86_64"))),
        }
    }
    
    pub fn macos_arm64() -> Self {
        Self {
            triple: "aarch64-apple-darwin".to_string(),
            os: OS::MacOS,
            arch: Arch::Aarch64,
            requires_cross: cfg!(not(all(target_os = "macos", target_arch = "aarch64"))),
        }
    }
    
    pub fn windows_x64() -> Self {
        Self {
            triple: "x86_64-pc-windows-msvc".to_string(),
            os: OS::Windows,
            arch: Arch::X86_64,
            requires_cross: cfg!(not(all(target_os = "windows", target_arch = "x86_64"))),
        }
    }
    
    pub fn wasm32() -> Self {
        Self {
            triple: "wasm32-unknown-unknown".to_string(),
            os: OS::Wasm,
            arch: Arch::Wasm32,
            requires_cross: false, // wasm doesn't need cross
        }
    }
    
    /// Parse from string representation
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "linux-x64" | "x86_64-unknown-linux-gnu" => Some(Self::linux_x64()),
            "linux-arm64" | "aarch64-unknown-linux-gnu" => Some(Self::linux_arm64()),
            "macos" | "macos-x64" | "x86_64-apple-darwin" => Some(Self::macos_x64()),
            "macos-arm64" | "aarch64-apple-darwin" => Some(Self::macos_arm64()),
            "windows" | "windows-x64" | "x86_64-pc-windows-msvc" => Some(Self::windows_x64()),
            "wasm" | "wasm32" | "wasm32-unknown-unknown" => Some(Self::wasm32()),
            _ => None,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.triple)
    }
}

impl fmt::Display for OS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OS::Linux => write!(f, "Linux"),
            OS::MacOS => write!(f, "macOS"),
            OS::Windows => write!(f, "Windows"),
            OS::Wasm => write!(f, "WASM"),
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "ARM64"),
            Arch::Wasm32 => write!(f, "WASM32"),
        }
    }
}