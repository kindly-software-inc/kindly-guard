//! Version management utilities

use anyhow::{Context, Result};
use regex::Regex;
use semver::Version;
use std::fs;
use std::path::Path;

/// Version locations in the project
#[derive(Debug, Clone)]
pub struct VersionLocation {
    pub file: String,
    pub pattern: Regex,
    pub replacement: String,
}

/// Get all version locations in the project
pub fn get_version_locations() -> Vec<VersionLocation> {
    vec![
        VersionLocation {
            file: "Cargo.toml".to_string(),
            pattern: Regex::new(r#"version = "[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
            replacement: r#"version = "{}""#.to_string(),
        },
        VersionLocation {
            file: "kindly-guard-server/Cargo.toml".to_string(),
            pattern: Regex::new(r#"version = "[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
            replacement: r#"version = "{}""#.to_string(),
        },
        VersionLocation {
            file: "kindly-guard-cli/Cargo.toml".to_string(),
            pattern: Regex::new(r#"version = "[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
            replacement: r#"version = "{}""#.to_string(),
        },
        VersionLocation {
            file: "kindly-guard-shield/Cargo.toml".to_string(),
            pattern: Regex::new(r#"version = "[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
            replacement: r#"version = "{}""#.to_string(),
        },
        VersionLocation {
            file: "npm-package/package.json".to_string(),
            pattern: Regex::new(r#""version": "[0-9]+\.[0-9]+\.[0-9]+""#).unwrap(),
            replacement: r#""version": "{}""#.to_string(),
        },
    ]
}

/// Get the current version from Cargo.toml
pub fn get_current_version() -> Result<Version> {
    let manifest = fs::read_to_string("Cargo.toml")?;
    let version_regex = Regex::new(r#"version = "([0-9]+\.[0-9]+\.[0-9]+)""#)?;
    
    if let Some(caps) = version_regex.captures(&manifest) {
        let version_str = caps.get(1).unwrap().as_str();
        Ok(Version::parse(version_str)?)
    } else {
        anyhow::bail!("Could not find version in Cargo.toml")
    }
}

/// Update version in a file
pub fn update_version_in_file(
    file_path: &str,
    pattern: &Regex,
    replacement_template: &str,
    new_version: &Version,
) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let replacement = replacement_template.replace("{}", &new_version.to_string());
    let new_content = pattern.replace_all(&content, replacement.as_str());
    
    fs::write(file_path, new_content.as_ref())?;
    Ok(())
}

/// Update version in all locations
pub fn update_all_versions(new_version: &Version) -> Result<()> {
    let locations = get_version_locations();
    
    for location in locations {
        if Path::new(&location.file).exists() {
            update_version_in_file(
                &location.file,
                &location.pattern,
                &location.replacement,
                new_version,
            )?;
        }
    }
    
    Ok(())
}

/// Bump version according to the specified level
pub fn bump_version(current: &Version, level: &str) -> Result<Version> {
    let mut new_version = current.clone();
    
    match level {
        "major" => {
            new_version.major += 1;
            new_version.minor = 0;
            new_version.patch = 0;
        }
        "minor" => {
            new_version.minor += 1;
            new_version.patch = 0;
        }
        "patch" => {
            new_version.patch += 1;
        }
        _ => anyhow::bail!("Invalid version bump level: {}", level),
    }
    
    Ok(new_version)
}

/// Parse a version string
pub fn parse_version(version_str: &str) -> Result<Version> {
    Ok(Version::parse(version_str)?)
}

/// Check if a version is valid
pub fn is_valid_version(version_str: &str) -> bool {
    Version::parse(version_str).is_ok()
}

/// Get version from Cargo.toml in specified directory or workspace root
pub fn get_version(dir: Option<&Path>) -> Result<String> {
    let cargo_toml_path = if let Some(d) = dir {
        d.join("Cargo.toml")
    } else {
        Path::new("Cargo.toml").to_path_buf()
    };
    
    let manifest = fs::read_to_string(&cargo_toml_path)
        .with_context(|| format!("Failed to read {}", cargo_toml_path.display()))?;
    
    let version_regex = Regex::new(r#"version = "([0-9]+\.[0-9]+\.[0-9]+)""#)?;
    
    if let Some(caps) = version_regex.captures(&manifest) {
        Ok(caps.get(1).unwrap().as_str().to_string())
    } else {
        anyhow::bail!("Could not find version in {}", cargo_toml_path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bump_version() {
        let version = Version::parse("1.2.3").unwrap();
        
        let major = bump_version(&version, "major").unwrap();
        assert_eq!(major.to_string(), "2.0.0");
        
        let minor = bump_version(&version, "minor").unwrap();
        assert_eq!(minor.to_string(), "1.3.0");
        
        let patch = bump_version(&version, "patch").unwrap();
        assert_eq!(patch.to_string(), "1.2.4");
    }

    #[test]
    fn test_is_valid_version() {
        assert!(is_valid_version("1.2.3"));
        assert!(is_valid_version("0.0.1"));
        assert!(!is_valid_version("1.2"));
        assert!(!is_valid_version("not-a-version"));
    }
}