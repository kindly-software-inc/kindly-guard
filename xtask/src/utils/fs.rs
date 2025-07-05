//! Filesystem utilities

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Copy a directory recursively
pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(&dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    
    Ok(())
}

/// Find files matching a pattern
pub fn find_files(root: impl AsRef<Path>, pattern: &str) -> Result<Vec<PathBuf>> {
    let re = regex::Regex::new(pattern)?;
    let mut files = Vec::new();
    
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if re.is_match(name) {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
    }
    
    Ok(files)
}

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir(path: impl AsRef<Path>) -> Result<()> {
    if !path.as_ref().exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Remove a directory and all its contents
pub fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    if path.as_ref().exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

/// Read a JSON file
pub fn read_json<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

/// Write a JSON file
pub fn write_json<T: serde::Serialize>(path: impl AsRef<Path>, data: &T) -> Result<()> {
    let contents = serde_json::to_string_pretty(data)?;
    fs::write(path, contents)?;
    Ok(())
}

/// Read a TOML file
pub fn read_toml<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&contents)?)
}

/// Write a TOML file
pub fn write_toml<T: serde::Serialize>(path: impl AsRef<Path>, data: &T) -> Result<()> {
    let contents = toml::to_string_pretty(data)?;
    fs::write(path, contents)?;
    Ok(())
}

/// Create a temporary directory that's automatically cleaned up
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()?;
        
        // Keep the temporary directory from being deleted
        let path = dir.path().to_path_buf();
        let _ = dir.keep();  // Keep returns the path, we already have it
        Ok(Self { path })
    }
    
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}