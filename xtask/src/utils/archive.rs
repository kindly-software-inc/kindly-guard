//! Archive creation and extraction utilities

use anyhow::{Context as _, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use tar::{Archive as TarArchive, Builder as TarBuilder};
use walkdir::WalkDir;
use zip::write::{FileOptions as ZipFileOptions, ZipWriter};
use zip::{CompressionMethod, ZipArchive};

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Get the total size of files in a directory
fn get_dir_size(dir: &Path) -> Result<u64> {
    let mut total_size = 0;
    
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }
    
    Ok(total_size)
}

/// Normalize path separators for cross-platform compatibility
fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
}

/// Options for creating archives
pub struct CreateOptions {
    /// Compression level (0-9)
    pub compression_level: u32,
    /// Whether to follow symlinks
    pub follow_symlinks: bool,
    /// Whether to preserve file permissions
    pub preserve_permissions: bool,
    /// Progress callback
    pub progress: Option<ProgressCallback>,
}

impl std::fmt::Debug for CreateOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateOptions")
            .field("compression_level", &self.compression_level)
            .field("follow_symlinks", &self.follow_symlinks)
            .field("preserve_permissions", &self.preserve_permissions)
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

impl Clone for CreateOptions {
    fn clone(&self) -> Self {
        Self {
            compression_level: self.compression_level,
            follow_symlinks: self.follow_symlinks,
            preserve_permissions: self.preserve_permissions,
            progress: None, // Cannot clone function pointers
        }
    }
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            compression_level: 6,
            follow_symlinks: false,
            preserve_permissions: true,
            progress: None,
        }
    }
}

/// Options for extracting archives
pub struct ExtractOptions {
    /// Whether to preserve file permissions
    pub preserve_permissions: bool,
    /// Whether to overwrite existing files
    pub overwrite: bool,
    /// Progress callback
    pub progress: Option<ProgressCallback>,
}

impl std::fmt::Debug for ExtractOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractOptions")
            .field("preserve_permissions", &self.preserve_permissions)
            .field("overwrite", &self.overwrite)
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

impl Clone for ExtractOptions {
    fn clone(&self) -> Self {
        Self {
            preserve_permissions: self.preserve_permissions,
            overwrite: self.overwrite,
            progress: None, // Cannot clone function pointers
        }
    }
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            preserve_permissions: true,
            overwrite: true,
            progress: None,
        }
    }
}

/// Create a tar.gz archive
pub fn create_tar_gz(
    archive_path: &Path,
    source_dir: &Path,
    options: CreateOptions,
) -> Result<()> {
    let file = File::create(archive_path)
        .with_context(|| format!("Failed to create archive: {}", archive_path.display()))?;
    
    let encoder = GzEncoder::new(file, Compression::new(options.compression_level));
    let mut builder = TarBuilder::new(encoder);
    
    // Collect all files to add
    let total_size = if options.progress.is_some() {
        get_dir_size(source_dir)?
    } else {
        0
    };
    
    let mut processed_size = 0u64;
    
    // Walk the directory and add files
    for entry in WalkDir::new(source_dir).follow_links(options.follow_symlinks) {
        let entry = entry?;
        let path = entry.path();
        
        // Skip the archive itself if it's in the source directory
        if path == archive_path {
            continue;
        }
        
        // Get relative path
        let rel_path = path.strip_prefix(source_dir)
            .with_context(|| format!("Failed to strip prefix from {}", path.display()))?;
        
        // Skip empty relative paths
        if rel_path.as_os_str().is_empty() {
            continue;
        }
        
        // Add to archive
        if entry.file_type().is_file() {
            let mut file = File::open(path)?;
            let metadata = file.metadata()?;
            
            if options.preserve_permissions {
                let mut header = tar::Header::new_gnu();
                header.set_size(metadata.len());
                header.set_mode(0o644); // Default to readable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    header.set_mode(metadata.permissions().mode());
                }
                header.set_cksum();
                
                builder.append_data(&mut header, normalize_path(rel_path), &mut file)?;
            } else {
                builder.append_file(normalize_path(rel_path), &mut file)?;
            }
            
            processed_size += metadata.len();
            
            if let Some(ref progress) = options.progress {
                progress(processed_size, total_size);
            }
        } else if entry.file_type().is_dir() {
            builder.append_dir(normalize_path(rel_path), path)?;
        }
    }
    
    builder.finish()?;
    Ok(())
}

/// Create a zip archive
pub fn create_zip(
    archive_path: &Path,
    source_dir: &Path,
    options: CreateOptions,
) -> Result<()> {
    let file = File::create(archive_path)
        .with_context(|| format!("Failed to create archive: {}", archive_path.display()))?;
    
    let mut zip = ZipWriter::new(file);
    
    let compression = match options.compression_level {
        0 => CompressionMethod::Stored,
        _ => CompressionMethod::Deflated,
    };
    
    let file_options = ZipFileOptions::<()>::default()
        .compression_method(compression)
        .compression_level(Some(options.compression_level as i64));
    
    // Collect all files to add
    let total_size = if options.progress.is_some() {
        get_dir_size(source_dir)?
    } else {
        0
    };
    
    let mut processed_size = 0u64;
    
    // Walk the directory and add files
    for entry in WalkDir::new(source_dir).follow_links(options.follow_symlinks) {
        let entry = entry?;
        let path = entry.path();
        
        // Skip the archive itself if it's in the source directory
        if path == archive_path {
            continue;
        }
        
        // Get relative path
        let rel_path = path.strip_prefix(source_dir)
            .with_context(|| format!("Failed to strip prefix from {}", path.display()))?;
        
        // Skip empty relative paths
        if rel_path.as_os_str().is_empty() {
            continue;
        }
        
        let name = normalize_path(rel_path);
        
        // Add to archive
        if entry.file_type().is_file() {
            #[cfg(unix)]
            let mut file_options = file_options;
            #[cfg(unix)]
            if options.preserve_permissions {
                use std::os::unix::fs::PermissionsExt;
                let metadata = entry.metadata()?;
                file_options = file_options.unix_permissions(metadata.permissions().mode());
            }
            
            zip.start_file(&name, file_options)?;
            let mut file = File::open(path)?;
            io::copy(&mut file, &mut zip)?;
            
            let metadata = entry.metadata()?;
            processed_size += metadata.len();
            
            if let Some(ref progress) = options.progress {
                progress(processed_size, total_size);
            }
        } else if entry.file_type().is_dir() && !name.is_empty() {
            zip.add_directory(&name, file_options)?;
        }
    }
    
    zip.finish()?;
    Ok(())
}

/// Extract a tar.gz archive
pub fn extract_tar_gz(
    archive_path: &Path,
    dest_dir: &Path,
    options: ExtractOptions,
) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    
    let decoder = GzDecoder::new(file);
    let mut archive = TarArchive::new(decoder);
    
    // Create destination directory if it doesn't exist
    fs::create_dir_all(dest_dir)?;
    
    // Count entries for progress
    let total_entries = if options.progress.is_some() {
        let file = File::open(archive_path)?;
        let decoder = GzDecoder::new(file);
        let mut counter = TarArchive::new(decoder);
        counter.entries()?.count() as u64
    } else {
        0
    };
    
    let mut processed_entries = 0u64;
    
    // Extract files
    archive.set_preserve_permissions(options.preserve_permissions);
    archive.set_overwrite(options.overwrite);
    
    for (idx, entry) in archive.entries()?.enumerate() {
        let mut entry = entry?;
        let path = entry.path()?;
        let dest_path = dest_dir.join(&path);
        
        // Ensure the parent directory exists
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        entry.unpack(&dest_path)?;
        
        processed_entries = idx as u64 + 1;
        if let Some(ref progress) = options.progress {
            progress(processed_entries, total_entries);
        }
    }
    
    Ok(())
}

/// Extract a zip archive
pub fn extract_zip(
    archive_path: &Path,
    dest_dir: &Path,
    options: ExtractOptions,
) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    
    let mut archive = ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("Failed to read zip archive: {}", archive_path.display()))?;
    
    // Create destination directory if it doesn't exist
    fs::create_dir_all(dest_dir)?;
    
    let total_entries = archive.len() as u64;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest_dir.join(file.name());
        
        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            
            if !options.overwrite && outpath.exists() {
                continue;
            }
            
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
            
            #[cfg(unix)]
            if options.preserve_permissions {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
        
        if let Some(ref progress) = options.progress {
            progress(i as u64 + 1, total_entries);
        }
    }
    
    Ok(())
}

/// List contents of an archive
pub fn list_archive_contents(archive_path: &Path) -> Result<Vec<String>> {
    let extension = archive_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    
    match extension {
        "gz" | "tgz" => list_tar_gz_contents(archive_path),
        "zip" => list_zip_contents(archive_path),
        _ => anyhow::bail!("Unsupported archive format: {}", extension),
    }
}

fn list_tar_gz_contents(archive_path: &Path) -> Result<Vec<String>> {
    let file = File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = TarArchive::new(decoder);
    
    let mut contents = Vec::new();
    for entry in archive.entries()? {
        let entry = entry?;
        contents.push(entry.path()?.to_string_lossy().to_string());
    }
    
    Ok(contents)
}

fn list_zip_contents(archive_path: &Path) -> Result<Vec<String>> {
    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;
    
    let mut contents = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        contents.push(file.name().to_string());
    }
    
    Ok(contents)
}

/// Extract a single file from an archive
pub fn extract_file(
    archive_path: &Path,
    file_name: &str,
    dest_path: &Path,
) -> Result<()> {
    let extension = archive_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    
    match extension {
        "gz" | "tgz" => extract_file_from_tar_gz(archive_path, file_name, dest_path),
        "zip" => extract_file_from_zip(archive_path, file_name, dest_path),
        _ => anyhow::bail!("Unsupported archive format: {}", extension),
    }
}

fn extract_file_from_tar_gz(
    archive_path: &Path,
    file_name: &str,
    dest_path: &Path,
) -> Result<()> {
    let file = File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = TarArchive::new(decoder);
    
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        
        if path.to_string_lossy() == file_name {
            // Ensure parent directory exists
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            entry.unpack(dest_path)?;
            return Ok(());
        }
    }
    
    anyhow::bail!("File '{}' not found in archive", file_name)
}

fn extract_file_from_zip(
    archive_path: &Path,
    file_name: &str,
    dest_path: &Path,
) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;
    
    let mut file = archive.by_name(file_name)
        .with_context(|| format!("File '{}' not found in archive", file_name))?;
    
    // Ensure parent directory exists
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut outfile = File::create(dest_path)?;
    io::copy(&mut file, &mut outfile)?;
    
    Ok(())
}

/// Create a platform-specific archive (zip for Windows, tar.gz for others)
pub fn create_platform_archive(
    archive_path: &Path,
    source_dir: &Path,
    target: Option<&str>,
    options: CreateOptions,
) -> Result<PathBuf> {
    let is_windows = target
        .map(|t| t.contains("windows"))
        .unwrap_or(cfg!(target_os = "windows"));
    
    let archive_path = if is_windows {
        archive_path.with_extension("zip")
    } else {
        archive_path.with_extension("tar.gz")
    };
    
    if is_windows {
        create_zip(&archive_path, source_dir, options)?;
    } else {
        create_tar_gz(&archive_path, source_dir, options)?;
    }
    
    Ok(archive_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_create_and_extract_tar_gz() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let archive_path = temp_dir.path().join("test.tar.gz");
        let extract_dir = temp_dir.path().join("extracted");
        
        // Create test files
        fs::create_dir_all(&source_dir)?;
        fs::write(source_dir.join("file1.txt"), "Hello, world!")?;
        fs::create_dir_all(source_dir.join("subdir"))?;
        fs::write(source_dir.join("subdir/file2.txt"), "Nested file")?;
        
        // Create archive
        create_tar_gz(&archive_path, &source_dir, CreateOptions::default())?;
        assert!(archive_path.exists());
        
        // Extract archive
        extract_tar_gz(&archive_path, &extract_dir, ExtractOptions::default())?;
        
        // Verify extracted files
        assert!(extract_dir.join("file1.txt").exists());
        assert!(extract_dir.join("subdir/file2.txt").exists());
        
        let content1 = fs::read_to_string(extract_dir.join("file1.txt"))?;
        assert_eq!(content1, "Hello, world!");
        
        let content2 = fs::read_to_string(extract_dir.join("subdir/file2.txt"))?;
        assert_eq!(content2, "Nested file");
        
        Ok(())
    }
    
    #[test]
    fn test_create_and_extract_zip() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let archive_path = temp_dir.path().join("test.zip");
        let extract_dir = temp_dir.path().join("extracted");
        
        // Create test files
        fs::create_dir_all(&source_dir)?;
        fs::write(source_dir.join("file1.txt"), "Hello, world!")?;
        fs::create_dir_all(source_dir.join("subdir"))?;
        fs::write(source_dir.join("subdir/file2.txt"), "Nested file")?;
        
        // Create archive
        create_zip(&archive_path, &source_dir, CreateOptions::default())?;
        assert!(archive_path.exists());
        
        // Extract archive
        extract_zip(&archive_path, &extract_dir, ExtractOptions::default())?;
        
        // Verify extracted files
        assert!(extract_dir.join("file1.txt").exists());
        assert!(extract_dir.join("subdir/file2.txt").exists());
        
        let content1 = fs::read_to_string(extract_dir.join("file1.txt"))?;
        assert_eq!(content1, "Hello, world!");
        
        let content2 = fs::read_to_string(extract_dir.join("subdir/file2.txt"))?;
        assert_eq!(content2, "Nested file");
        
        Ok(())
    }
    
    #[test]
    fn test_list_archive_contents() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let archive_path = temp_dir.path().join("test.tar.gz");
        
        // Create test files
        fs::create_dir_all(&source_dir)?;
        fs::write(source_dir.join("file1.txt"), "Hello")?;
        fs::create_dir_all(source_dir.join("subdir"))?;
        fs::write(source_dir.join("subdir/file2.txt"), "World")?;
        
        // Create archive
        create_tar_gz(&archive_path, &source_dir, CreateOptions::default())?;
        
        // List contents
        let contents = list_archive_contents(&archive_path)?;
        assert!(contents.iter().any(|f| f.contains("file1.txt")));
        assert!(contents.iter().any(|f| f.contains("file2.txt")));
        
        Ok(())
    }
}