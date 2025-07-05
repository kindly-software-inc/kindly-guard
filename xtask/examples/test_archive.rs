//! Example usage of the archive module

use anyhow::Result;
use std::path::Path;
use xtask::utils::archive::{
    create_tar_gz, create_zip, extract_tar_gz, extract_zip,
    list_archive_contents, CreateOptions, ExtractOptions,
};

fn main() -> Result<()> {
    println!("Archive utility example");
    
    // Example paths
    let source_dir = Path::new(".");
    let tar_gz_path = Path::new("test.tar.gz");
    let zip_path = Path::new("test.zip");
    
    // Create tar.gz with progress
    println!("\nCreating tar.gz archive...");
    let mut create_opts = CreateOptions::default();
    create_opts.compression_level = 6;
    create_opts.progress = Some(Box::new(|current, total| {
        println!("Progress: {}/{}", current, total);
    }));
    
    create_tar_gz(tar_gz_path, source_dir, create_opts.clone())?;
    println!("Created: {}", tar_gz_path.display());
    
    // Create zip
    println!("\nCreating zip archive...");
    create_zip(zip_path, source_dir, create_opts)?;
    println!("Created: {}", zip_path.display());
    
    // List contents
    println!("\nTar.gz contents:");
    let tar_contents = list_archive_contents(tar_gz_path)?;
    for (i, entry) in tar_contents.iter().take(10).enumerate() {
        println!("  {}. {}", i + 1, entry);
    }
    if tar_contents.len() > 10 {
        println!("  ... and {} more", tar_contents.len() - 10);
    }
    
    println!("\nZip contents:");
    let zip_contents = list_archive_contents(zip_path)?;
    for (i, entry) in zip_contents.iter().take(10).enumerate() {
        println!("  {}. {}", i + 1, entry);
    }
    if zip_contents.len() > 10 {
        println!("  ... and {} more", zip_contents.len() - 10);
    }
    
    // Clean up
    std::fs::remove_file(tar_gz_path).ok();
    std::fs::remove_file(zip_path).ok();
    
    println!("\nArchive operations completed successfully!");
    
    Ok(())
}