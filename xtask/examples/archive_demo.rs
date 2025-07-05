//! Comprehensive demonstration of the archive module features

use anyhow::Result;
use std::fs;
use std::path::Path;
use tempfile::TempDir;
use xtask::utils::archive::{
    create_platform_archive, create_tar_gz, create_zip, extract_tar_gz, extract_zip,
    list_archive_contents, ArchiveFormat, CreateOptions, ExtractOptions,
};

fn main() -> Result<()> {
    println!("=== Archive Module Demo ===\n");

    // Create a temporary directory for our demo
    let temp = TempDir::new()?;
    let demo_dir = temp.path();
    
    // Create sample directory structure
    create_sample_files(demo_dir)?;
    
    // Demo 1: Basic tar.gz creation
    demo_basic_tar_gz(demo_dir)?;
    
    // Demo 2: Zip with progress reporting
    demo_zip_with_progress(demo_dir)?;
    
    // Demo 3: Platform-specific archives
    demo_platform_archives(demo_dir)?;
    
    // Demo 4: Archive listing
    demo_list_archives(demo_dir)?;
    
    // Demo 5: Extract with options
    demo_extract_options(demo_dir)?;

    println!("\n✅ All demos completed successfully!");
    Ok(())
}

fn create_sample_files(base_dir: &Path) -> Result<()> {
    println!("📁 Creating sample directory structure...");
    
    let src_dir = base_dir.join("sample_project");
    fs::create_dir_all(&src_dir)?;
    
    // Create some sample files
    fs::write(src_dir.join("README.md"), "# Sample Project\n\nThis is a demo.")?;
    fs::write(src_dir.join("main.rs"), "fn main() {\n    println!(\"Hello, world!\");\n}")?;
    
    // Create subdirectory
    let sub_dir = src_dir.join("src");
    fs::create_dir_all(&sub_dir)?;
    fs::write(sub_dir.join("lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }")?;
    fs::write(sub_dir.join("utils.rs"), "pub fn helper() -> &'static str { \"Helper\" }")?;
    
    // Create binary directory
    let bin_dir = src_dir.join("bin");
    fs::create_dir_all(&bin_dir)?;
    fs::write(bin_dir.join("app"), "#!/bin/bash\necho 'Running app'")?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(bin_dir.join("app"), fs::Permissions::from_mode(0o755))?;
    }
    
    println!("   ✓ Created sample files in {:?}", src_dir);
    Ok(())
}

fn demo_basic_tar_gz(base_dir: &Path) -> Result<()> {
    println!("\n🎯 Demo 1: Basic tar.gz creation");
    
    let src_dir = base_dir.join("sample_project");
    let archive_path = base_dir.join("basic.tar.gz");
    
    let options = CreateOptions::default();
    create_tar_gz(&archive_path, &src_dir, options)?;
    
    let size = fs::metadata(&archive_path)?.len();
    println!("   ✓ Created archive: {:?} ({} bytes)", archive_path, size);
    
    Ok(())
}

fn demo_zip_with_progress(base_dir: &Path) -> Result<()> {
    println!("\n🎯 Demo 2: ZIP with progress reporting");
    
    let src_dir = base_dir.join("sample_project");
    let archive_path = base_dir.join("with_progress.zip");
    
    let mut options = CreateOptions::default();
    options.compression_level = 9; // Maximum compression
    options.progress = Some(Box::new(|current, total| {
        let percentage = (current as f64 / total as f64) * 100.0;
        print!("\r   Progress: {:.1}% ({}/{})", percentage, current, total);
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }));
    
    create_zip(&archive_path, &src_dir, options)?;
    println!(); // New line after progress
    
    let size = fs::metadata(&archive_path)?.len();
    println!("   ✓ Created compressed ZIP: {:?} ({} bytes)", archive_path, size);
    
    Ok(())
}

fn demo_platform_archives(base_dir: &Path) -> Result<()> {
    println!("\n🎯 Demo 3: Platform-specific archives");
    
    let src_dir = base_dir.join("sample_project");
    let targets = vec![
        ("x86_64-pc-windows-msvc", "Windows x64"),
        ("x86_64-unknown-linux-gnu", "Linux x64"),
        ("aarch64-apple-darwin", "macOS ARM64"),
    ];
    
    for (target, name) in targets {
        let archive_base = base_dir.join(format!("app-{}", target));
        let archive_path = create_platform_archive(
            &archive_base,
            &src_dir,
            target,
            CreateOptions::default(),
        )?;
        
        let ext = archive_path.extension().unwrap_or_default().to_string_lossy();
        println!("   ✓ {} archive: {:?} ({})", name, archive_path.file_name().unwrap(), ext);
    }
    
    Ok(())
}

fn demo_list_archives(base_dir: &Path) -> Result<()> {
    println!("\n🎯 Demo 4: Listing archive contents");
    
    let archives = vec![
        base_dir.join("basic.tar.gz"),
        base_dir.join("with_progress.zip"),
    ];
    
    for archive_path in archives {
        if archive_path.exists() {
            println!("\n   📋 Contents of {:?}:", archive_path.file_name().unwrap());
            let contents = list_archive_contents(&archive_path)?;
            for (i, entry) in contents.iter().enumerate() {
                if i < 5 {
                    println!("      - {}", entry);
                } else if i == 5 {
                    println!("      ... and {} more entries", contents.len() - 5);
                    break;
                }
            }
        }
    }
    
    Ok(())
}

fn demo_extract_options(base_dir: &Path) -> Result<()> {
    println!("\n🎯 Demo 5: Extract with options");
    
    let tar_path = base_dir.join("basic.tar.gz");
    let extract_dir = base_dir.join("extracted_tar");
    
    let mut options = ExtractOptions::default();
    options.preserve_permissions = true;
    options.overwrite = true;
    options.progress = Some(Box::new(|current, total| {
        if current == total {
            println!("   ✓ Extracted {}/{} files", current, total);
        }
    }));
    
    extract_tar_gz(&tar_path, &extract_dir, options)?;
    
    // Verify extraction
    let readme_path = extract_dir.join("README.md");
    if readme_path.exists() {
        println!("   ✓ Successfully extracted files to {:?}", extract_dir);
    }
    
    // Check permissions were preserved on Unix
    #[cfg(unix)]
    {
        let app_path = extract_dir.join("bin/app");
        if app_path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&app_path)?.permissions();
            if perms.mode() & 0o111 != 0 {
                println!("   ✓ Executable permissions preserved");
            }
        }
    }
    
    Ok(())
}