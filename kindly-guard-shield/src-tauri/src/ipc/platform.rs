use std::{
    fs::{self, OpenOptions},
    io::{self, Error, ErrorKind},
    path::PathBuf,
};

use tracing::{debug, info, warn};

use crate::errors::ShieldError;

/// Platform-specific shared memory path resolution
pub struct PlatformShm;

impl PlatformShm {
    /// Get the appropriate shared memory directory for the current platform
    pub fn get_shm_dir() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            // On Linux, use /dev/shm for true shared memory (tmpfs)
            let dev_shm = PathBuf::from("/dev/shm");
            if dev_shm.exists() && dev_shm.is_dir() {
                info!("Using /dev/shm for shared memory (Linux tmpfs)");
                return dev_shm.join("kindly-guard");
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS doesn't have /dev/shm, use /tmp with specific permissions
            let tmp_dir = PathBuf::from("/tmp");
            info!("Using /tmp for shared memory (macOS)");
            return tmp_dir.join("kindly-guard-shm");
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows: Use Local AppData for memory-mapped files
            if let Some(local_data) = dirs::data_local_dir() {
                info!("Using Local AppData for shared memory (Windows)");
                return local_data.join("KindlyGuard").join("shm");
            }
        }
        
        // Fallback to system temp directory
        let temp = std::env::temp_dir().join("kindly-guard-shm");
        warn!("Using temp directory for shared memory: {:?}", temp);
        temp
    }
    
    /// Set appropriate permissions for shared memory files
    pub fn set_shm_permissions(path: &PathBuf) -> Result<(), ShieldError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            // Set permissions to 0600 (read/write for owner only)
            let metadata = fs::metadata(path)
                .map_err(|e| ShieldError::Io(format!("Failed to get metadata: {}", e)))?;
            
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            
            fs::set_permissions(path, permissions)
                .map_err(|e| ShieldError::Io(format!("Failed to set permissions: {}", e)))?;
            
            debug!("Set Unix permissions 0600 on {:?}", path);
        }
        
        #[cfg(windows)]
        {
            // Windows: The file is already created with appropriate ACLs
            // Additional security can be added here if needed
            debug!("Windows file permissions set by default");
        }
        
        Ok(())
    }
    
    /// Create a lock file to ensure single writer
    pub fn create_lock_file(shm_dir: &PathBuf) -> Result<PathBuf, ShieldError> {
        let lock_path = shm_dir.join("kindly-guard.lock");
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            
            // Try to create with O_EXCL for atomic creation
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lock_path)
            {
                Ok(file) => {
                    // Write PID to lock file
                    use std::io::Write;
                    let pid = std::process::id();
                    writeln!(&file, "{}", pid)
                        .map_err(|e| ShieldError::Io(format!("Failed to write PID: {}", e)))?;
                    
                    info!("Created lock file with PID {}", pid);
                    Ok(lock_path)
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    // Check if the process is still alive
                    if let Ok(contents) = fs::read_to_string(&lock_path) {
                        if let Ok(pid) = contents.trim().parse::<u32>() {
                            if Self::is_process_alive(pid) {
                                return Err(ShieldError::Lock(
                                    format!("Another instance is running (PID: {})", pid)
                                ));
                            } else {
                                warn!("Removing stale lock file from PID {}", pid);
                                fs::remove_file(&lock_path).ok();
                                // Retry
                                return Self::create_lock_file(shm_dir);
                            }
                        }
                    }
                    Err(ShieldError::Lock("Lock file exists".into()))
                }
                Err(e) => Err(ShieldError::Io(format!("Failed to create lock file: {}", e))),
            }
        }
        
        #[cfg(windows)]
        {
            // Windows lock file creation
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    let pid = std::process::id();
                    writeln!(&mut file, "{}", pid)
                        .map_err(|e| ShieldError::Io(format!("Failed to write PID: {}", e)))?;
                    
                    info!("Created lock file with PID {}", pid);
                    Ok(lock_path)
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    Err(ShieldError::Lock("Another instance may be running".into()))
                }
                Err(e) => Err(ShieldError::Io(format!("Failed to create lock file: {}", e))),
            }
        }
    }
    
    /// Check if a process is still alive
    #[cfg(unix)]
    fn is_process_alive(pid: u32) -> bool {
        use libc::{kill, ESRCH};
        
        // Send signal 0 to check if process exists
        unsafe {
            let result = kill(pid as i32, 0);
            if result == 0 {
                true
            } else {
                let errno = *libc::__errno_location();
                errno != ESRCH // ESRCH means process doesn't exist
            }
        }
    }
    
    #[cfg(windows)]
    fn is_process_alive(pid: u32) -> bool {
        // Simple check - in production, use Windows API
        true
    }
    
    /// Clean up lock file on drop
    pub fn cleanup_lock_file(lock_path: &PathBuf) {
        if let Err(e) = fs::remove_file(lock_path) {
            warn!("Failed to remove lock file: {}", e);
        } else {
            debug!("Removed lock file");
        }
    }
    
    /// Get optimal buffer size for the platform
    pub fn get_optimal_buffer_size() -> usize {
        #[cfg(target_os = "linux")]
        {
            // Linux typically has good support for larger buffers
            2 * 1024 * 1024 // 2MB
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS may have different optimal sizes
            1024 * 1024 // 1MB
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows memory-mapped files
            1024 * 1024 // 1MB
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            512 * 1024 // 512KB for unknown platforms
        }
    }
    
    /// Check if huge pages are available (Linux)
    #[cfg(target_os = "linux")]
    pub fn check_huge_pages() -> bool {
        if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
            if contents.contains("HugePages_Total:") {
                // Parse the total number of huge pages
                for line in contents.lines() {
                    if line.starts_with("HugePages_Total:") {
                        if let Some(count_str) = line.split_whitespace().nth(1) {
                            if let Ok(count) = count_str.parse::<u32>() {
                                if count > 0 {
                                    info!("Huge pages available: {}", count);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }
    
    #[cfg(not(target_os = "linux"))]
    pub fn check_huge_pages() -> bool {
        false
    }
}

/// Platform-specific optimizations
pub struct PlatformOptimizations;

impl PlatformOptimizations {
    /// Apply platform-specific optimizations to the memory region
    pub fn optimize_memory_region(addr: *mut u8, size: usize) -> Result<(), ShieldError> {
        #[cfg(target_os = "linux")]
        {
            use libc::{madvise, MADV_SEQUENTIAL, MADV_WILLNEED};
            
            unsafe {
                // Advise kernel about access pattern
                let result = madvise(addr as *mut libc::c_void, size, MADV_SEQUENTIAL);
                if result != 0 {
                    warn!("madvise MADV_SEQUENTIAL failed");
                }
                
                // Pre-fault pages
                let result = madvise(addr as *mut libc::c_void, size, MADV_WILLNEED);
                if result != 0 {
                    warn!("madvise MADV_WILLNEED failed");
                } else {
                    debug!("Applied Linux memory optimizations");
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS-specific optimizations could go here
            debug!("No specific memory optimizations for macOS");
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows-specific optimizations could go here
            debug!("No specific memory optimizations for Windows");
        }
        
        Ok(())
    }
    
    /// Set CPU affinity for better cache performance
    #[cfg(target_os = "linux")]
    pub fn set_cpu_affinity(cpu: usize) -> Result<(), ShieldError> {
        use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};
        
        unsafe {
            let mut cpu_set: cpu_set_t = std::mem::zeroed();
            CPU_ZERO(&mut cpu_set);
            CPU_SET(cpu, &mut cpu_set);
            
            let result = sched_setaffinity(
                0, // Current thread
                std::mem::size_of::<cpu_set_t>(),
                &cpu_set,
            );
            
            if result == 0 {
                info!("Set CPU affinity to core {}", cpu);
                Ok(())
            } else {
                Err(ShieldError::Platform("Failed to set CPU affinity".into()))
            }
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    pub fn set_cpu_affinity(_cpu: usize) -> Result<(), ShieldError> {
        // Not implemented on other platforms
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_platform_shm_dir() {
        let dir = PlatformShm::get_shm_dir();
        println!("Platform SHM directory: {:?}", dir);
        
        // Directory should be absolute
        assert!(dir.is_absolute());
    }
    
    #[test]
    fn test_optimal_buffer_size() {
        let size = PlatformShm::get_optimal_buffer_size();
        println!("Optimal buffer size: {} bytes", size);
        
        // Should be at least 512KB
        assert!(size >= 512 * 1024);
    }
    
    #[cfg(target_os = "linux")]
    #[test]
    fn test_huge_pages_check() {
        let available = PlatformShm::check_huge_pages();
        println!("Huge pages available: {}", available);
    }
}