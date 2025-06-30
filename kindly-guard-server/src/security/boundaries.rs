//! Security boundaries and limits for safe operation

use once_cell::sync::Lazy;
use std::time::Duration;

/// Maximum sizes for various inputs
pub struct SecurityLimits {
    /// Maximum scan input size (10MB)
    pub max_scan_size: usize,
    /// Maximum JSON nesting depth
    pub max_json_depth: usize,
    /// Maximum regex pattern length
    pub max_pattern_length: usize,
    /// Maximum file path length
    pub max_path_length: usize,
    /// Maximum concurrent operations
    pub max_concurrent_ops: usize,
    /// Operation timeout
    pub operation_timeout: Duration,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            max_scan_size: 10 * 1024 * 1024, // 10MB
            max_json_depth: 100,
            max_pattern_length: 1000,
            max_path_length: 4096,
            max_concurrent_ops: 100,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Global security limits
pub static LIMITS: Lazy<SecurityLimits> = Lazy::new(SecurityLimits::default);

/// Validate size constraints
pub fn check_size_limit(size: usize, limit: usize, name: &str) -> Result<(), String> {
    if size > limit {
        Err(format!("{} exceeds maximum size: {} > {}", name, size, limit))
    } else {
        Ok(())
    }
}

/// Validate JSON depth to prevent stack overflow
pub fn check_json_depth(value: &serde_json::Value, max_depth: usize) -> Result<(), String> {
    fn measure_depth(value: &serde_json::Value, current: usize, max: usize) -> Result<usize, String> {
        if current > max {
            return Err(format!("JSON depth exceeds maximum: {} > {}", current, max));
        }
        
        match value {
            serde_json::Value::Object(map) => {
                let mut max_child = current;
                for v in map.values() {
                    max_child = max_child.max(measure_depth(v, current + 1, max)?);
                }
                Ok(max_child)
            }
            serde_json::Value::Array(arr) => {
                let mut max_child = current;
                for v in arr {
                    max_child = max_child.max(measure_depth(v, current + 1, max)?);
                }
                Ok(max_child)
            }
            _ => Ok(current),
        }
    }
    
    measure_depth(value, 0, max_depth).map(|_| ())
}

/// Semaphore for limiting concurrent operations
pub struct ConcurrencyLimiter {
    semaphore: tokio::sync::Semaphore,
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: tokio::sync::Semaphore::new(max_concurrent),
        }
    }
    
    pub async fn acquire(&self) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
        self.semaphore.acquire().await
            .map_err(|_| "Failed to acquire concurrency permit".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_size_limits() {
        assert!(check_size_limit(100, 1000, "test").is_ok());
        assert!(check_size_limit(2000, 1000, "test").is_err());
    }
    
    #[test]
    fn test_json_depth_check() {
        // Shallow JSON
        let shallow = serde_json::json!({
            "a": 1,
            "b": [2, 3],
            "c": {"d": 4}
        });
        assert!(check_json_depth(&shallow, 10).is_ok());
        
        // Deep JSON
        let mut deep = serde_json::json!({});
        let mut current = &mut deep;
        for i in 0..20 {
            *current = serde_json::json!({ 
                format!("level{}", i): {} 
            });
            current = current.as_object_mut().unwrap()
                .values_mut().next().unwrap();
        }
        
        assert!(check_json_depth(&deep, 10).is_err());
        assert!(check_json_depth(&deep, 25).is_ok());
    }
    
    #[tokio::test]
    async fn test_concurrency_limiter() {
        let limiter = ConcurrencyLimiter::new(2);
        
        // Acquire two permits
        let _p1 = limiter.acquire().await.unwrap();
        let _p2 = limiter.acquire().await.unwrap();
        
        // Third should wait (we'll timeout to test)
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            limiter.acquire()
        ).await;
        
        assert!(result.is_err()); // Timed out waiting
    }
}