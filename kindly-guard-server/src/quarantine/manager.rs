//! Quarantine manager implementation

use super::*;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use regex::Regex;

/// Implementation of the quarantine system
pub struct QuarantineManager {
    config: QuarantineConfig,
    cipher: Arc<RwLock<ChaCha20Poly1305>>,
    entries: Arc<RwLock<HashMap<String, QuarantineEntry>>>,
    /// Cache of file checksums for integrity validation
    file_checksums: Arc<RwLock<HashMap<String, String>>>,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new(config: QuarantineConfig) -> Self {
        // Generate a key for encryption (in production, this should be stored securely)
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        
        Self {
            config,
            cipher: Arc::new(RwLock::new(cipher)),
            entries: Arc::new(RwLock::new(HashMap::new())),
            file_checksums: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Initialize the quarantine directory
    async fn init_directory(&self) -> Result<()> {
        fs::create_dir_all(&self.config.base_path)
            .await
            .context("Failed to create quarantine directory")?;
        Ok(())
    }
    
    /// Generate a hash for content
    fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Sanitize quarantine ID to prevent path traversal
    fn sanitize_id(id: &str) -> Result<String> {
        // Only allow alphanumeric characters and hyphens
        let id_regex = Regex::new(r"^[a-zA-Z0-9-]+$").unwrap();
        
        if !id_regex.is_match(id) {
            return Err(anyhow::anyhow!("Invalid quarantine ID format"));
        }
        
        // Additional check for path traversal patterns
        if id.contains("..") || id.contains("/") || id.contains("\\") {
            return Err(anyhow::anyhow!("Path traversal attempt detected"));
        }
        
        Ok(id.to_string())
    }
    
    /// Get secure file path within quarantine directory
    fn get_secure_path(&self, id: &str) -> Result<PathBuf> {
        let sanitized_id = Self::sanitize_id(id)?;
        
        // Use subdirectory structure to prevent conflicts
        // e.g., ab/cd/abcd-1234-5678-9012-345678901234
        let subdir = if sanitized_id.len() >= 4 {
            let prefix = &sanitized_id[..2];
            let suffix = &sanitized_id[2..4];
            self.config.base_path.join(prefix).join(suffix)
        } else {
            self.config.base_path.join("misc")
        };
        
        let file_path = subdir.join(&sanitized_id);
        
        // Ensure the resolved path is within the quarantine directory
        let canonical_base = self.config.base_path.canonicalize()
            .unwrap_or_else(|_| self.config.base_path.clone());
        let resolved_path = file_path.canonicalize()
            .unwrap_or_else(|_| file_path.clone());
        
        if !resolved_path.starts_with(&canonical_base) {
            return Err(anyhow::anyhow!("Path traversal detected"));
        }
        
        Ok(file_path)
    }
    
    /// Calculate file checksum for integrity validation
    fn calculate_file_checksum(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
    
    /// Validate file integrity against stored checksum
    async fn validate_integrity(&self, id: &str, data: &[u8]) -> Result<bool> {
        let checksums = self.file_checksums.read().await;
        if let Some(expected_checksum) = checksums.get(id) {
            let actual_checksum = Self::calculate_file_checksum(data);
            Ok(actual_checksum == *expected_checksum)
        } else {
            // No checksum stored, cannot validate
            Ok(false)
        }
    }
    
    /// Encrypt content if configured
    async fn encrypt_content(&self, content: &str) -> Result<Vec<u8>> {
        if !self.config.encrypt {
            return Ok(content.as_bytes().to_vec());
        }
        
        let cipher = self.cipher.read().await;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let encrypted = cipher
            .encrypt(&nonce, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        // Prepend nonce to encrypted data
        let mut result = nonce.to_vec();
        result.extend(encrypted);
        
        Ok(result)
    }
    
    /// Decrypt content if encrypted
    async fn decrypt_content(&self, data: &[u8]) -> Result<String> {
        if !self.config.encrypt {
            return Ok(String::from_utf8(data.to_vec())?);
        }
        
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }
        
        let (nonce_bytes, encrypted) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let cipher = self.cipher.read().await;
        let decrypted = cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        Ok(String::from_utf8(decrypted)?)
    }
    
    /// Compress content
    fn compress_content(content: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content)?;
        Ok(encoder.finish()?)
    }
    
    /// Decompress content
    fn decompress_content(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(Vec::new());
        decoder.write_all(data)?;
        Ok(decoder.finish()?)
    }
}

#[async_trait::async_trait]
impl Quarantine for QuarantineManager {
    async fn quarantine(
        &self,
        content: &str,
        threat_info: ThreatInfo,
        source: Option<String>,
    ) -> Result<String> {
        self.init_directory().await?;
        
        let id = Uuid::new_v4().to_string();
        let content_hash = Self::hash_content(content);
        let timestamp = SystemTime::now();
        
        // Create subdirectory structure for secure storage
        let file_path = self.get_secure_path(&id)?;
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await
                .context("Failed to create quarantine subdirectory")?;
        }
        
        // Create entry
        let entry = QuarantineEntry {
            id: id.clone(),
            original_content: content.to_string(),
            threat_info,
            source,
            quarantined_at: timestamp,
            compressed: false,
            size_bytes: content.len(),
            content_hash: content_hash.clone(),
        };
        
        // Save to disk
        let _entry_json = serde_json::to_vec(&entry)?;
        
        // Encrypt the serialized entry
        let encrypted = self.encrypt_content(&serde_json::to_string(&entry)?).await?;
        
        // Calculate checksum of encrypted data for integrity validation
        let checksum = Self::calculate_file_checksum(&encrypted);
        
        fs::write(&file_path, encrypted)
            .await
            .context("Failed to write quarantine file")?;
        
        // Update in-memory index and checksum cache
        self.entries.write().await.insert(id.clone(), entry);
        self.file_checksums.write().await.insert(id.clone(), checksum);
        
        Ok(id)
    }
    
    async fn retrieve(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        // Validate ID format first
        let sanitized_id = Self::sanitize_id(id)?;
        
        // Get secure file path
        let file_path = self.get_secure_path(&sanitized_id)?;
        if !file_path.exists() {
            return Ok(None);
        }
        
        // Load from disk
        let encrypted_data = fs::read(&file_path).await?;
        
        // Validate file integrity before using cached data
        let is_valid = self.validate_integrity(&sanitized_id, &encrypted_data).await?;
        
        // Check in-memory cache only if integrity is valid
        if is_valid {
            if let Some(entry) = self.entries.read().await.get(&sanitized_id) {
                return Ok(Some(entry.clone()));
            }
        } else {
            // Remove from cache if integrity check fails
            self.entries.write().await.remove(&sanitized_id);
            self.file_checksums.write().await.remove(&sanitized_id);
        }
        
        // Handle decompression if needed
        let data = if file_path.with_extension("gz").exists() {
            let compressed = fs::read(&file_path.with_extension("gz")).await?;
            Self::decompress_content(&compressed)?
        } else {
            encrypted_data
        };
        
        let decrypted = self.decrypt_content(&data).await?;
        let entry: QuarantineEntry = serde_json::from_str(&decrypted)?;
        
        // Update cache with validated entry
        self.entries.write().await.insert(sanitized_id.clone(), entry.clone());
        
        // Store/update checksum for future validations
        let checksum = Self::calculate_file_checksum(&data);
        self.file_checksums.write().await.insert(sanitized_id, checksum);
        
        Ok(Some(entry))
    }
    
    async fn list(&self, filter: QuarantineFilter) -> Result<Vec<QuarantineEntry>> {
        let mut entries = Vec::new();
        
        // Helper function to scan directory recursively
        async fn scan_dir(
            path: &Path,
            entries: &mut Vec<QuarantineEntry>,
            manager: &QuarantineManager,
            filter: &QuarantineFilter,
        ) -> Result<()> {
            if !path.exists() {
                return Ok(());
            }
            
            let mut dir = fs::read_dir(path).await?;
            while let Some(entry) = dir.next_entry().await? {
                let file_type = entry.file_type().await?;
                let entry_path = entry.path();
                
                if file_type.is_dir() {
                    // Recursively scan subdirectories
                    Box::pin(scan_dir(&entry_path, entries, manager, filter)).await?;
                } else if file_type.is_file() {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    // Skip compressed files and non-UUID files
                    if filename.ends_with(".gz") || filename.len() < 36 {
                        continue;
                    }
                    
                    // Try to retrieve the entry
                    if let Ok(Some(quarantine_entry)) = manager.retrieve(&filename).await {
                        // Apply filters
                        let matches = filter.start_time.is_none_or(|t| quarantine_entry.quarantined_at >= t)
                            && filter.end_time.is_none_or(|t| quarantine_entry.quarantined_at <= t)
                            && filter.threat_type.as_ref().is_none_or(|t| &quarantine_entry.threat_info.threat_type == t)
                            && filter.severity.as_ref().is_none_or(|s| &quarantine_entry.threat_info.severity == s)
                            && filter.source.as_ref().is_none_or(|s| quarantine_entry.source.as_ref() == Some(s));
                        
                        if matches {
                            entries.push(quarantine_entry);
                        }
                    }
                }
            }
            Ok(())
        }
        
        // Scan the quarantine directory recursively
        scan_dir(&self.config.base_path, &mut entries, self, &filter).await?;
        
        // Sort by timestamp (newest first)
        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        
        Ok(entries)
    }
    
    async fn delete(&self, id: &str) -> Result<bool> {
        // Validate ID format
        let sanitized_id = Self::sanitize_id(id)?;
        
        // Get secure file path
        let file_path = self.get_secure_path(&sanitized_id)?;
        if file_path.exists() {
            fs::remove_file(&file_path).await?;
            
            // Also check for compressed version
            let compressed_path = file_path.with_extension("gz");
            if compressed_path.exists() {
                fs::remove_file(&compressed_path).await?;
            }
            
            // Remove from caches
            self.entries.write().await.remove(&sanitized_id);
            self.file_checksums.write().await.remove(&sanitized_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    async fn apply_retention(&self) -> Result<RetentionStats> {
        let policy = RetentionPolicy {
            compress_after: Duration::from_secs(self.config.compress_after_days as u64 * 24 * 60 * 60),
            delete_after: Duration::from_secs(self.config.delete_after_days as u64 * 24 * 60 * 60),
            max_total_size: self.config.max_size_mb * 1024 * 1024,
        };
        
        let mut stats = RetentionStats {
            compressed: 0,
            deleted: 0,
            errors: 0,
        };
        
        let entries = self.list(QuarantineFilter::default()).await?;
        
        for entry in entries {
            // Check if should delete
            if policy.should_delete(entry.quarantined_at) {
                if let Err(e) = self.delete(&entry.id).await {
                    tracing::error!("Failed to delete quarantine entry {}: {}", entry.id, e);
                    stats.errors += 1;
                } else {
                    stats.deleted += 1;
                }
                continue;
            }
            
            // Check if should compress
            if !entry.compressed && policy.should_compress(entry.quarantined_at) {
                if let Ok(file_path) = self.get_secure_path(&entry.id) {
                    if let Ok(data) = fs::read(&file_path).await {
                        if let Ok(compressed) = Self::compress_content(&data) {
                            let compressed_path = file_path.with_extension("gz");
                            if let Err(e) = fs::write(&compressed_path, compressed).await {
                                tracing::error!("Failed to compress quarantine entry {}: {}", entry.id, e);
                                stats.errors += 1;
                            } else {
                                // Remove original
                                let _ = fs::remove_file(&file_path).await;
                                stats.compressed += 1;
                            }
                        }
                    }
                } else {
                    tracing::error!("Invalid quarantine ID format: {}", entry.id);
                    stats.errors += 1;
                }
            }
        }
        
        Ok(stats)
    }
}