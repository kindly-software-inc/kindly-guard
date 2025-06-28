//! Threat pattern definitions
//! 
//! Configurable patterns for detecting various security threats

use std::path::Path;
use std::fs;
use serde::{Deserialize, Serialize};
use super::ScanError;

/// Collection of threat detection patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPatterns {
    prompt_injection: Vec<String>,
    command_injection: Vec<String>,
    path_traversal: Vec<String>,
    sql_injection: Vec<String>,
}

impl ThreatPatterns {
    /// Load patterns from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, ScanError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ScanError::InvalidInput(format!("Failed to read patterns file: {}", e)))?;
            
        serde_json::from_str(&content)
            .map_err(|e| ScanError::InvalidInput(format!("Invalid patterns JSON: {}", e)))
    }
    
    /// Get prompt injection patterns
    pub fn prompt_injection_patterns(&self) -> &[String] {
        &self.prompt_injection
    }
    
    /// Get command injection patterns
    pub fn command_injection_patterns(&self) -> &[String] {
        &self.command_injection
    }
    
    /// Get path traversal patterns
    pub fn path_traversal_patterns(&self) -> &[String] {
        &self.path_traversal
    }
    
    /// Get SQL injection patterns
    pub fn sql_injection_patterns(&self) -> &[String] {
        &self.sql_injection
    }
    
    /// Get all patterns as a serializable structure
    pub fn get_all_patterns(&self) -> &ThreatPatterns {
        self
    }
}

impl Default for ThreatPatterns {
    fn default() -> Self {
        Self {
            prompt_injection: vec![
                // AI-specific prompt injections
                r"(?i)ignore\s+(previous|all|above)\s+(instructions?|prompts?|commands?)".to_string(),
                r"(?i)disregard\s+(previous|all|above)\s+(instructions?|prompts?|commands?)".to_string(),
                r"(?i)forget\s+(everything|all|previous)\s+(above|before)".to_string(),
                r"(?i)new\s+instructions?:\s*".to_string(),
                r"(?i)system\s*:\s*you\s+are".to_string(),
                r"(?i)pretend\s+you\s+are".to_string(),
                r"(?i)act\s+as\s+if\s+you".to_string(),
                r"(?i)roleplay\s+as".to_string(),
                r"(?i)you\s+are\s+now\s+in\s+developer\s+mode".to_string(),
                r"(?i)enable\s+developer\s+mode".to_string(),
                r"\[\[.*\]\]".to_string(), // Hidden instructions in brackets
                r"<system>.*</system>".to_string(), // Fake system tags
                r"(?i)simulation\s+mode".to_string(),
                r"(?i)testing\s+mode".to_string(),
            ],
            
            command_injection: vec![
                // Shell command separators
                r";\s*rm\s+".to_string(),
                r";\s*cat\s+".to_string(),
                r";\s*ls\s+".to_string(),
                r";\s*wget\s+".to_string(),
                r";\s*curl\s+".to_string(),
                r"&&\s*[a-z]+\s+".to_string(),
                r"\|\|\s*[a-z]+\s+".to_string(),
                r"\|\s*[a-z]+\s+".to_string(),
                
                // Command substitution
                r"\$\([^)]+\)".to_string(),
                r"`[^`]+`".to_string(),
                r"\$\{[^}]+\}".to_string(),
                
                // Common dangerous commands
                r"(?i)(rm|del)\s+-rf?\s+".to_string(),
                r"(?i)format\s+[cd]:".to_string(),
                r"(?i)shutdown\s+".to_string(),
                r"/bin/(sh|bash|zsh|dash)".to_string(),
                r"cmd\.exe".to_string(),
                r"powershell".to_string(),
                
                // Path injection
                r"\.\./\.\./(\.\./)*(etc|bin|usr|var)".to_string(),
            ],
            
            path_traversal: vec![
                // Unix path traversal
                r"\.\./(\.\./)*(etc|usr|bin|var|tmp|home|root)".to_string(),
                r"/\.\.".to_string(),
                r"\.\.%2[fF]".to_string(), // URL encoded
                r"%2e%2e/".to_string(),
                r"%252e%252e/".to_string(), // Double encoded
                
                // Windows path traversal
                r"\.\.\\(\.\.\\)*(windows|system32|users|program files)".to_string(),
                r"\\\.\.".to_string(),
                r"\.\.%5[cC]".to_string(), // URL encoded backslash
                r"%2e%2e\\\\".to_string(),
                
                // Null byte injection
                r"%00".to_string(),
                r"\x00".to_string(),
                
                // Absolute paths
                r"^/etc/".to_string(),
                r"^/usr/".to_string(),
                r"^/var/".to_string(),
                r"^[cC]:\\\\".to_string(),
            ],
            
            sql_injection: vec![
                // Classic SQL injection
                r"'\s*(OR|AND)\s*'?1'?\s*=\s*'?1".to_string(),
                r"'\s*(OR|AND)\s+[0-9]+\s*=\s*[0-9]+".to_string(),
                r"admin'\s*--".to_string(),
                r"'\s*OR\s*'[^']*'\s*=\s*'[^']*".to_string(),
                
                // Union-based
                r"(?i)union\s+(all\s+)?select".to_string(),
                r"(?i)union\s+distinct\s+select".to_string(),
                
                // Time-based
                r"(?i)sleep\s*\(\s*[0-9]+\s*\)".to_string(),
                r"(?i)waitfor\s+delay".to_string(),
                r"(?i)benchmark\s*\(".to_string(),
                
                // Error-based
                r"(?i)extractvalue\s*\(".to_string(),
                r"(?i)updatexml\s*\(".to_string(),
                r"(?i)xmltype\s*\(".to_string(),
                
                // Common SQL commands
                r"(?i)(drop|create|alter)\s+(table|database|schema|index)".to_string(),
                r"(?i)insert\s+into\s+".to_string(),
                r"(?i)delete\s+from\s+".to_string(),
                r"(?i)update\s+\w+\s+set".to_string(),
                
                // Comment syntax
                r"--\s*$".to_string(),
                r"/\*.*\*/".to_string(),
                r"#\s*$".to_string(),
                
                // Hex encoding
                r"0x[0-9a-fA-F]+".to_string(),
                
                // SQL functions that might be abused
                r"(?i)concat\s*\(".to_string(),
                r"(?i)char\s*\(".to_string(),
                r"(?i)load_file\s*\(".to_string(),
                r"(?i)into\s+outfile".to_string(),
            ],
        }
    }
}

/// Save default patterns to a file (for customization)
pub fn save_default_patterns(path: &Path) -> Result<(), ScanError> {
    let patterns = ThreatPatterns::default();
    let json = serde_json::to_string_pretty(&patterns)
        .map_err(|e| ScanError::InvalidInput(format!("Failed to serialize patterns: {}", e)))?;
        
    fs::write(path, json)
        .map_err(|e| ScanError::InvalidInput(format!("Failed to write patterns file: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_patterns() {
        let patterns = ThreatPatterns::default();
        assert!(!patterns.prompt_injection.is_empty());
        assert!(!patterns.command_injection.is_empty());
        assert!(!patterns.path_traversal.is_empty());
        assert!(!patterns.sql_injection.is_empty());
    }
    
    #[test]
    fn test_pattern_serialization() {
        let patterns = ThreatPatterns::default();
        let json = serde_json::to_string(&patterns).unwrap();
        let loaded: ThreatPatterns = serde_json::from_str(&json).unwrap();
        
        assert_eq!(patterns.prompt_injection.len(), loaded.prompt_injection.len());
        assert_eq!(patterns.command_injection.len(), loaded.command_injection.len());
    }
}