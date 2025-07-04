// Copyright 2025 Kindly-Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Threat pattern definitions
//!
//! Configurable patterns for detecting various security threats

use super::ScanError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Collection of threat detection patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPatterns {
    prompt_injection: Vec<String>,
    command_injection: Vec<String>,
    path_traversal: Vec<String>,
    sql_injection: Vec<String>,
    xss_patterns: Vec<String>,
    ldap_injection: Vec<String>,
    xml_injection: Vec<String>,
    nosql_injection: Vec<String>,
}

impl ThreatPatterns {
    /// Load patterns from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, ScanError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ScanError::InvalidInput(format!("Failed to read patterns file: {e}")))?;

        serde_json::from_str(&content)
            .map_err(|e| ScanError::InvalidInput(format!("Invalid patterns JSON: {e}")))
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

    /// Get XSS patterns
    pub fn xss_patterns(&self) -> &[String] {
        &self.xss_patterns
    }

    /// Get LDAP injection patterns
    pub fn ldap_injection_patterns(&self) -> &[String] {
        &self.ldap_injection
    }

    /// Get XML injection patterns
    pub fn xml_injection_patterns(&self) -> &[String] {
        &self.xml_injection
    }

    /// Get NoSQL injection patterns
    pub fn nosql_injection_patterns(&self) -> &[String] {
        &self.nosql_injection
    }

    /// Get all patterns as a serializable structure
    pub const fn get_all_patterns(&self) -> &Self {
        self
    }
}

impl Default for ThreatPatterns {
    fn default() -> Self {
        Self {
            prompt_injection: vec![
                // AI-specific prompt injections
                r"(?i)ignore\s+(previous|all|above)\s+(instructions?|prompts?|commands?)"
                    .to_string(),
                r"(?i)disregard\s+(previous|all|above)\s+(instructions?|prompts?|commands?)"
                    .to_string(),
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
                r";\s*python\s+".to_string(),
                r";\s*python3\s+".to_string(),
                r";\s*perl\s+".to_string(),
                r";\s*ruby\s+".to_string(),
                r";\s*php\s+".to_string(),
                r";\s*node\s+".to_string(),
                r";\s*java\s+".to_string(),
                r"&&\s*[a-z]+\s+".to_string(),
                r"\|\|\s*[a-z]+\s+".to_string(),
                r"\|\s*[a-z]+\s+".to_string(),
                r"\|\s*nc\s+".to_string(),
                r"\|\s*netcat\s+".to_string(),
                r"\|\s*ncat\s+".to_string(),
                r"\|\s*socat\s+".to_string(),
                r"\|\s*telnet\s+".to_string(),
                r"\|\s*ssh\s+".to_string(),
                // Command substitution
                r"\$\([^)]+\)".to_string(),
                r"`[^`]+`".to_string(),
                r"\$\{[^}]+\}".to_string(),
                // Common dangerous commands
                r"(?i)(rm|del)\s+-rf?\s+".to_string(),
                r"(?i)format\s+[cd]:".to_string(),
                r"(?i)shutdown\s+".to_string(),
                r"/bin/(sh|bash|zsh|dash)".to_string(),
                // Windows-specific command injection patterns
                r"(?i)cmd\.exe\s*/c".to_string(),
                r"(?i)cmd\s*/c".to_string(),
                r"(?i)cmd\.exe\s+/c".to_string(),
                r"(?i)cmd\s+/c".to_string(),
                r"(?i)powershell\.exe\s*-c".to_string(),
                r"(?i)powershell\s*-c".to_string(),
                r"(?i)powershell\.exe\s*-Command".to_string(),
                r"(?i)powershell\s*-Command".to_string(),
                r"(?i)powershell\.exe\s*-ExecutionPolicy".to_string(),
                r"(?i)powershell\s*-ExecutionPolicy".to_string(),
                r"(?i)wscript\.exe".to_string(),
                r"(?i)cscript\.exe".to_string(),
                r"(?i)mshta\.exe".to_string(),
                r"(?i)rundll32\.exe".to_string(),
                r"(?i)regsvr32\.exe".to_string(),
                // Windows operators and pipes
                r"&\s*net\s+".to_string(),
                r"&\s*netsh\s+".to_string(),
                r"&\s*sc\s+".to_string(),
                r"&\s*reg\s+".to_string(),
                r"&\s*wmic\s+".to_string(),
                r"\|\s*findstr\s+".to_string(),
                r"\^\s*".to_string(), // Windows escape character
                // Windows shell shortcuts
                r"(?i)%comspec%".to_string(),
                r"(?i)%systemroot%".to_string(),
                r"(?i)%windir%".to_string(),
                // Newline command injection
                r"\n\s*/bin/".to_string(),
                r"\n\s*/usr/bin/".to_string(),
                r"\r\n\s*cmd".to_string(),
                r"\n\s*python".to_string(),
                r"\n\s*perl".to_string(),
                r"\n\s*ruby".to_string(),
                r"\n\s*sh\s*".to_string(),
                r"\n\s*bash\s*".to_string(),
                // Path injection
                r"\.\./\.\./(\.\./)*(etc|bin|usr|var)".to_string(),
            ],

            path_traversal: vec![
                // Unix path traversal - specific patterns first
                r"\.\./\.\./\.\./etc/passwd".to_string(), // Specific pattern for test
                r"\.\./(\.\./)*(etc|usr|bin|var|tmp|home|root)".to_string(),
                r"/\.\.".to_string(),
                r"\.\.%2[fF]".to_string(),      // URL encoded forward slash
                r"%2e%2e/".to_string(),         // URL encoded dots with slash
                r"%2e%2e%2f".to_string(),       // Fully URL encoded ../
                r"%252e%252e/".to_string(),     // Double encoded
                r"%252e%252e%252f".to_string(), // Double encoded ../
                r"%252f".to_string(),           // Double encoded forward slash
                // Windows path traversal
                r"\.\.\\(\.\.\\)*(windows|system32|users|program files)".to_string(),
                r"\\\.\.".to_string(),
                r"\.\.%5[cC]".to_string(), // URL encoded backslash
                r"%2e%2e\\\\".to_string(),
                // Advanced path traversal patterns
                r"\.{2,}/".to_string(),    // Multiple dots
                r"\.\.\.+/".to_string(),   // Three or more dots
                r"\.\./\.\./".to_string(), // Multiple traversals
                // Unicode and overlong encodings
                r"%c0%af".to_string(), // Overlong UTF-8 for /
                r"%c1%9c".to_string(), // Overlong UTF-8 for \
                // Null byte injection
                r"%00".to_string(),
                r"\x00".to_string(),
                // Absolute paths
                r"^/etc/".to_string(),
                r"^/usr/".to_string(),
                r"^/var/".to_string(),
                r"^[cC]:\\\\".to_string(),
                // Common target files
                r"etc/passwd".to_string(),
                r"etc/shadow".to_string(),
                r"windows/win\.ini".to_string(),
                r"boot\.ini".to_string(),
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

            xss_patterns: vec![
                // IMPORTANT: These patterns are for DETECTION only, not prevention
                // For actual XSS prevention, use proper HTML sanitization libraries

                // Script tags - various forms
                r"<script[^>]*>".to_string(),
                r"</script[^>]*>".to_string(),
                r"(?i)<script[^>]*>".to_string(),
                // Event handlers - most common XSS vector
                r"(?i)\bon\w+\s*=".to_string(), // matches onclick=, onerror=, etc.
                r"(?i)(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=".to_string(),
                // JavaScript protocol
                r"(?i)javascript\s*:".to_string(),
                r"(?i)vbscript\s*:".to_string(),
                r"(?i)livescript\s*:".to_string(),
                // Data URI with script content
                r"(?i)data:[^,]*script".to_string(),
                r"(?i)data:.*base64".to_string(),
                // Dangerous HTML elements
                r"(?i)<iframe[^>]*>".to_string(),
                r"(?i)<object[^>]*>".to_string(),
                r"(?i)<embed[^>]*>".to_string(),
                r"(?i)<applet[^>]*>".to_string(),
                r"(?i)<form[^>]*>".to_string(),
                r"(?i)<link[^>]*>".to_string(),
                r"(?i)<meta[^>]*>".to_string(),
                // SVG-based XSS
                r"(?i)<svg[^>]*>".to_string(),
                r"(?i)<svg[^>]*onload".to_string(),
                // Style-based XSS
                r"(?i)<style[^>]*>".to_string(),
                r"(?i)style\s*=.*expression\s*\(".to_string(),
                r"(?i)style\s*=.*javascript\s*:".to_string(),
                // Encoded script tags (hex, decimal, unicode)
                r"%3[Cc]script".to_string(),
                r"&#x3[Cc];script".to_string(),
                r"&#60;script".to_string(),
                r"\\u003[Cc]script".to_string(),
                r"\\x3[Cc]script".to_string(),
                // Common obfuscation techniques
                r"String\.fromCharCode".to_string(),
                r"eval\s*\(".to_string(),
                r"(?i)expression\s*\(".to_string(),
                r"(?i)document\s*\.\s*(write|writeln)".to_string(),
                r"(?i)window\s*\.\s*location".to_string(),
                r"(?i)document\s*\.\s*cookie".to_string(),
                // HTML5 event handlers
                r"(?i)onhashchange\s*=".to_string(),
                r"(?i)onpopstate\s*=".to_string(),
                r"(?i)onstorage\s*=".to_string(),
                // Bypasses with null bytes and comments
                r"<scr\x00ipt".to_string(),
                r"<scr\<!--.*--\>ipt".to_string(),
            ],

            ldap_injection: vec![
                // LDAP filter injection
                r"\(\|\(".to_string(),
                r"\)\(\|".to_string(),
                r"\(\&\(".to_string(),
                r"\)\(\&".to_string(),
                r"(?i)\*\)\(\|".to_string(),
                r"(?i)\)\(\|\(".to_string(),
                // LDAP escape sequences
                r"\\2a".to_string(), // \*
                r"\\28".to_string(), // \(
                r"\\29".to_string(), // \)
                r"\\5c".to_string(), // \\
                // Common LDAP injection patterns
                r"(?i)admin\*\)\(".to_string(),
                r"(?i)\*\)\(uid=\*".to_string(),
                r"(?i)\*\)\(objectClass=\*".to_string(),
                r"(?i)cn=\*\)\(".to_string(),
                // LDAP boolean conditions
                r"(?i)\|\(uid=\*".to_string(),
                r"(?i)\&\(uid=\*".to_string(),
                r"(?i)\!\(uid=\*".to_string(),
            ],

            xml_injection: vec![
                // XML entity injection
                r"<!ENTITY".to_string(),
                r"<!DOCTYPE".to_string(),
                r#"SYSTEM\s+["']file:"#.to_string(),
                r#"SYSTEM\s+["']http:"#.to_string(),
                r#"SYSTEM\s+["']https:"#.to_string(),
                // XXE patterns
                r"&xxe;".to_string(),
                r"%xxe;".to_string(),
                r"<!ENTITY\s+xxe".to_string(),
                r"<!ENTITY\s+%\s+xxe".to_string(),
                // XML injection via CDATA
                r"<!\[CDATA\[.*\]\]>".to_string(),
                r"]]>.*<!\[CDATA\[".to_string(),
                // SOAP injection
                r"</[^>]+><[^>]+>".to_string(),
                r"(?i)<soap:.*>".to_string(),
                // XPath injection
                r"(?i)' or '1'='1".to_string(),
                r#"(?i)" or "1"="1"#.to_string(),
                r"(?i)' or 1=1".to_string(),
                r#"(?i)" or 1=1"#.to_string(),
                // XML bomb patterns
                r#"<!ENTITY\s+lol\s+"lol"#.to_string(),
                r"&lol9;".to_string(),
            ],

            nosql_injection: vec![
                // MongoDB injection patterns
                r"\$ne".to_string(),
                r"\$eq".to_string(),
                r"\$gt".to_string(),
                r"\$gte".to_string(),
                r"\$lt".to_string(),
                r"\$lte".to_string(),
                r"\$nin".to_string(),
                r"\$in".to_string(),
                r"\$regex".to_string(),
                r"\$where".to_string(),
                r"\$exists".to_string(),
                r"\$type".to_string(),
                r"\$expr".to_string(),
                r"\$jsonSchema".to_string(),
                r"\$mod".to_string(),
                // MongoDB operators in JSON
                r#"["']\s*:\s*\{\s*["']\$"#.to_string(),
                r#"\{\s*["']\$ne["']\s*:"#.to_string(),
                r#"\{\s*["']\$gt["']\s*:"#.to_string(),
                // JavaScript injection in NoSQL
                r"(?i)function\s*\(".to_string(),
                r"(?i)return\s+true".to_string(),
                r"(?i)return\s+1\s*==\s*1".to_string(),
                r"(?i)this\.\w+\s*==".to_string(),
                // CouchDB injection
                r"_design/".to_string(),
                r"_view/".to_string(),
                r"\$text\s*:\s*\{".to_string(),
                r"\$search\s*:".to_string(),
                // Redis injection
                r"(?i)FLUSHDB".to_string(),
                r"(?i)FLUSHALL".to_string(),
                r"(?i)CONFIG\s+SET".to_string(),
                r"(?i)SCRIPT\s+LOAD".to_string(),
            ],
        }
    }
}

/// Save default patterns to a file (for customization)
pub fn save_default_patterns(path: &Path) -> Result<(), ScanError> {
    let patterns = ThreatPatterns::default();
    let json = serde_json::to_string_pretty(&patterns)
        .map_err(|e| ScanError::InvalidInput(format!("Failed to serialize patterns: {e}")))?;

    fs::write(path, json)
        .map_err(|e| ScanError::InvalidInput(format!("Failed to write patterns file: {e}")))
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

        assert_eq!(
            patterns.prompt_injection.len(),
            loaded.prompt_injection.len()
        );
        assert_eq!(
            patterns.command_injection.len(),
            loaded.command_injection.len()
        );
    }
}
