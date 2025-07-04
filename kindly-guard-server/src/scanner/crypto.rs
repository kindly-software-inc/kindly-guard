//! Cryptographic security scanner for detecting weak crypto patterns
//!
//! This module detects:
//! - Deprecated algorithms (MD5, SHA1, DES, etc.)
//! - Insecure random number generation
//! - Weak key sizes
//! - Insecure encryption modes (ECB)
//! - IV reuse patterns
//! - Bad key derivation practices

use crate::scanner::{Location, ScanResult, Severity, Threat, ThreatType};
use regex::Regex;
use tracing::{debug, trace, error};

#[derive(Debug, Clone)]
pub struct CryptoScanner {
    /// Patterns for deprecated hash algorithms
    deprecated_hash_patterns: Vec<Regex>,
    
    /// Patterns for weak encryption algorithms
    weak_encryption_patterns: Vec<Regex>,
    
    /// Patterns for insecure random number generation
    insecure_rng_patterns: Vec<Regex>,
    
    /// Patterns for weak key sizes
    weak_key_patterns: Vec<Regex>,
    
    /// Patterns for insecure encryption modes
    insecure_mode_patterns: Vec<Regex>,
    
    /// Patterns for bad key derivation
    bad_kdf_patterns: Vec<Regex>,
}

impl Default for CryptoScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoScanner {
    /// Helper function to compile regex patterns with error handling
    fn compile_patterns(patterns: &[&str]) -> Vec<Regex> {
        patterns
            .iter()
            .filter_map(|pattern| {
                match Regex::new(pattern) {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        error!("Failed to compile crypto scanner regex '{}': {}", pattern, e);
                        None
                    }
                }
            })
            .collect()
    }
    
    pub fn new() -> Self {
        // Initialize deprecated hash patterns
        let deprecated_hash_patterns = Self::compile_patterns(&[
            // MD5 usage
            r"(?i)\b(md5|Md5Hash|md5sum|MD5_)\b",
            r"(?i)use\s+md5(?:::|\s|;)",
            r"(?i)md5::compute",
            
            // SHA1 usage
            r"(?i)\b(sha1|Sha1|SHA1_|sha1sum)\b",
            r"(?i)use\s+sha1(?:::|\s|;)",
            r"(?i)sha1::Sha1",
            
            // MD4 usage
            r"(?i)\b(md4|Md4Hash|MD4_)\b",
            
            // Other deprecated hashes
            r"(?i)\b(md2|ripemd|RIPEMD)\b",
        ]);
        
        // Initialize weak encryption patterns
        let weak_encryption_patterns = Self::compile_patterns(&[
            // DES usage
            r"(?i)\b(des|DES|DesKey|des_key)\b",
            r"(?i)use\s+des(?:::|\s|;)",
            
            // 3DES (except when properly keyed)
            r"(?i)\b(3des|triple_?des|TDES)\b",
            
            // RC4 usage
            r"(?i)\b(rc4|RC4|arcfour)\b",
            
            // RC2 usage
            r"(?i)\b(rc2|RC2)\b",
            
            // Other weak ciphers
            r"(?i)\b(skipjack|blowfish|CAST5?)\b",
        ]);
        
        // Initialize insecure RNG patterns
        let insecure_rng_patterns = Self::compile_patterns(&[
            // Non-crypto RNG usage in crypto context
            r"(?i)(rand::random|thread_rng)\s*\(\s*\)",
            
            // Fastrand usage (not crypto secure)
            r"(?i)fastrand::",
            
            // Oorandom usage (not crypto secure)
            r"(?i)oorandom::",
            
            // Using system time as seed
            r"(?i)(SystemTime::now|time::now).*seed",
            
            // Predictable seeds
            r"(?i)seed\s*=\s*(\d+|0x[0-9a-fA-F]+)",
            
            // Non-crypto PRNGs
            r"(?i)\b(SmallRng|StdRng|Xorshift|Pcg32)\b.*(?:key|crypto|secure)",
        ]);
        
        // Initialize weak key size patterns
        let weak_key_patterns = Self::compile_patterns(&[
            // RSA with small keys
            r"(?i)rsa.*(?:512|768|1024)",
            r"(?i)RsaKeySize::Rsa(?:512|768|1024)",
            r"(?i)RsaPrivateKey::new.*1024",
            
            // ECC with small keys
            r"(?i)(?:ecc|ecdsa|ecdh).*(?:112|128|160|192)\s*(?:bit|_bit)",
            r"(?i)(?:P-?112|P-?128|P-?160|P-?192|secp112|secp128|secp160|secp192)",
            
            // AES with weak keys
            r"(?i)aes.*(?:64|80|96)\s*(?:bit|_bit)",
            
            // DH with small primes
            r"(?i)(?:dh|diffie).*(?:512|768|1024)\s*(?:bit|_bit)",
        ]);
        
        // Initialize insecure mode patterns
        let insecure_mode_patterns = Self::compile_patterns(&[
            // ECB mode usage
            r"(?i)\b(ecb|ECB|EcbMode|ecb_mode)\b",
            r#"(?i)mode\s*=\s*["']?ecb["']?"#,
            r#"(?i)cipher.*ecb"#,
            r#"(?i)encrypt_ecb"#,
            
            // Static IV usage
            r#"(?i)iv\s*=\s*(\[0(?:,\s*0)*\]|vec!\[0(?:;\s*\d+)?\])"#,
            r#"(?i)const\s+IV\s*:\s*\[u8"#,
            r#"(?i)static\s+IV\s*:\s*\[u8"#,
            
            // IV reuse patterns
            r#"(?i)self\.iv|cached_iv|reuse.*iv"#,
            
            // No IV usage with CBC
            r#"(?i)cbc.*encrypt.*\(\s*[^,)]+\s*\)"#,
        ]);
        
        // Initialize bad KDF patterns
        let bad_kdf_patterns = Self::compile_patterns(&[
            // Simple hashing for passwords
            r#"(?i)(sha256|sha512|md5|sha1)\s*\(\s*password"#,
            r#"(?i)(Sha256|Sha512|Md5|Sha1)::new\(\)"#,
            r#"(?i)hasher\.update\(password"#,
            
            // Low iteration counts for PBKDF2
            r#"(?i)pbkdf2.*iterations?\s*[=:]\s*(?:[1-9]\d{0,3}|10000)\b"#,
            
            // Missing salt - simplified pattern without lookahead
            r#"(?i)simple_hash_password\s*\("#,
            
            // Hardcoded salts
            r#"(?i)salt\s*=\s*["'][\w\s]+["']"#,
            r#"(?i)const\s+SALT\s*:\s*(?:&str|&\[u8\])"#,
        ]);
        
        Self {
            deprecated_hash_patterns,
            weak_encryption_patterns,
            insecure_rng_patterns,
            weak_key_patterns,
            insecure_mode_patterns,
            bad_kdf_patterns,
        }
    }
    
    fn check_deprecated_algorithms(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        let mut line_start = 0;
        
        for (_line_num, line) in text.lines().enumerate() {
            // Skip comments
            if line.trim_start().starts_with("//") {
                line_start += line.len() + 1; // +1 for newline
                continue;
            }
            
            // Check deprecated hash algorithms
            for pattern in &self.deprecated_hash_patterns {
                if let Some(m) = pattern.find(line) {
                    let algo = m.as_str();
                    let (name, recommendation) = if algo.to_lowercase().contains("md5") {
                        ("MD5", "Use SHA-256, SHA-3, or BLAKE3 instead")
                    } else if algo.to_lowercase().contains("sha1") {
                        ("SHA-1", "Use SHA-256, SHA-3, or BLAKE3 instead")
                    } else if algo.to_lowercase().contains("md4") {
                        ("MD4", "Use SHA-256, SHA-3, or BLAKE3 instead")
                    } else {
                        ("deprecated hash", "Use SHA-256, SHA-3, or BLAKE3 instead")
                    };
                    
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_deprecated_hash".to_string()),
                        severity: Severity::High,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: format!("Deprecated hash algorithm {} detected. {}", name, recommendation),
                        remediation: Some(recommendation.to_string()),
                    });
                }
            }
            
            // Check weak encryption algorithms
            for pattern in &self.weak_encryption_patterns {
                if let Some(m) = pattern.find(line) {
                    let algo = m.as_str();
                    let (name, recommendation) = if algo.to_lowercase().contains("des") {
                        ("DES/3DES", "Use AES-256-GCM or ChaCha20-Poly1305")
                    } else if algo.to_lowercase().contains("rc4") {
                        ("RC4", "Use AES-256-GCM or ChaCha20-Poly1305")
                    } else {
                        ("weak cipher", "Use AES-256-GCM or ChaCha20-Poly1305")
                    };
                    
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_weak_cipher".to_string()),
                        severity: Severity::Critical,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: format!("Weak encryption algorithm {} detected. {}", name, recommendation),
                        remediation: Some(recommendation.to_string()),
                    });
                }
            }
            
            line_start += line.len() + 1; // +1 for newline
        }
        
        threats
    }
    
    fn check_insecure_rng(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        
        // Check if this looks like crypto code
        let is_crypto_context = text.contains("key") || text.contains("Key") || 
                               text.contains("encrypt") || text.contains("decrypt") ||
                               text.contains("hash") || text.contains("sign") ||
                               text.contains("nonce") || text.contains("salt") ||
                               text.contains("iv") || text.contains("IV");
        
        if !is_crypto_context {
            return threats;
        }
        
        let mut line_start = 0;
        
        for (_line_num, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                line_start += line.len() + 1;
                continue;
            }
            
            for pattern in &self.insecure_rng_patterns {
                if let Some(m) = pattern.find(line) {
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_insecure_rng".to_string()),
                        severity: Severity::Critical,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: "Insecure random number generation for cryptographic use. Use rand::rngs::OsRng or ring::rand::SystemRandom for cryptographic randomness".to_string(),
                        remediation: Some(
                            "Use rand::rngs::OsRng or ring::rand::SystemRandom for cryptographic randomness".to_string()
                        ),
                    });
                }
            }
            
            line_start += line.len() + 1;
        }
        
        threats
    }
    
    fn check_weak_key_sizes(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        let mut line_start = 0;
        
        for (_line_num, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                line_start += line.len() + 1;
                continue;
            }
            
            for pattern in &self.weak_key_patterns {
                if let Some(m) = pattern.find(line) {
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_weak_key_size".to_string()),
                        severity: Severity::High,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: "Weak key size detected - insufficient for 2025 standards. Use RSA-3072+, ECC P-256+, or AES-256 for 2025 compliance".to_string(),
                        remediation: Some(
                            "Use RSA-3072+, ECC P-256+, or AES-256 for 2025 compliance".to_string()
                        ),
                    });
                }
            }
            
            line_start += line.len() + 1;
        }
        
        threats
    }
    
    fn check_insecure_modes(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        let mut line_start = 0;
        
        for (_line_num, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                line_start += line.len() + 1;
                continue;
            }
            
            for pattern in &self.insecure_mode_patterns {
                if let Some(m) = pattern.find(line) {
                    let detail = m.as_str();
                    let (message, recommendation) = if detail.to_lowercase().contains("ecb") {
                        (
                            "ECB mode encryption is insecure - reveals patterns",
                            "Use authenticated encryption: AES-GCM, ChaCha20-Poly1305, or AES-GCM-SIV"
                        )
                    } else if detail.to_lowercase().contains("iv") {
                        (
                            "Static or reused IV detected - breaks semantic security",
                            "Generate a unique random IV for each encryption operation"
                        )
                    } else {
                        (
                            "Insecure encryption mode detected",
                            "Use authenticated encryption modes"
                        )
                    };
                    
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_insecure_mode".to_string()),
                        severity: Severity::Critical,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: format!("{}. {}", message, recommendation),
                        remediation: Some(recommendation.to_string()),
                    });
                }
            }
            
            line_start += line.len() + 1;
        }
        
        threats
    }
    
    fn check_bad_kdf(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        
        // Don't flag if using proper KDF libraries
        let has_good_kdf = text.contains("argon2") || text.contains("Argon2") ||
                          text.contains("scrypt") || text.contains("bcrypt") ||
                          text.contains("pbkdf2") && text.contains("100000");
        
        let mut line_start = 0;
        
        for (_line_num, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                line_start += line.len() + 1;
                continue;
            }
            
            for pattern in &self.bad_kdf_patterns {
                if let Some(m) = pattern.find(line) {
                    // Skip if it's using a good KDF in the same line
                    if has_good_kdf && (line.contains("argon") || line.contains("scrypt") || line.contains("bcrypt")) {
                        continue;
                    }
                    
                    threats.push(Threat {
                        threat_type: ThreatType::Custom("crypto_bad_kdf".to_string()),
                        severity: Severity::High,
                        location: Location::Text {
                            offset: line_start + m.start(),
                            length: m.len(),
                        },
                        description: "Insecure key derivation detected. Use Argon2id, scrypt, or bcrypt with proper parameters for password hashing".to_string(),
                        remediation: Some(
                            "Use Argon2id, scrypt, or bcrypt with proper parameters for password hashing".to_string()
                        ),
                    });
                }
            }
            
            line_start += line.len() + 1;
        }
        
        threats
    }
    
    fn check_post_quantum_readiness(&self, text: &str) -> Vec<Threat> {
        let mut threats = Vec::new();
        
        // Check for RSA/ECC usage without migration plan
        let has_rsa = text.contains("RSA") || text.contains("rsa");
        let has_ecc = text.contains("ECC") || text.contains("ECDSA") || text.contains("ECDH");
        let has_pqc = text.contains("ML-KEM") || text.contains("ML-DSA") || 
                      text.contains("SPHINCS") || text.contains("Dilithium") || 
                      text.contains("Kyber") || text.contains("post-quantum") ||
                      text.contains("pqcrypto");
        
        if (has_rsa || has_ecc) && !has_pqc {
            threats.push(Threat {
                threat_type: ThreatType::Custom("crypto_no_pqc_plan".to_string()),
                severity: Severity::Medium,
                location: Location::Text {
                    offset: 0,
                    length: text.len(),
                },
                description: "No post-quantum cryptography migration detected. Plan migration to NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) by 2035".to_string(),
                remediation: Some(
                    "Plan migration to NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) by 2035".to_string()
                ),
            });
        }
        
        threats
    }
    
    pub fn scan_text(&self, text: &str) -> ScanResult {
        trace!("Starting cryptographic security scan");
        
        let mut all_threats = Vec::new();
        
        // Run all checks
        all_threats.extend(self.check_deprecated_algorithms(text));
        all_threats.extend(self.check_insecure_rng(text));
        all_threats.extend(self.check_weak_key_sizes(text));
        all_threats.extend(self.check_insecure_modes(text));
        all_threats.extend(self.check_bad_kdf(text));
        all_threats.extend(self.check_post_quantum_readiness(text));
        
        debug!("Crypto scan found {} threats", all_threats.len());
        
        Ok(all_threats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_md5() {
        let scanner = CryptoScanner::new();
        let code = r#"
use md5;

fn hash_password(password: &str) -> String {
    let digest = md5::compute(password);
    format!("{:x}", digest)
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(matches!(threats[0].threat_type, ThreatType::Custom(ref s) if s == "crypto_deprecated_hash"));
        assert!(threats[0].description.contains("MD5"));
    }
    
    #[test]
    fn test_detect_weak_rsa_key() {
        let scanner = CryptoScanner::new();
        let code = r#"
const RSA_KEY_SIZE: usize = 1024;

fn generate_rsa_key() {
    let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(matches!(threats[0].threat_type, ThreatType::Custom(ref s) if s == "crypto_weak_key_size"));
    }
    
    #[test]
    fn test_detect_ecb_mode() {
        let scanner = CryptoScanner::new();
        let code = r#"
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

fn encrypt_ecb(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).unwrap();
    // ECB mode encryption
    let mut output = data.to_vec();
    cipher.encrypt_block((&mut output).into());
    output
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::Custom(ref s) if s == "crypto_insecure_mode")));
    }
    
    #[test]
    fn test_detect_insecure_rng() {
        let scanner = CryptoScanner::new();
        let code = r#"
use rand::prelude::*;

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut key);
    key
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(matches!(threats[0].threat_type, ThreatType::Custom(ref s) if s == "crypto_insecure_rng"));
    }
    
    #[test]
    fn test_detect_static_iv() {
        let scanner = CryptoScanner::new();
        let code = r#"
const IV: [u8; 16] = [0; 16];

fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, &IV).unwrap();
    cipher.encrypt_vec(plaintext)
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(matches!(threats[0].threat_type, ThreatType::Custom(ref s) if s == "crypto_insecure_mode"));
        assert!(threats[0].description.contains("IV"));
    }
    
    #[test]
    fn test_detect_bad_password_hashing() {
        let scanner = CryptoScanner::new();
        let code = r#"
use sha2::{Sha256, Digest};

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password);
    format!("{:x}", hasher.finalize())
}
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        assert!(!threats.is_empty());
        assert!(matches!(threats[0].threat_type, ThreatType::Custom(ref s) if s == "crypto_bad_kdf"));
    }
    
    #[test]
    fn test_no_false_positives_for_secure_code() {
        let scanner = CryptoScanner::new();
        let code = r#"
use ring::rand::{SecureRandom, SystemRandom};
use argon2::{Argon2, PasswordHasher, PasswordHash, PasswordVerifier};

fn generate_secure_key() -> Result<[u8; 32], ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)?;
    Ok(key)
}

fn hash_password_secure(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

// Using AES-256-GCM for authenticated encryption
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
"#;
        
        let threats = scanner.scan_text(code).unwrap();
        // Should only potentially flag lack of PQC, not the secure implementations
        assert!(threats.iter().all(|t| {
            if let ThreatType::Custom(ref s) = t.threat_type {
                s != "crypto_insecure_rng" && s != "crypto_bad_kdf"
            } else {
                true
            }
        }));
    }
}