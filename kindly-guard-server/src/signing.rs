//! Message signing and verification for secure MCP communication
//! Implements HMAC-SHA256 for message integrity and Ed25519 for authenticity

use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use base64::{Engine as _, engine::general_purpose};

type HmacSha256 = Hmac<Sha256>;

/// Signing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Enable message signing
    pub enabled: bool,
    
    /// Algorithm to use (hmac-sha256 or ed25519)
    pub algorithm: SigningAlgorithm,
    
    /// HMAC secret key (base64 encoded)
    pub hmac_secret: Option<String>,
    
    /// Ed25519 private key (base64 encoded)
    pub ed25519_private_key: Option<String>,
    
    /// Require signatures on incoming messages
    pub require_signatures: bool,
    
    /// Allow unsigned messages during grace period
    pub grace_period_seconds: u64,
    
    /// Include timestamp in signatures
    pub include_timestamp: bool,
    
    /// Maximum clock skew allowed (seconds)
    pub max_clock_skew_seconds: u64,
}

/// Signing algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    HmacSha256,
    Ed25519,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningAlgorithm::HmacSha256 => write!(f, "hmac-sha256"),
            SigningAlgorithm::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: SigningAlgorithm::HmacSha256,
            hmac_secret: None,
            ed25519_private_key: None,
            require_signatures: false,
            grace_period_seconds: 86400, // 24 hours
            include_timestamp: true,
            max_clock_skew_seconds: 300, // 5 minutes
        }
    }
}

/// Message signature with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSignature {
    /// Algorithm used
    pub algorithm: SigningAlgorithm,
    
    /// The signature value (base64)
    pub signature: String,
    
    /// Timestamp when signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    
    /// Key ID (for key rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// Signing key manager
pub struct SigningManager {
    config: SigningConfig,
    hmac_key: Option<Vec<u8>>,
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
    start_time: SystemTime,
}

/// Signed message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The original message
    pub message: serde_json::Value,
    
    /// Signature information
    pub signature: MessageSignature,
}

impl SigningManager {
    /// Create a new signing manager
    pub fn new(config: SigningConfig) -> Result<Self> {
        let mut hmac_key = None;
        let mut signing_key = None;
        let mut verifying_key = None;
        
        if config.enabled {
            match config.algorithm {
                SigningAlgorithm::HmacSha256 => {
                    if let Some(secret) = &config.hmac_secret {
                        let key = general_purpose::STANDARD
                            .decode(secret)
                            .context("Invalid HMAC secret base64")?;
                        if key.len() < 32 {
                            anyhow::bail!("HMAC secret must be at least 32 bytes");
                        }
                        hmac_key = Some(key);
                    } else {
                        anyhow::bail!("HMAC secret required when HMAC-SHA256 is enabled");
                    }
                }
                SigningAlgorithm::Ed25519 => {
                    if let Some(private_key) = &config.ed25519_private_key {
                        let key_bytes = general_purpose::STANDARD
                            .decode(private_key)
                            .context("Invalid Ed25519 private key base64")?;
                        
                        if key_bytes.len() != 32 {
                            anyhow::bail!("Ed25519 private key must be exactly 32 bytes");
                        }
                        
                        let key_array: [u8; 32] = match key_bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => anyhow::bail!("Failed to convert key bytes to array")
                        };
                        let secret = SigningKey::from_bytes(&key_array);
                        verifying_key = Some(secret.verifying_key());
                        signing_key = Some(secret);
                    } else {
                        anyhow::bail!("Ed25519 private key required when Ed25519 is enabled");
                    }
                }
            }
        }
        
        Ok(Self {
            config,
            hmac_key,
            signing_key,
            verifying_key,
            start_time: SystemTime::now(),
        })
    }
    
    /// Sign a message
    pub fn sign_message(&self, message: &serde_json::Value) -> Result<SignedMessage> {
        if !self.config.enabled {
            anyhow::bail!("Message signing is not enabled");
        }
        
        let timestamp = if self.config.include_timestamp {
            Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs())
        } else {
            None
        };
        
        // Create canonical message representation
        let canonical = self.canonicalize_message(message, timestamp)?;
        
        let signature_value = match self.config.algorithm {
            SigningAlgorithm::HmacSha256 => {
                let key = self.hmac_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("HMAC key not initialized"))?;
                
                let mut mac = HmacSha256::new_from_slice(key)?;
                mac.update(canonical.as_bytes());
                let result = mac.finalize();
                
                general_purpose::STANDARD.encode(result.into_bytes())
            }
            SigningAlgorithm::Ed25519 => {
                let signing_key = self.signing_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Ed25519 key not initialized"))?;
                
                let signature = signing_key.sign(canonical.as_bytes());
                general_purpose::STANDARD.encode(signature.to_bytes())
            }
        };
        
        Ok(SignedMessage {
            message: message.clone(),
            signature: MessageSignature {
                algorithm: self.config.algorithm.clone(),
                signature: signature_value,
                timestamp,
                key_id: None, // TODO: Implement key rotation
            },
        })
    }
    
    /// Verify a signed message
    pub fn verify_message(&self, signed: &SignedMessage) -> Result<()> {
        if !self.config.enabled {
            // If signing is disabled, accept all messages
            return Ok(());
        }
        
        // Check if we're in grace period
        if !self.config.require_signatures {
            let elapsed = SystemTime::now()
                .duration_since(self.start_time)?
                .as_secs();
            
            if elapsed < self.config.grace_period_seconds {
                // Still in grace period, accept unsigned
                return Ok(());
            }
        }
        
        // Verify timestamp if present
        if let Some(timestamp) = signed.signature.timestamp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            
            let time_diff = if timestamp > now {
                timestamp - now
            } else {
                now - timestamp
            };
            
            if time_diff > self.config.max_clock_skew_seconds {
                anyhow::bail!("Message timestamp outside acceptable range");
            }
        }
        
        // Check algorithm matches
        if signed.signature.algorithm != self.config.algorithm {
            anyhow::bail!("Signature algorithm mismatch");
        }
        
        // Create canonical representation
        let canonical = self.canonicalize_message(
            &signed.message,
            signed.signature.timestamp
        )?;
        
        // Verify signature
        match signed.signature.algorithm {
            SigningAlgorithm::HmacSha256 => {
                let key = self.hmac_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("HMAC key not initialized"))?;
                
                let mut mac = HmacSha256::new_from_slice(key)?;
                mac.update(canonical.as_bytes());
                
                let expected = general_purpose::STANDARD
                    .decode(&signed.signature.signature)?;
                
                mac.verify_slice(&expected)
                    .map_err(|_| anyhow::anyhow!("HMAC verification failed"))?;
            }
            SigningAlgorithm::Ed25519 => {
                let verifying_key = self.verifying_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Ed25519 verifying key not initialized"))?;
                
                let signature_bytes = general_purpose::STANDARD
                    .decode(&signed.signature.signature)?;
                
                let signature = Signature::from_slice(&signature_bytes)
                    .context("Invalid Ed25519 signature format")?;
                
                verifying_key.verify(canonical.as_bytes(), &signature)
                    .map_err(|_| anyhow::anyhow!("Ed25519 verification failed"))?;
            }
        }
        
        Ok(())
    }
    
    /// Create canonical message representation for signing
    fn canonicalize_message(&self, message: &serde_json::Value, timestamp: Option<u64>) -> Result<String> {
        // Create a deterministic representation
        let mut canonical = serde_json::to_string(message)?;
        
        if let Some(ts) = timestamp {
            canonical.push_str(&format!("|timestamp:{}", ts));
        }
        
        Ok(canonical)
    }
    
    /// Extract signature from authorization header
    pub fn extract_signature(authorization: &str) -> Option<MessageSignature> {
        // Format: "Signature algorithm=hmac-sha256,signature=base64,timestamp=123"
        if !authorization.starts_with("Signature ") {
            return None;
        }
        
        let parts = authorization.trim_start_matches("Signature ");
        let mut algorithm = None;
        let mut signature = None;
        let mut timestamp = None;
        let mut key_id = None;
        
        for part in parts.split(',') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            
            match kv[0] {
                "algorithm" => {
                    algorithm = match kv[1] {
                        "hmac-sha256" => Some(SigningAlgorithm::HmacSha256),
                        "ed25519" => Some(SigningAlgorithm::Ed25519),
                        _ => None,
                    };
                }
                "signature" => signature = Some(kv[1].to_string()),
                "timestamp" => timestamp = kv[1].parse().ok(),
                "keyid" => key_id = Some(kv[1].to_string()),
                _ => {}
            }
        }
        
        match (algorithm, signature) {
            (Some(alg), Some(sig)) => Some(MessageSignature {
                algorithm: alg,
                signature: sig,
                timestamp,
                key_id,
            }),
            _ => None,
        }
    }
    
    /// Create authorization header from signature
    pub fn create_auth_header(signature: &MessageSignature) -> String {
        let mut parts = vec![
            format!("algorithm={}", match signature.algorithm {
                SigningAlgorithm::HmacSha256 => "hmac-sha256",
                SigningAlgorithm::Ed25519 => "ed25519",
            }),
            format!("signature={}", signature.signature),
        ];
        
        if let Some(ts) = signature.timestamp {
            parts.push(format!("timestamp={}", ts));
        }
        
        if let Some(kid) = &signature.key_id {
            parts.push(format!("keyid={}", kid));
        }
        
        format!("Signature {}", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hmac_signing() {
        let config = SigningConfig {
            enabled: true,
            algorithm: SigningAlgorithm::HmacSha256,
            hmac_secret: Some(general_purpose::STANDARD.encode(b"FAKE-TEST-KEY-DO-NOT-USE-IN-PROD-32b")),
            include_timestamp: false,
            require_signatures: true,
            grace_period_seconds: 0, // No grace period
            ..Default::default()
        };
        
        let manager = SigningManager::new(config).unwrap();
        let message = serde_json::json!({"method": "test", "params": {}});
        
        let signed = manager.sign_message(&message).unwrap();
        assert_eq!(signed.signature.algorithm, SigningAlgorithm::HmacSha256);
        
        // Verify should succeed
        manager.verify_message(&signed).unwrap();
        
        // Tampered message should fail
        let mut tampered = signed.clone();
        tampered.message = serde_json::json!({"method": "tampered", "params": {}});
        assert!(manager.verify_message(&tampered).is_err());
    }
    
    #[test]
    fn test_ed25519_signing() {
        use rand::rngs::OsRng;
        
        // Generate a test key
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_base64 = general_purpose::STANDARD.encode(signing_key.to_bytes());
        
        let config = SigningConfig {
            enabled: true,
            algorithm: SigningAlgorithm::Ed25519,
            ed25519_private_key: Some(private_key_base64),
            include_timestamp: true,
            ..Default::default()
        };
        
        let manager = SigningManager::new(config).unwrap();
        let message = serde_json::json!({"method": "test", "params": {}});
        
        let signed = manager.sign_message(&message).unwrap();
        assert_eq!(signed.signature.algorithm, SigningAlgorithm::Ed25519);
        assert!(signed.signature.timestamp.is_some());
        
        // Verify should succeed
        manager.verify_message(&signed).unwrap();
    }
    
    #[test]
    fn test_signature_extraction() {
        let auth = "Signature algorithm=hmac-sha256,signature=abc123,timestamp=1234567890";
        let sig = SigningManager::extract_signature(auth).unwrap();
        
        assert_eq!(sig.algorithm, SigningAlgorithm::HmacSha256);
        assert_eq!(sig.signature, "abc123");
        assert_eq!(sig.timestamp, Some(1234567890));
    }
}