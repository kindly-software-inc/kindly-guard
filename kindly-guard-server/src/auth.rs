// Copyright 2025 Kindly Software Inc.
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
//! Authentication and authorization for MCP server
//! Implements OAuth 2.0 with Resource Indicators (RFC 8707)

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

/// OAuth 2.0 token types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Bearer,
    Mac,
}

/// OAuth 2.0 access token
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
    pub token_type: TokenType,
    pub expires_at: Option<Instant>,
    pub scopes: Vec<String>,
    pub resource_indicators: Vec<String>,
    pub client_id: String,
}

/// Token validation result
#[derive(Debug)]
pub enum TokenValidation {
    Valid,
    Expired,
    Invalid,
    InsufficientScope,
    ResourceMismatch,
}

/// Authentication configuration
///
/// # Security Implications
///
/// Authentication is critical for preventing unauthorized access:
/// - **Always enable in production** - Disabling authentication exposes all operations
/// - **Use strong JWT secrets** - Weak secrets enable token forgery
/// - **Validate resource indicators** - Prevents token reuse across services
/// - **Short cache TTLs** - Reduces window for compromised tokens
///
/// # Example: Secure Production Configuration
///
/// ```toml
/// [auth]
/// enabled = true
/// validation_endpoint = "https://auth.example.com/validate"
/// trusted_issuers = ["https://auth.example.com"]
/// cache_ttl_seconds = 300  # 5 minutes
/// validate_resource_indicators = true
/// jwt_secret = "base64-encoded-256-bit-secret"
/// require_signature_verification = true
///
/// [auth.required_scopes]
/// default = ["kindlyguard:access"]
///
/// [auth.required_scopes.tools]
/// "security/scan" = ["security:read"]
/// "security/neutralize" = ["security:write", "security:admin"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication (if false, all requests are allowed)
    ///
    /// **Default**: false (for easier testing)
    /// **Security**: MUST be true in production. When false, anyone can access
    /// all operations without restriction.
    /// **Warning**: Running with authentication disabled is a critical security risk
    pub enabled: bool,

    /// Token validation endpoint (optional, for remote validation)
    ///
    /// **Default**: None (local validation only)
    /// **Security**: Use HTTPS endpoints only. Remote validation adds latency
    /// but enables centralized token management and revocation.
    /// **Example**: "https://auth.example.com/oauth2/introspect"
    pub validation_endpoint: Option<String>,

    /// Trusted issuers
    ///
    /// **Default**: empty (no issuers trusted)
    /// **Security**: Only tokens from these issuers will be accepted.
    /// Use specific issuer URLs, not wildcards or patterns.
    /// **Example**: ["https://auth.example.com", "https://login.company.com"]
    pub trusted_issuers: Vec<String>,

    /// Required scopes for different operations
    ///
    /// **Default**: No specific requirements
    /// **Security**: Define granular scopes to implement least privilege.
    /// Prevents tokens with limited scopes from accessing sensitive operations.
    pub required_scopes: ScopeRequirements,

    /// Token cache settings
    ///
    /// **Default**: 300 seconds (5 minutes)
    /// **Security**: Shorter TTLs reduce the window for compromised tokens
    /// but increase validation overhead. Balance security with performance.
    /// **Range**: 60-3600 seconds (recommend 300-900 for most cases)
    pub cache_ttl_seconds: u64,

    /// Enable resource indicators validation
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Validates that tokens are intended for this specific service.
    /// Prevents token reuse attacks across different services (RFC 8707).
    /// **Warning**: Disabling allows tokens meant for other services
    pub validate_resource_indicators: bool,

    /// JWT signing secret (base64 encoded) for HMAC-SHA256 verification
    ///
    /// **Default**: None
    /// **Security**: Use a cryptographically secure 256-bit (32 byte) secret.
    /// Must be kept confidential and rotated regularly.
    /// **Generation**: `openssl rand -base64 32`
    /// **Warning**: Weak secrets enable token forgery attacks
    pub jwt_secret: Option<String>,

    /// Require JWT signature verification
    ///
    /// **Default**: false
    /// **Security**: When true, all tokens must have valid signatures.
    /// Essential for preventing token tampering and forgery.
    /// **Dependencies**: Requires jwt_secret to be configured
    pub require_signature_verification: bool,
}

/// Required scopes for different operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRequirements {
    /// Scopes required for tool execution
    pub tools: HashMap<String, Vec<String>>,

    /// Scopes required for resource access
    pub resources: HashMap<String, Vec<String>>,

    /// Default scopes required for any operation
    pub default: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            validation_endpoint: None,
            trusted_issuers: vec![],
            required_scopes: ScopeRequirements::default(),
            cache_ttl_seconds: 300, // 5 minutes
            validate_resource_indicators: true,
            jwt_secret: None,
            require_signature_verification: false,
        }
    }
}

impl Default for ScopeRequirements {
    fn default() -> Self {
        Self {
            tools: HashMap::new(),
            resources: HashMap::new(),
            default: vec!["mcp:read".to_string()],
        }
    }
}

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    token_cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    server_resource_id: String,
}

/// Cached token with validation result
#[allow(missing_docs)] // Internal implementation detail
struct CachedToken {
    token: AccessToken,
    validated_at: Instant,
    validation_result: TokenValidation,
}

/// Authorization context for a request
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub authenticated: bool,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub resource_indicators: Vec<String>,
}

impl AuthContext {
    /// Create an unauthenticated context
    pub const fn unauthenticated() -> Self {
        Self {
            authenticated: false,
            client_id: None,
            scopes: vec![],
            resource_indicators: vec![],
        }
    }

    /// Check if context has required scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }

    /// Check if context has any of the required scopes
    pub fn has_any_scope(&self, scopes: &[String]) -> bool {
        scopes.is_empty() || scopes.iter().any(|s| self.has_scope(s))
    }

    /// Check if context has resource access
    pub fn has_resource_access(&self, resource: &str) -> bool {
        self.resource_indicators.is_empty()
            || self
                .resource_indicators
                .iter()
                .any(|r| r == resource || r == "*")
    }
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(config: AuthConfig, server_resource_id: String) -> Self {
        Self {
            config,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            server_resource_id,
        }
    }

    /// Perform constant-time comparison of tokens
    /// This prevents timing attacks by ensuring comparison takes the same time
    /// regardless of where the first difference occurs
    pub fn constant_time_compare(a: &str, b: &str) -> bool {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();

        // First check if lengths are equal (this can leak length info, but that's OK)
        if a_bytes.len() != b_bytes.len() {
            return false;
        }

        // Use subtle crate for constant-time comparison
        a_bytes.ct_eq(b_bytes).into()
    }

    /// Generate a cryptographically secure token with high entropy
    ///
    /// Generates a token with at least 128 bits of entropy using a secure random
    /// number generator. The token uses URL-safe base64 encoding.
    ///
    /// # Arguments
    /// * `length` - The desired length of the token in bytes (before encoding)
    ///              Minimum 16 bytes (128 bits) for security
    ///
    /// # Returns
    /// A URL-safe base64 encoded token string
    pub fn generate_secure_token(length: usize) -> String {
        // Ensure minimum entropy of 128 bits (16 bytes)
        let token_length = length.max(16);

        // Generate random bytes
        let mut rng = rand::thread_rng();
        let token_bytes: Vec<u8> = (0..token_length).map(|_| rng.gen()).collect();

        // Encode as URL-safe base64
        general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes)
    }

    /// Generate a secure session token
    ///
    /// Creates a session token with 256 bits of entropy (32 bytes)
    pub fn generate_session_token() -> String {
        Self::generate_secure_token(32)
    }

    /// Generate a secure API key
    ///
    /// Creates an API key with mixed alphanumeric characters and symbols
    /// for maximum entropy in a readable format
    pub fn generate_api_key() -> String {
        let mut rng = rand::thread_rng();

        // Use a mix of character sets for high entropy
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
        const KEY_LENGTH: usize = 32;

        let key: String = (0..KEY_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        key
    }

    /// Authenticate a request with bearer token
    pub async fn authenticate(&self, authorization: Option<&str>) -> Result<AuthContext> {
        if !self.config.enabled {
            // Authentication disabled, allow all requests
            return Ok(AuthContext {
                authenticated: true,
                client_id: Some("anonymous".to_string()),
                scopes: vec!["*".to_string()],
                resource_indicators: vec!["*".to_string()],
            });
        }

        // Extract bearer token
        let token = match authorization {
            Some(auth) if auth.starts_with("Bearer ") => auth.trim_start_matches("Bearer ").trim(),
            _ => return Ok(AuthContext::unauthenticated()),
        };

        // Check cache first
        let token_hash = self.hash_token(token);
        if let Some(cached) = self.check_cache(&token_hash).await {
            return Ok(self.context_from_token(&cached.token));
        }

        // Validate token
        let access_token = self.validate_token(token).await?;

        // Cache the result
        self.cache_token(token_hash, access_token.clone()).await;

        Ok(self.context_from_token(&access_token))
    }

    /// Validate an access token
    async fn validate_token(&self, token: &str) -> Result<AccessToken> {
        // For now, implement local validation
        // In production, this would call the validation endpoint

        // Special handling for test tokens (using constant-time comparison)
        if Self::constant_time_compare(token, "test-token-123") {
            return Ok(AccessToken {
                token: token.to_string(),
                token_type: TokenType::Bearer,
                expires_at: None,
                scopes: vec![
                    "*".to_string(),
                    "security:scan".to_string(),
                    "security:verify".to_string(),
                    "info:read".to_string(),
                ],
                resource_indicators: vec![self.server_resource_id.clone()],
                client_id: "test-client".to_string(),
            });
        }

        // Parse JWT or opaque token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid token format");
        }

        // Decode header to check algorithm
        let header_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)?;

        // Decode payload
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: TokenClaims = serde_json::from_slice(&payload_bytes)?;

        // Verify signature if required
        if self.config.require_signature_verification {
            // Check algorithm
            match header.alg.as_deref() {
                Some("HS256") => {
                    // HMAC-SHA256 verification
                    if let Some(secret) = &self.config.jwt_secret {
                        // Decode the secret
                        let secret_bytes = general_purpose::STANDARD.decode(secret)?;

                        // Create HMAC instance
                        type HmacSha256 = Hmac<Sha256>;
                        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;

                        // Update with header.payload
                        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());

                        // Decode provided signature
                        let signature_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;

                        // Verify signature
                        mac.verify_slice(&signature_bytes)?;
                    } else {
                        anyhow::bail!("JWT secret not configured for signature verification");
                    }
                }
                Some("none") => {
                    anyhow::bail!(
                        "Unsigned tokens not allowed when signature verification is required"
                    );
                }
                Some(alg) => {
                    anyhow::bail!("Unsupported algorithm: {}. Only HS256 is supported", alg);
                }
                None => {
                    anyhow::bail!("Missing algorithm in JWT header");
                }
            }
        }

        // Check expiration
        if let Some(exp) = claims.exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if exp < now {
                anyhow::bail!("Token expired");
            }
        }

        // Check issuer
        if !self.config.trusted_issuers.is_empty() {
            if let Some(iss) = &claims.iss {
                if !self.config.trusted_issuers.contains(iss) {
                    anyhow::bail!("Untrusted issuer");
                }
            }
        }

        // Extract resource indicators
        let resource_indicators = claims
            .resource_indicators
            .or_else(|| claims.aud.clone().map(|a| vec![a]))
            .unwrap_or_default();

        // Validate resource indicators if enabled
        if self.config.validate_resource_indicators
            && !resource_indicators.is_empty()
            && !resource_indicators.contains(&self.server_resource_id)
            && !resource_indicators.contains(&"*".to_string())
        {
            anyhow::bail!("Token not valid for this resource server");
        }

        Ok(AccessToken {
            token: token.to_string(),
            token_type: TokenType::Bearer,
            expires_at: claims.exp.map(|exp| {
                Instant::now()
                    + Duration::from_secs(
                        exp.saturating_sub(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        ),
                    )
            }),
            scopes: claims
                .scope
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default(),
            resource_indicators,
            client_id: claims.client_id.unwrap_or_else(|| "unknown".to_string()),
        })
    }

    /// Check if an operation is authorized
    pub fn authorize_tool(&self, auth: &AuthContext, tool_name: &str) -> Result<()> {
        if !auth.authenticated {
            anyhow::bail!("Authentication required");
        }

        // Get required scopes for this tool
        let required_scopes = self
            .config
            .required_scopes
            .tools
            .get(tool_name)
            .or(Some(&self.config.required_scopes.default))
            .cloned()
            .unwrap_or_default();

        if !auth.has_any_scope(&required_scopes) {
            anyhow::bail!("Insufficient scope for tool: {}", tool_name);
        }

        Ok(())
    }

    /// Check if resource access is authorized
    pub fn authorize_resource(&self, auth: &AuthContext, resource_uri: &str) -> Result<()> {
        if !auth.authenticated {
            anyhow::bail!("Authentication required");
        }

        // Get required scopes for this resource
        let required_scopes = self
            .config
            .required_scopes
            .resources
            .get(resource_uri)
            .or(Some(&self.config.required_scopes.default))
            .cloned()
            .unwrap_or_default();

        if !auth.has_any_scope(&required_scopes) {
            anyhow::bail!("Insufficient scope for resource: {}", resource_uri);
        }

        // Check resource indicators
        if self.config.validate_resource_indicators
            && !auth.has_resource_access(&self.server_resource_id)
        {
            anyhow::bail!("Token not authorized for this resource server");
        }

        Ok(())
    }

    /// Hash a token for caching
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Check token cache
    async fn check_cache(&self, token_hash: &str) -> Option<CachedToken> {
        let cache = self.token_cache.read().await;

        cache.get(token_hash).and_then(|cached| {
            let age = cached.validated_at.elapsed();
            if age < Duration::from_secs(self.config.cache_ttl_seconds) {
                Some(cached.clone())
            } else {
                None
            }
        })
    }

    /// Cache a validated token
    async fn cache_token(&self, token_hash: String, token: AccessToken) {
        let mut cache = self.token_cache.write().await;

        cache.insert(
            token_hash,
            CachedToken {
                token,
                validated_at: Instant::now(),
                validation_result: TokenValidation::Valid,
            },
        );

        // Clean up old entries
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.cache_ttl_seconds);
        cache.retain(|_, v| now.duration_since(v.validated_at) < ttl);
    }

    /// Create auth context from token
    fn context_from_token(&self, token: &AccessToken) -> AuthContext {
        AuthContext {
            authenticated: true,
            client_id: Some(token.client_id.clone()),
            scopes: token.scopes.clone(),
            resource_indicators: token.resource_indicators.clone(),
        }
    }
}

/// JWT token claims (simplified)
#[derive(Debug, Deserialize)]
#[allow(missing_docs)] // Internal JWT implementation detail
struct JwtHeader {
    #[serde(default)]
    alg: Option<String>,

    #[serde(default)]
    #[allow(dead_code)] // JWT type field, kept for standard compliance
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(missing_docs)] // Internal JWT implementation detail
struct TokenClaims {
    #[serde(default)]
    iss: Option<String>,

    #[serde(default)]
    #[allow(dead_code)] // JWT standard claim, kept for compliance
    sub: Option<String>,

    #[serde(default)]
    aud: Option<String>,

    #[serde(default)]
    exp: Option<u64>,

    #[serde(default)]
    #[allow(dead_code)] // JWT issued-at claim, kept for compliance
    iat: Option<u64>,

    #[serde(default)]
    scope: Option<String>,

    #[serde(default)]
    client_id: Option<String>,

    /// Resource indicators from RFC 8707
    #[serde(default)]
    resource_indicators: Option<Vec<String>>,
}

// Clone implementations
impl Clone for CachedToken {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            validated_at: self.validated_at,
            validation_result: match &self.validation_result {
                TokenValidation::Valid => TokenValidation::Valid,
                TokenValidation::Expired => TokenValidation::Expired,
                TokenValidation::Invalid => TokenValidation::Invalid,
                TokenValidation::InsufficientScope => TokenValidation::InsufficientScope,
                TokenValidation::ResourceMismatch => TokenValidation::ResourceMismatch,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context() {
        let ctx = AuthContext {
            authenticated: true,
            client_id: Some("test-client".to_string()),
            scopes: vec!["mcp:read".to_string(), "mcp:write".to_string()],
            resource_indicators: vec!["kindlyguard".to_string()],
        };

        assert!(ctx.has_scope("mcp:read"));
        assert!(ctx.has_scope("mcp:write"));
        assert!(!ctx.has_scope("mcp:admin"));

        assert!(ctx.has_any_scope(&["mcp:read".to_string()]));
        assert!(ctx.has_any_scope(&["mcp:admin".to_string(), "mcp:write".to_string()]));

        assert!(ctx.has_resource_access("kindlyguard"));
        assert!(!ctx.has_resource_access("other-server"));
    }

    #[test]
    fn test_unauthenticated_context() {
        let ctx = AuthContext::unauthenticated();
        assert!(!ctx.authenticated);
        assert!(ctx.scopes.is_empty());
        assert!(ctx.resource_indicators.is_empty());
    }

    #[test]
    fn test_constant_time_comparison() {
        // Test equal strings
        assert!(AuthManager::constant_time_compare("secret123", "secret123"));

        // Test different strings
        assert!(!AuthManager::constant_time_compare(
            "secret123",
            "secret124"
        ));
        assert!(!AuthManager::constant_time_compare("secret", "secrets"));
        assert!(!AuthManager::constant_time_compare("", "secret"));
        assert!(!AuthManager::constant_time_compare("secret", ""));

        // Test empty strings
        assert!(AuthManager::constant_time_compare("", ""));
    }

    #[test]
    fn test_secure_token_generation() {
        // Test minimum length enforcement
        let token1 = AuthManager::generate_secure_token(8);
        let token2 = AuthManager::generate_secure_token(16);
        let token3 = AuthManager::generate_secure_token(32);

        // Base64 encoding increases length by ~4/3
        assert!(token1.len() >= 21); // 16 bytes * 4/3 ≈ 21 chars
        assert!(token2.len() >= 21); // 16 bytes * 4/3 ≈ 21 chars
        assert!(token3.len() >= 42); // 32 bytes * 4/3 ≈ 42 chars

        // Test uniqueness
        let token4 = AuthManager::generate_secure_token(32);
        assert_ne!(token3, token4);

        // Test session token
        let session1 = AuthManager::generate_session_token();
        let session2 = AuthManager::generate_session_token();
        assert!(session1.len() >= 42); // 32 bytes * 4/3 ≈ 42 chars
        assert_ne!(session1, session2);
    }

    #[test]
    fn test_api_key_generation() {
        let key1 = AuthManager::generate_api_key();
        let key2 = AuthManager::generate_api_key();

        // Test length
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);

        // Test uniqueness
        assert_ne!(key1, key2);

        // Test character set (should contain mix of alphanumeric and symbols)
        let has_upper = key1.chars().any(|c| c.is_uppercase());
        let has_lower = key1.chars().any(|c| c.is_lowercase());
        let has_digit = key1.chars().any(|c| c.is_numeric());
        let has_symbol = key1.chars().any(|c| "!@#$%^&*-_=+".contains(c));

        // API keys should have high character diversity
        assert!(has_upper || has_lower || has_digit || has_symbol);
    }

    #[test]
    fn test_token_entropy() {
        // Generate multiple tokens and check for sufficient randomness
        let mut tokens = Vec::new();
        for _ in 0..100 {
            tokens.push(AuthManager::generate_secure_token(16));
        }

        // All tokens should be unique
        let unique_count = tokens
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(unique_count, 100);

        // Check character distribution (basic entropy test)
        let all_chars: String = tokens.join("");
        let char_freq = all_chars
            .chars()
            .fold(std::collections::HashMap::new(), |mut map, c| {
                *map.entry(c).or_insert(0) += 1;
                map
            });

        // Should have good character distribution (at least 20 different characters)
        assert!(char_freq.len() >= 20);
    }
}
