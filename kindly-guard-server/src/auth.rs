//! Authentication and authorization for MCP server
//! Implements OAuth 2.0 with Resource Indicators (RFC 8707)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication (if false, all requests are allowed)
    pub enabled: bool,
    
    /// Token validation endpoint (optional, for remote validation)
    pub validation_endpoint: Option<String>,
    
    /// Trusted issuers
    pub trusted_issuers: Vec<String>,
    
    /// Required scopes for different operations
    pub required_scopes: ScopeRequirements,
    
    /// Token cache settings
    pub cache_ttl_seconds: u64,
    
    /// Enable resource indicators validation
    pub validate_resource_indicators: bool,
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
    pub fn unauthenticated() -> Self {
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
        self.resource_indicators.is_empty() || 
        self.resource_indicators.iter().any(|r| r == resource || r == "*")
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
            Some(auth) if auth.starts_with("Bearer ") => {
                auth.trim_start_matches("Bearer ").trim()
            }
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
        
        // Parse JWT or opaque token
        // This is a simplified implementation
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid token format");
        }
        
        // Decode header and payload (simplified, no signature verification)
        use base64::{Engine as _, engine::general_purpose};
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: TokenClaims = serde_json::from_slice(&payload)?;
        
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
        let resource_indicators = claims.resource_indicators
            .or_else(|| claims.aud.clone().map(|a| vec![a]))
            .unwrap_or_default();
        
        // Validate resource indicators if enabled
        if self.config.validate_resource_indicators {
            if !resource_indicators.is_empty() && 
               !resource_indicators.contains(&self.server_resource_id) &&
               !resource_indicators.contains(&"*".to_string()) {
                anyhow::bail!("Token not valid for this resource server");
            }
        }
        
        Ok(AccessToken {
            token: token.to_string(),
            token_type: TokenType::Bearer,
            expires_at: claims.exp.map(|exp| {
                Instant::now() + Duration::from_secs(exp.saturating_sub(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                ))
            }),
            scopes: claims.scope
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
        let required_scopes = self.config.required_scopes.tools
            .get(tool_name)
            .or_else(|| Some(&self.config.required_scopes.default))
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
        let required_scopes = self.config.required_scopes.resources
            .get(resource_uri)
            .or_else(|| Some(&self.config.required_scopes.default))
            .cloned()
            .unwrap_or_default();
        
        if !auth.has_any_scope(&required_scopes) {
            anyhow::bail!("Insufficient scope for resource: {}", resource_uri);
        }
        
        // Check resource indicators
        if self.config.validate_resource_indicators {
            if !auth.has_resource_access(&self.server_resource_id) {
                anyhow::bail!("Token not authorized for this resource server");
            }
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
        
        cache.insert(token_hash, CachedToken {
            token,
            validated_at: Instant::now(),
            validation_result: TokenValidation::Valid,
        });
        
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
struct TokenClaims {
    #[serde(default)]
    iss: Option<String>,
    
    #[serde(default)]
    sub: Option<String>,
    
    #[serde(default)]
    aud: Option<String>,
    
    #[serde(default)]
    exp: Option<u64>,
    
    #[serde(default)]
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
}