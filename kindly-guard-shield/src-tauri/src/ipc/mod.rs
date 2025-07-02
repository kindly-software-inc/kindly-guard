use serde::{Deserialize, Serialize};
use tauri::{command, State, Window};
use tracing::{debug, error, info};

use crate::{
    core::{Severity, ShieldCore, Statistics, Threat, ThreatType},
    security::SecurityValidator,
    AppState,
};

pub mod shm;
pub mod factory;
pub mod platform;
pub mod benchmark;
pub mod client;

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> IpcResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

pub trait IpcHandlers {
    // Trait for organizing IPC handlers
}

#[command]
pub async fn show_shield(
    window: Window,
    state: State<'_, AppState>,
) -> Result<IpcResult<()>, String> {
    debug!("Showing shield window");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"show_shield") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    match window.show() {
        Ok(_) => {
            info!("Shield window shown");
            Ok(IpcResult::success(()))
        }
        Err(e) => {
            error!("Failed to show window: {}", e);
            Ok(IpcResult::error(format!("Failed to show window: {}", e)))
        }
    }
}

#[command]
pub async fn hide_shield(
    window: Window,
    state: State<'_, AppState>,
) -> Result<IpcResult<()>, String> {
    debug!("Hiding shield window");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"hide_shield") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    match window.hide() {
        Ok(_) => {
            info!("Shield window hidden");
            Ok(IpcResult::success(()))
        }
        Err(e) => {
            error!("Failed to hide window: {}", e);
            Ok(IpcResult::error(format!("Failed to hide window: {}", e)))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatUpdate {
    pub threat_type: String,
    pub severity: String,
    pub source: String,
    pub details: String,
    pub blocked: bool,
}

#[command]
pub async fn update_threats(
    threats: Vec<ThreatUpdate>,
    state: State<'_, AppState>,
) -> Result<IpcResult<()>, String> {
    debug!("Updating threats: {} threats", threats.len());
    
    // Validate request
    let json = serde_json::to_value(&threats)
        .map_err(|e| format!("Serialization error: {}", e))?;
    
    if let Err(e) = state.validator.validate_json(&json) {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    for threat_update in threats {
        let threat_type = match threat_update.threat_type.as_str() {
            "unicode_invisible" => ThreatType::UnicodeInvisible,
            "unicode_bidi" => ThreatType::UnicodeBiDi,
            "unicode_homoglyph" => ThreatType::UnicodeHomoglyph,
            "injection_attempt" => ThreatType::InjectionAttempt,
            "path_traversal" => ThreatType::PathTraversal,
            "suspicious_pattern" => ThreatType::SuspiciousPattern,
            "rate_limit_violation" => ThreatType::RateLimitViolation,
            _ => ThreatType::Unknown,
        };
        
        let severity = match threat_update.severity.as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Medium,
        };
        
        let threat = ShieldCore::create_threat(
            threat_type,
            severity,
            threat_update.source,
            threat_update.details,
            threat_update.blocked,
        );
        
        if let Err(e) = state.core.record_threat(threat) {
            error!("Failed to record threat: {}", e);
            return Ok(IpcResult::error(format!("Failed to record threat: {}", e)));
        }
    }
    
    info!("Recorded {} threats", threats.len());
    Ok(IpcResult::success(()))
}

#[command]
pub async fn get_statistics(
    state: State<'_, AppState>,
) -> Result<IpcResult<Statistics>, String> {
    debug!("Getting statistics");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"get_statistics") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    let stats = state.core.get_statistics();
    Ok(IpcResult::success(stats))
}

#[command]
pub async fn clear_threats(
    state: State<'_, AppState>,
) -> Result<IpcResult<()>, String> {
    debug!("Clearing threats");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"clear_threats") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    state.core.clear_threats();
    info!("Threats cleared");
    Ok(IpcResult::success(()))
}

#[command]
pub async fn toggle_protection(
    state: State<'_, AppState>,
) -> Result<IpcResult<bool>, String> {
    debug!("Toggling protection");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"toggle_protection") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    let new_state = state.core.toggle_protection();
    info!("Protection toggled to: {}", new_state);
    Ok(IpcResult::success(new_state))
}

#[command]
pub async fn get_protection_status(
    state: State<'_, AppState>,
) -> Result<IpcResult<bool>, String> {
    debug!("Getting protection status");
    
    // Validate request
    if let Err(e) = state.validator.validate_message(b"get_protection_status") {
        error!("Validation failed: {}", e);
        return Ok(IpcResult::error(format!("Security validation failed: {}", e)));
    }
    
    let status = state.core.is_protection_enabled();
    Ok(IpcResult::success(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ipc_result() {
        let success: IpcResult<String> = IpcResult::success("test".to_string());
        assert!(success.success);
        assert_eq!(success.data, Some("test".to_string()));
        assert!(success.error.is_none());
        
        let error: IpcResult<String> = IpcResult::error("error");
        assert!(!error.success);
        assert!(error.data.is_none());
        assert_eq!(error.error, Some("error".to_string()));
    }
    
    #[test]
    fn test_threat_update_parsing() {
        let update = ThreatUpdate {
            threat_type: "unicode_invisible".to_string(),
            severity: "high".to_string(),
            source: "test".to_string(),
            details: "Test threat".to_string(),
            blocked: true,
        };
        
        let json = serde_json::to_string(&update).unwrap();
        let parsed: ThreatUpdate = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.threat_type, update.threat_type);
        assert_eq!(parsed.severity, update.severity);
    }
}