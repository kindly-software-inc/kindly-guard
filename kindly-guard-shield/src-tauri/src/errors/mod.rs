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
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("WebSocket connection error: {0}")]
    WebSocketError(String),
    
    #[error("IPC validation failed: {0}")]
    IpcValidationError(String),
    
    #[error("Security validation failed: {0}")]
    SecurityError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("State management error: {0}")]
    StateError(String),
    
    #[error("System tray error: {0}")]
    TrayError(String),
    
    #[error("Notification error: {0}")]
    NotificationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Shared memory error: {0}")]
    Io(String),
    
    #[error("Lock acquisition failed: {0}")]
    Lock(String),
    
    #[error("Platform-specific error: {0}")]
    Platform(String),
    
    #[error("Capacity exceeded: {0}")]
    Capacity(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Tauri error: {0}")]
    TauriError(#[from] tauri::Error),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

// For IPC communication
impl Serialize for ShieldError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ErrorResponse {
            error: String,
            code: String,
        }
        
        let response = ErrorResponse {
            error: self.to_string(),
            code: match self {
                Self::WebSocketError(_) => "WEBSOCKET_ERROR",
                Self::IpcValidationError(_) => "IPC_VALIDATION_ERROR",
                Self::SecurityError(_) => "SECURITY_ERROR",
                Self::ConfigError(_) => "CONFIG_ERROR",
                Self::StateError(_) => "STATE_ERROR",
                Self::TrayError(_) => "TRAY_ERROR",
                Self::NotificationError(_) => "NOTIFICATION_ERROR",
                Self::IoError(_) => "IO_ERROR",
                Self::SerializationError(_) => "SERIALIZATION_ERROR",
                Self::Io(_) => "SHM_IO_ERROR",
                Self::Lock(_) => "LOCK_ERROR",
                Self::Platform(_) => "PLATFORM_ERROR",
                Self::Capacity(_) => "CAPACITY_ERROR",
                Self::Validation(_) => "VALIDATION_ERROR",
                Self::TauriError(_) => "TAURI_ERROR",
                Self::Unknown(_) => "UNKNOWN_ERROR",
            }.to_string(),
        };
        
        response.serialize(serializer)
    }
}

pub type Result<T> = std::result::Result<T, ShieldError>;