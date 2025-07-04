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
use std::fmt;
use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid magic bytes")]
    InvalidMagic,
    
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: u32, max: u32 },
    
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    
    #[error("Insufficient buffer size: need {need}, have {have}")]
    InsufficientBuffer { need: usize, have: usize },
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Trait for protocol encoding/decoding
pub trait ProtocolCodec: Send + Sync {
    type Message;
    
    /// Encode a message into a buffer
    fn encode(&self, msg: &Self::Message, buf: &mut Vec<u8>) -> Result<usize, ProtocolError>;
    
    /// Decode a message from a buffer (zero-copy when possible)
    fn decode(&self, buf: &[u8]) -> Result<(Self::Message, usize), ProtocolError>;
    
    /// Get the protocol version
    fn version(&self) -> u8;
    
    /// Check if a buffer contains a complete message
    fn is_complete_message(&self, buf: &[u8]) -> bool;
}

/// Protocol capabilities for negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub supports_binary: bool,
    pub supports_compression: bool,
    pub supports_delta_encoding: bool,
    pub max_message_size: u32,
}

impl Default for ProtocolCapabilities {
    fn default() -> Self {
        Self {
            supports_binary: true,
            supports_compression: false,
            supports_delta_encoding: true,
            max_message_size: 1024 * 1024, // 1MB
        }
    }
}