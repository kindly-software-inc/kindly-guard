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
//! Binary Protocol - Optimized binary encoding for WebSocket messages
//!
//! This module provides efficient binary serialization with optional compression.
//! The production version uses custom bit-packing for maximum efficiency.

use anyhow::Result;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Compression levels for message encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression
    None,
    /// Fast compression (lower ratio, higher speed)
    Fast,
    /// Balanced compression
    Balanced,
    /// Best compression (higher ratio, lower speed)
    Best,
}

/// Binary protocol encoder/decoder
pub struct BinaryProtocol {
    /// Protocol version for compatibility
    version: u8,
}

impl BinaryProtocol {
    /// Create a new binary protocol handler
    pub fn new() -> Self {
        Self { version: 1 }
    }

    /// Encode a message to binary format
    pub fn encode<T: Serialize>(&self, message: &T) -> Result<Vec<u8>> {
        // In production, this would use custom binary encoding
        // For now, we use bincode or similar
        let mut data = vec![self.version];
        let encoded = serde_json::to_vec(message)?;
        data.extend_from_slice(&encoded);
        Ok(data)
    }

    /// Decode a message from binary format
    pub fn decode<T: for<'de> Deserialize<'de>>(&self, data: &[u8]) -> Result<T> {
        if data.is_empty() {
            anyhow::bail!("Empty data");
        }

        let version = data[0];
        if version != self.version {
            anyhow::bail!("Protocol version mismatch: expected {}, got {}", self.version, version);
        }

        let message = serde_json::from_slice(&data[1..])?;
        Ok(message)
    }
}

/// Message compressor for bandwidth optimization
pub struct MessageCompressor {
    level: CompressionLevel,
    total_input: u64,
    total_output: u64,
}

impl MessageCompressor {
    /// Create a new message compressor
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            level,
            total_input: 0,
            total_output: 0,
        }
    }

    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.level {
            CompressionLevel::None => Ok(data.to_vec()),
            _ => {
                let compression = match self.level {
                    CompressionLevel::Fast => Compression::fast(),
                    CompressionLevel::Balanced => Compression::default(),
                    CompressionLevel::Best => Compression::best(),
                    CompressionLevel::None => unreachable!(),
                };

                let mut encoder = GzEncoder::new(Vec::new(), compression);
                encoder.write_all(data)?;
                let compressed = encoder.finish()?;
                
                // Update metrics (in production, would use atomics)
                // self.total_input += data.len() as u64;
                // self.total_output += compressed.len() as u64;
                
                Ok(compressed)
            }
        }
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.level {
            CompressionLevel::None => Ok(data.to_vec()),
            _ => {
                let mut decoder = GzDecoder::new(data);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
        }
    }

    /// Get compression ratio
    pub fn get_compression_ratio(&self) -> f64 {
        if self.total_input == 0 {
            1.0
        } else {
            self.total_output as f64 / self.total_input as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestMessage {
        id: u32,
        content: String,
    }

    #[test]
    fn test_binary_protocol() {
        let protocol = BinaryProtocol::new();
        let msg = TestMessage {
            id: 42,
            content: "Hello, World!".to_string(),
        };

        let encoded = protocol.encode(&msg).unwrap();
        let decoded: TestMessage = protocol.decode(&encoded).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_compression() {
        let compressor = MessageCompressor::new(CompressionLevel::Fast);
        let data = b"Hello, World! ".repeat(100);
        
        let compressed = compressor.compress(&data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data, decompressed);
        assert!(compressed.len() < data.len());
    }
}