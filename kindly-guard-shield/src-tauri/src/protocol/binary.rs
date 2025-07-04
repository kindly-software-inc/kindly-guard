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
use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};

use crate::core::{Severity, Threat, ThreatType};
use super::{ProtocolError, PROTOCOL_MAGIC};

// Message type constants (4 bits)
pub const MSG_TYPE_THREAT: u8 = 0x01;
pub const MSG_TYPE_STATUS: u8 = 0x02;
pub const MSG_TYPE_HEARTBEAT: u8 = 0x03;
pub const MSG_TYPE_ERROR: u8 = 0x04;
pub const MSG_TYPE_COMMAND: u8 = 0x05;
pub const MSG_TYPE_STATS_DELTA: u8 = 0x06;

// Command type constants
pub const CMD_SUBSCRIBE: u8 = 0x01;
pub const CMD_UNSUBSCRIBE: u8 = 0x02;
pub const CMD_GET_STATUS: u8 = 0x03;
pub const CMD_TOGGLE_PROTECTION: u8 = 0x04;

// Threat type bit flags (for efficient encoding)
pub const THREAT_FLAG_UNICODE_INVISIBLE: u8 = 1 << 0;
pub const THREAT_FLAG_UNICODE_BIDI: u8 = 1 << 1;
pub const THREAT_FLAG_UNICODE_HOMOGLYPH: u8 = 1 << 2;
pub const THREAT_FLAG_INJECTION: u8 = 1 << 3;
pub const THREAT_FLAG_PATH_TRAVERSAL: u8 = 1 << 4;
pub const THREAT_FLAG_SUSPICIOUS: u8 = 1 << 5;
pub const THREAT_FLAG_RATE_LIMIT: u8 = 1 << 6;
pub const THREAT_FLAG_UNKNOWN: u8 = 1 << 7;

// Severity encoding (2 bits)
pub const SEVERITY_LOW: u8 = 0x00;
pub const SEVERITY_MEDIUM: u8 = 0x01;
pub const SEVERITY_HIGH: u8 = 0x02;
pub const SEVERITY_CRITICAL: u8 = 0x03;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub magic: [u8; 4],      // Magic bytes "KGSP"
    pub version: u8,          // Protocol version
    pub msg_type: u8,         // Message type (4 bits) + flags (4 bits)
    pub payload_size: u16,    // Payload size (little endian)
    pub sequence: u32,        // Message sequence number
    pub timestamp: u64,       // Unix timestamp in milliseconds
}

impl MessageHeader {
    pub fn new(msg_type: u8, payload_size: u16, sequence: u32) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        Self {
            magic: PROTOCOL_MAGIC,
            version: super::PROTOCOL_VERSION_BINARY,
            msg_type,
            payload_size,
            sequence,
            timestamp,
        }
    }
    
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        
        if self.version != super::PROTOCOL_VERSION_BINARY {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        
        Ok(())
    }
    
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_u8(self.version)?;
        writer.write_u8(self.msg_type)?;
        writer.write_u16::<LittleEndian>(self.payload_size)?;
        writer.write_u32::<LittleEndian>(self.sequence)?;
        writer.write_u64::<LittleEndian>(self.timestamp)?;
        Ok(())
    }
    
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        
        let version = reader.read_u8()?;
        let msg_type = reader.read_u8()?;
        let payload_size = reader.read_u16::<LittleEndian>()?;
        let sequence = reader.read_u32::<LittleEndian>()?;
        let timestamp = reader.read_u64::<LittleEndian>()?;
        
        let header = Self {
            magic,
            version,
            msg_type,
            payload_size,
            sequence,
            timestamp,
        };
        
        header.validate()?;
        Ok(header)
    }
}

pub const HEADER_SIZE: usize = 20; // 4 + 1 + 1 + 2 + 4 + 8

#[derive(Debug, Clone)]
pub enum BinaryMessage {
    Threat {
        threats: Vec<CompactThreat>,
    },
    Status {
        protection_enabled: bool,
        threats_blocked: u64,
        threats_analyzed: u64,
    },
    StatsDelta {
        threats_blocked_delta: i32,
        threats_analyzed_delta: i32,
        threat_type_deltas: [i16; 8],
    },
    Heartbeat {
        uptime_seconds: u64,
    },
    Error {
        code: u16,
        message: String,
    },
    Command {
        cmd_type: u8,
        params: Vec<u8>,
    },
}

/// Compact threat representation for efficient binary encoding
#[derive(Debug, Clone)]
pub struct CompactThreat {
    pub threat_flags: u8,     // Bit-packed threat types
    pub severity: u8,         // 2 bits severity + 6 bits reserved
    pub blocked: bool,
    pub source_len: u16,
    pub source: Vec<u8>,      // UTF-8 bytes
    pub details_len: u16,
    pub details: Vec<u8>,     // UTF-8 bytes
    pub timestamp: u64,       // Unix timestamp in milliseconds
}

impl CompactThreat {
    pub fn from_threat(threat: &Threat) -> Self {
        let threat_flags = match &threat.threat_type {
            ThreatType::UnicodeInvisible => THREAT_FLAG_UNICODE_INVISIBLE,
            ThreatType::UnicodeBiDi => THREAT_FLAG_UNICODE_BIDI,
            ThreatType::UnicodeHomoglyph => THREAT_FLAG_UNICODE_HOMOGLYPH,
            ThreatType::InjectionAttempt => THREAT_FLAG_INJECTION,
            ThreatType::PathTraversal => THREAT_FLAG_PATH_TRAVERSAL,
            ThreatType::SuspiciousPattern => THREAT_FLAG_SUSPICIOUS,
            ThreatType::RateLimitViolation => THREAT_FLAG_RATE_LIMIT,
            ThreatType::Unknown => THREAT_FLAG_UNKNOWN,
        };
        
        let severity = match threat.severity {
            Severity::Low => SEVERITY_LOW,
            Severity::Medium => SEVERITY_MEDIUM,
            Severity::High => SEVERITY_HIGH,
            Severity::Critical => SEVERITY_CRITICAL,
        };
        
        let source = threat.source.as_bytes().to_vec();
        let details = threat.details.as_bytes().to_vec();
        
        Self {
            threat_flags,
            severity,
            blocked: threat.blocked,
            source_len: source.len() as u16,
            source,
            details_len: details.len() as u16,
            details,
            timestamp: threat.timestamp.timestamp_millis() as u64,
        }
    }
    
    pub fn to_threat(&self, id: String) -> Result<Threat, ProtocolError> {
        let threat_type = match self.threat_flags {
            THREAT_FLAG_UNICODE_INVISIBLE => ThreatType::UnicodeInvisible,
            THREAT_FLAG_UNICODE_BIDI => ThreatType::UnicodeBiDi,
            THREAT_FLAG_UNICODE_HOMOGLYPH => ThreatType::UnicodeHomoglyph,
            THREAT_FLAG_INJECTION => ThreatType::InjectionAttempt,
            THREAT_FLAG_PATH_TRAVERSAL => ThreatType::PathTraversal,
            THREAT_FLAG_SUSPICIOUS => ThreatType::SuspiciousPattern,
            THREAT_FLAG_RATE_LIMIT => ThreatType::RateLimitViolation,
            _ => ThreatType::Unknown,
        };
        
        let severity = match self.severity & 0x03 {
            SEVERITY_LOW => Severity::Low,
            SEVERITY_MEDIUM => Severity::Medium,
            SEVERITY_HIGH => Severity::High,
            SEVERITY_CRITICAL => Severity::Critical,
            _ => Severity::Low,
        };
        
        let source = std::str::from_utf8(&self.source)?;
        let details = std::str::from_utf8(&self.details)?;
        
        let timestamp = DateTime::<Utc>::from_timestamp_millis(self.timestamp as i64)
            .unwrap_or_else(Utc::now);
        
        Ok(Threat {
            id,
            threat_type,
            severity,
            source: source.to_string(),
            details: details.to_string(),
            timestamp,
            blocked: self.blocked,
        })
    }
    
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u8(self.threat_flags)?;
        writer.write_u8(self.severity)?;
        writer.write_u8(if self.blocked { 1 } else { 0 })?;
        writer.write_u16::<LittleEndian>(self.source_len)?;
        writer.write_all(&self.source)?;
        writer.write_u16::<LittleEndian>(self.details_len)?;
        writer.write_all(&self.details)?;
        writer.write_u64::<LittleEndian>(self.timestamp)?;
        Ok(())
    }
    
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {
        let threat_flags = reader.read_u8()?;
        let severity = reader.read_u8()?;
        let blocked = reader.read_u8()? != 0;
        
        let source_len = reader.read_u16::<LittleEndian>()?;
        let mut source = vec![0u8; source_len as usize];
        reader.read_exact(&mut source)?;
        
        let details_len = reader.read_u16::<LittleEndian>()?;
        let mut details = vec![0u8; details_len as usize];
        reader.read_exact(&mut details)?;
        
        let timestamp = reader.read_u64::<LittleEndian>()?;
        
        Ok(Self {
            threat_flags,
            severity,
            blocked,
            source_len,
            source,
            details_len,
            details,
            timestamp,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProtocolVersion(pub u8);

impl ProtocolVersion {
    pub const JSON: Self = Self(1);
    pub const BINARY: Self = Self(2);
    
    pub fn is_binary(&self) -> bool {
        self.0 == Self::BINARY.0
    }
}