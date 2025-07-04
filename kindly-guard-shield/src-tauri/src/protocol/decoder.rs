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
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::websocket::{WsMessage, WsCommand};
use super::{
    binary::*,
    traits::{ProtocolCodec, ProtocolError},
};

pub struct BinaryDecoder {
    max_message_size: u32,
}

impl BinaryDecoder {
    pub fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
        }
    }
    
    pub fn decode_to_ws_message(&self, binary_msg: BinaryMessage) -> Result<WsMessage, ProtocolError> {
        match binary_msg {
            BinaryMessage::Threat { threats } => {
                let ws_threats: Result<Vec<_>, _> = threats
                    .into_iter()
                    .enumerate()
                    .map(|(i, ct)| ct.to_threat(format!("threat_{}", i)))
                    .collect();
                
                Ok(WsMessage::Threat { threats: ws_threats? })
            }
            BinaryMessage::Status { protection_enabled, threats_blocked, .. } => {
                Ok(WsMessage::Status { protection_enabled, threats_blocked })
            }
            BinaryMessage::Heartbeat { .. } => {
                Ok(WsMessage::Heartbeat)
            }
            BinaryMessage::Error { message, .. } => {
                Ok(WsMessage::Error { message })
            }
            _ => Err(ProtocolError::InvalidMessageType(0xFF)),
        }
    }
    
    pub fn decode_to_ws_command(&self, binary_msg: BinaryMessage) -> Result<WsCommand, ProtocolError> {
        match binary_msg {
            BinaryMessage::Command { cmd_type, .. } => {
                match cmd_type {
                    CMD_SUBSCRIBE => Ok(WsCommand::Subscribe),
                    CMD_UNSUBSCRIBE => Ok(WsCommand::Unsubscribe),
                    CMD_GET_STATUS => Ok(WsCommand::GetStatus),
                    CMD_TOGGLE_PROTECTION => Ok(WsCommand::ToggleProtection),
                    _ => Err(ProtocolError::InvalidMessageType(cmd_type)),
                }
            }
            _ => Err(ProtocolError::InvalidMessageType(0xFF)),
        }
    }
    
    fn decode_payload(&self, msg_type: u8, reader: &mut dyn Read) -> Result<BinaryMessage, ProtocolError> {
        match msg_type {
            MSG_TYPE_THREAT => {
                let count = reader.read_u16::<LittleEndian>()?;
                let mut threats = Vec::with_capacity(count as usize);
                
                for _ in 0..count {
                    threats.push(CompactThreat::decode(reader)?);
                }
                
                Ok(BinaryMessage::Threat { threats })
            }
            MSG_TYPE_STATUS => {
                let protection_enabled = reader.read_u8()? != 0;
                let threats_blocked = reader.read_u64::<LittleEndian>()?;
                let threats_analyzed = reader.read_u64::<LittleEndian>()?;
                
                Ok(BinaryMessage::Status {
                    protection_enabled,
                    threats_blocked,
                    threats_analyzed,
                })
            }
            MSG_TYPE_STATS_DELTA => {
                let threats_blocked_delta = reader.read_i32::<LittleEndian>()?;
                let threats_analyzed_delta = reader.read_i32::<LittleEndian>()?;
                let mut threat_type_deltas = [0i16; 8];
                
                for delta in &mut threat_type_deltas {
                    *delta = reader.read_i16::<LittleEndian>()?;
                }
                
                Ok(BinaryMessage::StatsDelta {
                    threats_blocked_delta,
                    threats_analyzed_delta,
                    threat_type_deltas,
                })
            }
            MSG_TYPE_HEARTBEAT => {
                let uptime_seconds = reader.read_u64::<LittleEndian>()?;
                Ok(BinaryMessage::Heartbeat { uptime_seconds })
            }
            MSG_TYPE_ERROR => {
                let code = reader.read_u16::<LittleEndian>()?;
                let msg_len = reader.read_u16::<LittleEndian>()?;
                let mut msg_bytes = vec![0u8; msg_len as usize];
                reader.read_exact(&mut msg_bytes)?;
                let message = std::str::from_utf8(&msg_bytes)?.to_string();
                
                Ok(BinaryMessage::Error { code, message })
            }
            MSG_TYPE_COMMAND => {
                let cmd_type = reader.read_u8()?;
                let params_len = reader.read_u16::<LittleEndian>()?;
                let mut params = vec![0u8; params_len as usize];
                reader.read_exact(&mut params)?;
                
                Ok(BinaryMessage::Command { cmd_type, params })
            }
            _ => Err(ProtocolError::InvalidMessageType(msg_type)),
        }
    }
}

impl ProtocolCodec for BinaryDecoder {
    type Message = BinaryMessage;
    
    fn encode(&self, _msg: &Self::Message, _buf: &mut Vec<u8>) -> Result<usize, ProtocolError> {
        // Decoder doesn't encode
        unimplemented!("Use BinaryEncoder for encoding")
    }
    
    fn decode(&self, buf: &[u8]) -> Result<(Self::Message, usize), ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::InsufficientBuffer {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }
        
        let mut cursor = Cursor::new(buf);
        let header = MessageHeader::decode(&mut cursor)?;
        
        let total_size = HEADER_SIZE + header.payload_size as usize;
        if buf.len() < total_size {
            return Err(ProtocolError::InsufficientBuffer {
                need: total_size,
                have: buf.len(),
            });
        }
        
        if header.payload_size as u32 > self.max_message_size {
            return Err(ProtocolError::MessageTooLarge {
                size: header.payload_size as u32,
                max: self.max_message_size,
            });
        }
        
        let msg = self.decode_payload(header.msg_type, &mut cursor)?;
        Ok((msg, total_size))
    }
    
    fn version(&self) -> u8 {
        super::PROTOCOL_VERSION_BINARY
    }
    
    fn is_complete_message(&self, buf: &[u8]) -> bool {
        if buf.len() < HEADER_SIZE {
            return false;
        }
        
        // Validate magic bytes
        if &buf[..4] != PROTOCOL_MAGIC {
            return false;
        }
        
        // Read payload size from header
        let payload_size = u16::from_le_bytes([buf[6], buf[7]]) as usize;
        buf.len() >= HEADER_SIZE + payload_size
    }
}

// Enhanced decoder with zero-copy string handling
#[cfg(feature = "enhanced")]
pub struct EnhancedBinaryDecoder {
    standard: BinaryDecoder,
}

#[cfg(feature = "enhanced")]
impl EnhancedBinaryDecoder {
    pub fn new() -> Self {
        Self {
            standard: BinaryDecoder::new(),
        }
    }
    
    /// Zero-copy decode that returns references to the original buffer where possible
    pub fn decode_zero_copy<'a>(&self, buf: &'a [u8]) -> Result<(BinaryMessageRef<'a>, usize), ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::InsufficientBuffer {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }
        
        let header = unsafe {
            // Safe because we verified buffer size
            std::ptr::read_unaligned(buf.as_ptr() as *const MessageHeader)
        };
        
        header.validate()?;
        
        let total_size = HEADER_SIZE + header.payload_size as usize;
        if buf.len() < total_size {
            return Err(ProtocolError::InsufficientBuffer {
                need: total_size,
                have: buf.len(),
            });
        }
        
        let payload = &buf[HEADER_SIZE..total_size];
        let msg_ref = self.decode_payload_zero_copy(header.msg_type, payload)?;
        
        Ok((msg_ref, total_size))
    }
    
    fn decode_payload_zero_copy<'a>(&self, msg_type: u8, payload: &'a [u8]) -> Result<BinaryMessageRef<'a>, ProtocolError> {
        // Implementation would return references to the original buffer
        // This is a placeholder for the actual zero-copy implementation
        unimplemented!("Zero-copy implementation requires lifetime management")
    }
}

// Zero-copy message reference (for enhanced mode)
#[cfg(feature = "enhanced")]
pub enum BinaryMessageRef<'a> {
    Threat {
        threats: Vec<CompactThreatRef<'a>>,
    },
    Status {
        protection_enabled: bool,
        threats_blocked: u64,
        threats_analyzed: u64,
    },
    Error {
        code: u16,
        message: &'a str,
    },
    // ... other variants
}

#[cfg(feature = "enhanced")]
pub struct CompactThreatRef<'a> {
    pub threat_flags: u8,
    pub severity: u8,
    pub blocked: bool,
    pub source: &'a str,
    pub details: &'a str,
    pub timestamp: u64,
}