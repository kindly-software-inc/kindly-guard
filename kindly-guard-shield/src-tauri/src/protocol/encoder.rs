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
use std::io::{Cursor, Write};

use byteorder::{LittleEndian, WriteBytesExt};

use crate::websocket::{WsMessage, WsCommand};
use super::{
    binary::*,
    traits::{ProtocolCodec, ProtocolError},
};

pub struct BinaryEncoder {
    sequence: u32,
    max_message_size: u32,
}

impl BinaryEncoder {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            max_message_size: 1024 * 1024, // 1MB
        }
    }
    
    pub fn encode_ws_message(&mut self, msg: &WsMessage) -> Result<Vec<u8>, ProtocolError> {
        let binary_msg = match msg {
            WsMessage::Threat { threats } => {
                let compact_threats: Vec<CompactThreat> = threats
                    .iter()
                    .map(CompactThreat::from_threat)
                    .collect();
                BinaryMessage::Threat { threats: compact_threats }
            }
            WsMessage::Status { protection_enabled, threats_blocked } => {
                BinaryMessage::Status {
                    protection_enabled: *protection_enabled,
                    threats_blocked: *threats_blocked,
                    threats_analyzed: 0, // TODO: Get from core
                }
            }
            WsMessage::Heartbeat => {
                BinaryMessage::Heartbeat { uptime_seconds: 0 } // TODO: Get actual uptime
            }
            WsMessage::Error { message } => {
                BinaryMessage::Error {
                    code: 0, // TODO: Error codes
                    message: message.clone(),
                }
            }
        };
        
        let mut buf = Vec::with_capacity(256);
        self.encode(&binary_msg, &mut buf)?;
        Ok(buf)
    }
    
    pub fn encode_ws_command(&mut self, cmd: &WsCommand) -> Result<Vec<u8>, ProtocolError> {
        let (cmd_type, params) = match cmd {
            WsCommand::Subscribe => (CMD_SUBSCRIBE, vec![]),
            WsCommand::Unsubscribe => (CMD_UNSUBSCRIBE, vec![]),
            WsCommand::GetStatus => (CMD_GET_STATUS, vec![]),
            WsCommand::ToggleProtection => (CMD_TOGGLE_PROTECTION, vec![]),
        };
        
        let binary_msg = BinaryMessage::Command { cmd_type, params };
        let mut buf = Vec::with_capacity(64);
        self.encode(&binary_msg, &mut buf)?;
        Ok(buf)
    }
    
    fn encode_payload(&self, msg: &BinaryMessage, writer: &mut dyn Write) -> Result<(), ProtocolError> {
        match msg {
            BinaryMessage::Threat { threats } => {
                writer.write_u16::<LittleEndian>(threats.len() as u16)?;
                for threat in threats {
                    threat.encode(writer)?;
                }
            }
            BinaryMessage::Status { protection_enabled, threats_blocked, threats_analyzed } => {
                writer.write_u8(if *protection_enabled { 1 } else { 0 })?;
                writer.write_u64::<LittleEndian>(*threats_blocked)?;
                writer.write_u64::<LittleEndian>(*threats_analyzed)?;
            }
            BinaryMessage::StatsDelta { threats_blocked_delta, threats_analyzed_delta, threat_type_deltas } => {
                writer.write_i32::<LittleEndian>(*threats_blocked_delta)?;
                writer.write_i32::<LittleEndian>(*threats_analyzed_delta)?;
                for delta in threat_type_deltas {
                    writer.write_i16::<LittleEndian>(*delta)?;
                }
            }
            BinaryMessage::Heartbeat { uptime_seconds } => {
                writer.write_u64::<LittleEndian>(*uptime_seconds)?;
            }
            BinaryMessage::Error { code, message } => {
                writer.write_u16::<LittleEndian>(*code)?;
                let msg_bytes = message.as_bytes();
                writer.write_u16::<LittleEndian>(msg_bytes.len() as u16)?;
                writer.write_all(msg_bytes)?;
            }
            BinaryMessage::Command { cmd_type, params } => {
                writer.write_u8(*cmd_type)?;
                writer.write_u16::<LittleEndian>(params.len() as u16)?;
                writer.write_all(params)?;
            }
        }
        Ok(())
    }
    
    fn get_message_type(msg: &BinaryMessage) -> u8 {
        match msg {
            BinaryMessage::Threat { .. } => MSG_TYPE_THREAT,
            BinaryMessage::Status { .. } => MSG_TYPE_STATUS,
            BinaryMessage::StatsDelta { .. } => MSG_TYPE_STATS_DELTA,
            BinaryMessage::Heartbeat { .. } => MSG_TYPE_HEARTBEAT,
            BinaryMessage::Error { .. } => MSG_TYPE_ERROR,
            BinaryMessage::Command { .. } => MSG_TYPE_COMMAND,
        }
    }
}

impl ProtocolCodec for BinaryEncoder {
    type Message = BinaryMessage;
    
    fn encode(&self, msg: &Self::Message, buf: &mut Vec<u8>) -> Result<usize, ProtocolError> {
        // First encode payload to get size
        let mut payload = Vec::new();
        self.encode_payload(msg, &mut payload)?;
        
        let payload_size = payload.len() as u16;
        if payload.len() > self.max_message_size as usize {
            return Err(ProtocolError::MessageTooLarge {
                size: payload.len() as u32,
                max: self.max_message_size,
            });
        }
        
        // Create header
        let header = MessageHeader::new(
            Self::get_message_type(msg),
            payload_size,
            self.sequence,
        );
        
        // Write header and payload
        let mut cursor = Cursor::new(buf);
        header.encode(&mut cursor)?;
        cursor.write_all(&payload)?;
        
        let written = cursor.position() as usize;
        Ok(written)
    }
    
    fn decode(&self, _buf: &[u8]) -> Result<(Self::Message, usize), ProtocolError> {
        // Encoder doesn't decode
        unimplemented!("Use BinaryDecoder for decoding")
    }
    
    fn version(&self) -> u8 {
        super::PROTOCOL_VERSION_BINARY
    }
    
    fn is_complete_message(&self, buf: &[u8]) -> bool {
        if buf.len() < HEADER_SIZE {
            return false;
        }
        
        // Read payload size from header
        let payload_size = u16::from_le_bytes([buf[6], buf[7]]) as usize;
        buf.len() >= HEADER_SIZE + payload_size
    }
}

// Enhanced encoder with zero-copy optimizations
#[cfg(feature = "enhanced")]
pub struct EnhancedBinaryEncoder {
    standard: BinaryEncoder,
    // Reusable buffers for zero allocation
    header_buf: [u8; HEADER_SIZE],
    payload_buf: Vec<u8>,
}

#[cfg(feature = "enhanced")]
impl EnhancedBinaryEncoder {
    pub fn new() -> Self {
        Self {
            standard: BinaryEncoder::new(),
            header_buf: [0u8; HEADER_SIZE],
            payload_buf: Vec::with_capacity(4096),
        }
    }
    
    pub fn encode_zero_copy(&mut self, msg: &BinaryMessage, out: &mut [u8]) -> Result<usize, ProtocolError> {
        self.payload_buf.clear();
        self.standard.encode_payload(msg, &mut self.payload_buf)?;
        
        let payload_size = self.payload_buf.len();
        let total_size = HEADER_SIZE + payload_size;
        
        if out.len() < total_size {
            return Err(ProtocolError::InsufficientBuffer {
                need: total_size,
                have: out.len(),
            });
        }
        
        // Write header directly to output buffer
        let header = MessageHeader::new(
            BinaryEncoder::get_message_type(msg),
            payload_size as u16,
            self.standard.sequence,
        );
        
        let mut cursor = Cursor::new(&mut self.header_buf[..]);
        header.encode(&mut cursor)?;
        
        out[..HEADER_SIZE].copy_from_slice(&self.header_buf);
        out[HEADER_SIZE..total_size].copy_from_slice(&self.payload_buf);
        
        Ok(total_size)
    }
}