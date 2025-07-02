use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

use super::{
    traits::{ProtocolCapabilities, ProtocolCodec},
    ProtocolVersion,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NegotiationMessage {
    #[serde(rename = "hello")]
    Hello {
        version: u8,
        capabilities: ProtocolCapabilities,
    },
    #[serde(rename = "accept")]
    Accept {
        version: u8,
        capabilities: ProtocolCapabilities,
    },
    #[serde(rename = "reject")]
    Reject {
        reason: String,
        fallback_version: u8,
    },
}

pub struct ProtocolNegotiator {
    supported_versions: Vec<ProtocolVersion>,
    capabilities: ProtocolCapabilities,
}

impl ProtocolNegotiator {
    pub fn new() -> Self {
        Self {
            supported_versions: vec![
                ProtocolVersion::BINARY,
                ProtocolVersion::JSON,
            ],
            capabilities: ProtocolCapabilities::default(),
        }
    }
    
    pub fn with_capabilities(mut self, capabilities: ProtocolCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
    
    /// Initiate protocol negotiation (client side)
    pub fn create_hello(&self) -> Result<Message, Box<dyn std::error::Error>> {
        let hello = NegotiationMessage::Hello {
            version: ProtocolVersion::BINARY.0,
            capabilities: self.capabilities,
        };
        
        let json = serde_json::to_string(&hello)?;
        Ok(Message::Text(json))
    }
    
    /// Handle negotiation message (server side)
    pub fn handle_negotiation(&self, msg: &Message) -> Result<(Message, ProtocolVersion), Box<dyn std::error::Error>> {
        match msg {
            Message::Text(text) => {
                let negotiation: NegotiationMessage = serde_json::from_str(text)?;
                
                match negotiation {
                    NegotiationMessage::Hello { version, capabilities } => {
                        debug!("Received protocol hello: version={}, capabilities={:?}", version, capabilities);
                        
                        // Check if we support the requested version
                        let requested_version = ProtocolVersion(version);
                        if self.supported_versions.contains(&requested_version) {
                            // Check capabilities compatibility
                            if self.is_compatible(&capabilities) {
                                info!("Accepting protocol version {}", version);
                                
                                let accept = NegotiationMessage::Accept {
                                    version,
                                    capabilities: self.capabilities,
                                };
                                
                                let response = Message::Text(serde_json::to_string(&accept)?);
                                Ok((response, requested_version))
                            } else {
                                // Capabilities mismatch, fallback to JSON
                                let reject = NegotiationMessage::Reject {
                                    reason: "Capabilities mismatch".to_string(),
                                    fallback_version: ProtocolVersion::JSON.0,
                                };
                                
                                let response = Message::Text(serde_json::to_string(&reject)?);
                                Ok((response, ProtocolVersion::JSON))
                            }
                        } else {
                            // Version not supported, fallback to JSON
                            let reject = NegotiationMessage::Reject {
                                reason: format!("Version {} not supported", version),
                                fallback_version: ProtocolVersion::JSON.0,
                            };
                            
                            let response = Message::Text(serde_json::to_string(&reject)?);
                            Ok((response, ProtocolVersion::JSON))
                        }
                    }
                    _ => {
                        // Not a hello message, assume JSON protocol
                        Ok((Message::Text("".to_string()), ProtocolVersion::JSON))
                    }
                }
            }
            _ => {
                // Non-text message during negotiation, assume JSON
                Ok((Message::Text("".to_string()), ProtocolVersion::JSON))
            }
        }
    }
    
    /// Check if client capabilities are compatible with server
    fn is_compatible(&self, client_caps: &ProtocolCapabilities) -> bool {
        // For now, just check max message size
        client_caps.max_message_size <= self.capabilities.max_message_size
    }
    
    /// Parse negotiation response (client side)
    pub fn parse_response(&self, msg: &Message) -> Result<ProtocolVersion, Box<dyn std::error::Error>> {
        match msg {
            Message::Text(text) => {
                let negotiation: NegotiationMessage = serde_json::from_str(text)?;
                
                match negotiation {
                    NegotiationMessage::Accept { version, .. } => {
                        info!("Protocol negotiation accepted: version {}", version);
                        Ok(ProtocolVersion(version))
                    }
                    NegotiationMessage::Reject { reason, fallback_version } => {
                        info!("Protocol negotiation rejected: {}. Using version {}", reason, fallback_version);
                        Ok(ProtocolVersion(fallback_version))
                    }
                    _ => {
                        // Unexpected message, fallback to JSON
                        Ok(ProtocolVersion::JSON)
                    }
                }
            }
            _ => Ok(ProtocolVersion::JSON),
        }
    }
}

/// Protocol selection based on negotiation result
pub enum ProtocolSelection {
    Json,
    Binary {
        encoder: Arc<dyn ProtocolCodec<Message = super::binary::BinaryMessage>>,
        decoder: Arc<dyn ProtocolCodec<Message = super::binary::BinaryMessage>>,
    },
}

impl ProtocolSelection {
    pub fn from_version(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::BINARY => {
                #[cfg(feature = "enhanced")]
                {
                    Self::Binary {
                        encoder: Arc::new(super::encoder::EnhancedBinaryEncoder::new()),
                        decoder: Arc::new(super::decoder::EnhancedBinaryDecoder::new()),
                    }
                }
                
                #[cfg(not(feature = "enhanced"))]
                {
                    Self::Binary {
                        encoder: Arc::new(super::encoder::BinaryEncoder::new()),
                        decoder: Arc::new(super::decoder::BinaryDecoder::new()),
                    }
                }
            }
            _ => Self::Json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_negotiation_hello() {
        let negotiator = ProtocolNegotiator::new();
        let hello = negotiator.create_hello().unwrap();
        
        match hello {
            Message::Text(text) => {
                assert!(text.contains("\"type\":\"hello\""));
                assert!(text.contains("\"version\":2"));
            }
            _ => panic!("Expected text message"),
        }
    }
    
    #[test]
    fn test_version_compatibility() {
        let negotiator = ProtocolNegotiator::new();
        
        // Test compatible version
        let hello = r#"{"type":"hello","version":2,"capabilities":{"supports_binary":true,"supports_compression":false,"supports_delta_encoding":true,"max_message_size":1048576}}"#;
        let msg = Message::Text(hello.to_string());
        
        let (response, version) = negotiator.handle_negotiation(&msg).unwrap();
        assert_eq!(version.0, 2);
        
        match response {
            Message::Text(text) => {
                assert!(text.contains("\"type\":\"accept\""));
            }
            _ => panic!("Expected text message"),
        }
    }
}