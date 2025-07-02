#[cfg(test)]
mod tests {
    use super::super::*;
    use super::super::binary::*;
    use crate::core::{ShieldCore, Severity, ThreatType};
    
    fn create_test_threat() -> crate::core::Threat {
        ShieldCore::create_threat(
            ThreatType::UnicodeInvisible,
            Severity::High,
            "test_source".to_string(),
            "Test threat details".to_string(),
            true,
        )
    }
    
    #[test]
    fn test_message_header_encode_decode() {
        let header = MessageHeader::new(MSG_TYPE_THREAT, 100, 42);
        
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        
        assert_eq!(buf.len(), HEADER_SIZE);
        
        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = MessageHeader::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.magic, PROTOCOL_MAGIC);
        assert_eq!(decoded.version, PROTOCOL_VERSION_BINARY);
        assert_eq!(decoded.msg_type, MSG_TYPE_THREAT);
        assert_eq!(decoded.payload_size, 100);
        assert_eq!(decoded.sequence, 42);
    }
    
    #[test]
    fn test_compact_threat_conversion() {
        let threat = create_test_threat();
        let compact = CompactThreat::from_threat(&threat);
        
        assert_eq!(compact.threat_flags, THREAT_FLAG_UNICODE_INVISIBLE);
        assert_eq!(compact.severity, SEVERITY_HIGH);
        assert!(compact.blocked);
        assert_eq!(compact.source, b"test_source");
        assert_eq!(compact.details, b"Test threat details");
        
        let reconverted = compact.to_threat("test_id".to_string()).unwrap();
        assert_eq!(reconverted.id, "test_id");
        assert_eq!(reconverted.threat_type, ThreatType::UnicodeInvisible);
        assert_eq!(reconverted.severity, Severity::High);
        assert_eq!(reconverted.source, "test_source");
        assert_eq!(reconverted.details, "Test threat details");
        assert_eq!(reconverted.blocked, true);
    }
    
    #[test]
    fn test_binary_message_encoding() {
        let threats = vec![
            CompactThreat::from_threat(&create_test_threat()),
            CompactThreat::from_threat(&create_test_threat()),
        ];
        
        let msg = BinaryMessage::Threat { threats };
        
        let mut encoder = BinaryEncoder::new();
        let mut buf = Vec::new();
        let size = encoder.encode(&msg, &mut buf).unwrap();
        
        assert!(size > HEADER_SIZE);
        assert_eq!(buf.len(), size);
        
        // Verify header
        assert_eq!(&buf[..4], &PROTOCOL_MAGIC);
        assert_eq!(buf[4], PROTOCOL_VERSION_BINARY);
        assert_eq!(buf[5], MSG_TYPE_THREAT);
    }
    
    #[test]
    fn test_binary_message_decoding() {
        let threats = vec![
            CompactThreat::from_threat(&create_test_threat()),
        ];
        
        let original_msg = BinaryMessage::Threat { threats };
        
        let mut encoder = BinaryEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&original_msg, &mut buf).unwrap();
        
        let decoder = BinaryDecoder::new();
        let (decoded_msg, consumed) = decoder.decode(&buf).unwrap();
        
        assert_eq!(consumed, buf.len());
        
        match decoded_msg {
            BinaryMessage::Threat { threats } => {
                assert_eq!(threats.len(), 1);
                assert_eq!(threats[0].threat_flags, THREAT_FLAG_UNICODE_INVISIBLE);
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_status_message_encoding() {
        let msg = BinaryMessage::Status {
            protection_enabled: true,
            threats_blocked: 12345,
            threats_analyzed: 67890,
        };
        
        let mut encoder = BinaryEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&msg, &mut buf).unwrap();
        
        let decoder = BinaryDecoder::new();
        let (decoded, _) = decoder.decode(&buf).unwrap();
        
        match decoded {
            BinaryMessage::Status { protection_enabled, threats_blocked, threats_analyzed } => {
                assert!(protection_enabled);
                assert_eq!(threats_blocked, 12345);
                assert_eq!(threats_analyzed, 67890);
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_delta_encoding() {
        let msg = BinaryMessage::StatsDelta {
            threats_blocked_delta: -5,
            threats_analyzed_delta: 10,
            threat_type_deltas: [1, -2, 3, 0, 0, 1, 0, -1],
        };
        
        let mut encoder = BinaryEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&msg, &mut buf).unwrap();
        
        // Delta messages should be very compact
        assert!(buf.len() < 50); // Header + 8 bytes + 16 bytes
        
        let decoder = BinaryDecoder::new();
        let (decoded, _) = decoder.decode(&buf).unwrap();
        
        match decoded {
            BinaryMessage::StatsDelta { threats_blocked_delta, threats_analyzed_delta, threat_type_deltas } => {
                assert_eq!(threats_blocked_delta, -5);
                assert_eq!(threats_analyzed_delta, 10);
                assert_eq!(threat_type_deltas[0], 1);
                assert_eq!(threat_type_deltas[1], -2);
                assert_eq!(threat_type_deltas[2], 3);
                assert_eq!(threat_type_deltas[7], -1);
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_is_complete_message() {
        let msg = BinaryMessage::Heartbeat { uptime_seconds: 3600 };
        
        let mut encoder = BinaryEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&msg, &mut buf).unwrap();
        
        // Test partial buffers
        assert!(!encoder.is_complete_message(&buf[..10]));
        assert!(!encoder.is_complete_message(&buf[..HEADER_SIZE - 1]));
        assert!(!encoder.is_complete_message(&buf[..HEADER_SIZE + 1]));
        assert!(encoder.is_complete_message(&buf));
    }
    
    #[test]
    fn test_error_handling() {
        let decoder = BinaryDecoder::new();
        
        // Test invalid magic
        let mut bad_magic = vec![0xFF; HEADER_SIZE + 10];
        match decoder.decode(&bad_magic) {
            Err(ProtocolError::InvalidMagic) => {}
            _ => panic!("Expected InvalidMagic error"),
        }
        
        // Test insufficient buffer
        let small_buf = vec![0; 5];
        match decoder.decode(&small_buf) {
            Err(ProtocolError::InsufficientBuffer { .. }) => {}
            _ => panic!("Expected InsufficientBuffer error"),
        }
    }
    
    #[test]
    fn test_protocol_negotiation() {
        let negotiator = ProtocolNegotiator::new();
        
        // Test hello creation
        let hello = negotiator.create_hello().unwrap();
        match hello {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                assert!(text.contains("hello"));
                assert!(text.contains("\"version\":2"));
            }
            _ => panic!("Expected text message"),
        }
        
        // Test negotiation handling
        let client_hello = r#"{"type":"hello","version":2,"capabilities":{"supports_binary":true,"supports_compression":false,"supports_delta_encoding":true,"max_message_size":1048576}}"#;
        let msg = tokio_tungstenite::tungstenite::Message::Text(client_hello.to_string());
        
        let (response, version) = negotiator.handle_negotiation(&msg).unwrap();
        assert_eq!(version.0, 2);
        
        match response {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                assert!(text.contains("accept"));
            }
            _ => panic!("Expected text message"),
        }
    }
    
    #[test]
    fn test_size_comparison() {
        use crate::websocket::WsMessage;
        
        // Create equivalent messages
        let threat = create_test_threat();
        
        let binary_msg = BinaryMessage::Threat {
            threats: vec![CompactThreat::from_threat(&threat)],
        };
        
        let json_msg = WsMessage::Threat {
            threats: vec![threat],
        };
        
        // Encode both
        let mut encoder = BinaryEncoder::new();
        let mut binary_buf = Vec::new();
        encoder.encode(&binary_msg, &mut binary_buf).unwrap();
        
        let json_str = serde_json::to_string(&json_msg).unwrap();
        
        println!("Binary size: {} bytes", binary_buf.len());
        println!("JSON size: {} bytes", json_str.len());
        
        // Binary should be significantly smaller
        assert!(binary_buf.len() < json_str.len());
    }
}