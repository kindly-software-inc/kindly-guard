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
use kindly_guard_shield_lib::{
    core::{ShieldCore, Severity, ThreatType},
    protocol::{BinaryEncoder, BinaryDecoder, BinaryMessage, binary::CompactThreat},
    websocket::WsMessage,
};

#[test]
fn test_binary_protocol_roundtrip() {
    // Create a test threat
    let threat = ShieldCore::create_threat(
        ThreatType::UnicodeInvisible,
        Severity::High,
        "test_source".to_string(),
        "Unicode invisible character detected".to_string(),
        true,
    );
    
    // Convert to binary message
    let binary_msg = BinaryMessage::Threat {
        threats: vec![CompactThreat::from_threat(&threat)],
    };
    
    // Encode
    let mut encoder = BinaryEncoder::new();
    let mut buf = Vec::new();
    let encoded_size = encoder.encode(&binary_msg, &mut buf).unwrap();
    
    println!("Encoded message size: {} bytes", encoded_size);
    
    // Decode
    let decoder = BinaryDecoder::new();
    let (decoded_msg, consumed) = decoder.decode(&buf).unwrap();
    
    assert_eq!(consumed, encoded_size);
    
    // Verify the decoded message
    match decoded_msg {
        BinaryMessage::Threat { threats } => {
            assert_eq!(threats.len(), 1);
            let decoded_threat = threats[0].to_threat("test_id".to_string()).unwrap();
            assert_eq!(decoded_threat.threat_type, ThreatType::UnicodeInvisible);
            assert_eq!(decoded_threat.severity, Severity::High);
            assert_eq!(decoded_threat.source, "test_source");
            assert!(decoded_threat.blocked);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_size_efficiency() {
    // Create multiple threats
    let threats: Vec<_> = (0..10)
        .map(|i| {
            ShieldCore::create_threat(
                match i % 4 {
                    0 => ThreatType::UnicodeInvisible,
                    1 => ThreatType::InjectionAttempt,
                    2 => ThreatType::PathTraversal,
                    _ => ThreatType::SuspiciousPattern,
                },
                Severity::Medium,
                format!("source_{}", i),
                format!("Threat {} detected", i),
                i % 2 == 0,
            )
        })
        .collect();
    
    // Binary encoding
    let binary_msg = BinaryMessage::Threat {
        threats: threats.iter().map(CompactThreat::from_threat).collect(),
    };
    
    let mut encoder = BinaryEncoder::new();
    let mut binary_buf = Vec::new();
    encoder.encode(&binary_msg, &mut binary_buf).unwrap();
    
    // JSON encoding
    let json_msg = WsMessage::Threat { threats };
    let json_str = serde_json::to_string(&json_msg).unwrap();
    
    let size_reduction = (1.0 - (binary_buf.len() as f64 / json_str.len() as f64)) * 100.0;
    
    println!("Binary size: {} bytes", binary_buf.len());
    println!("JSON size: {} bytes", json_str.len());
    println!("Size reduction: {:.1}%", size_reduction);
    
    // Binary should be at least 50% smaller
    assert!(size_reduction > 50.0);
}

#[test]
fn test_delta_encoding() {
    let delta = BinaryMessage::StatsDelta {
        threats_blocked_delta: 5,
        threats_analyzed_delta: 10,
        threat_type_deltas: [1, 0, 2, -1, 0, 1, 0, 0],
    };
    
    let mut encoder = BinaryEncoder::new();
    let mut buf = Vec::new();
    encoder.encode(&delta, &mut buf).unwrap();
    
    // Delta messages should be very compact (header + deltas)
    // 20 bytes header + 4 + 4 + 16 = 44 bytes
    assert!(buf.len() < 50);
    
    println!("Delta message size: {} bytes", buf.len());
}