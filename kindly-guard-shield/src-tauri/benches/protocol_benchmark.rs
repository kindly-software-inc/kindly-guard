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
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kindly_guard_shield_lib::{
    core::{ShieldCore, Severity, ThreatType},
    protocol::{BinaryEncoder, BinaryDecoder, BinaryMessage, binary::CompactThreat},
    websocket::WsMessage,
};

fn create_test_threat() -> kindly_guard_shield_lib::core::Threat {
    ShieldCore::create_threat(
        ThreatType::UnicodeInvisible,
        Severity::High,
        "test_source_123".to_string(),
        "Unicode invisible character detected at position 42".to_string(),
        true,
    )
}

fn create_binary_message() -> BinaryMessage {
    let threats = vec![
        CompactThreat::from_threat(&create_test_threat()),
        CompactThreat::from_threat(&create_test_threat()),
        CompactThreat::from_threat(&create_test_threat()),
    ];
    
    BinaryMessage::Threat { threats }
}

fn create_json_message() -> WsMessage {
    let threats = vec![
        create_test_threat(),
        create_test_threat(),
        create_test_threat(),
    ];
    
    WsMessage::Threat { threats }
}

fn benchmark_binary_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding");
    
    let binary_msg = create_binary_message();
    let json_msg = create_json_message();
    
    // Calculate message sizes for throughput
    let mut encoder = BinaryEncoder::new();
    let mut binary_buf = Vec::new();
    encoder.encode(&binary_msg, &mut binary_buf).unwrap();
    let binary_size = binary_buf.len() as u64;
    
    let json_str = serde_json::to_string(&json_msg).unwrap();
    let json_size = json_str.len() as u64;
    
    println!("Binary size: {} bytes", binary_size);
    println!("JSON size: {} bytes", json_size);
    println!("Size reduction: {:.1}%", (1.0 - (binary_size as f64 / json_size as f64)) * 100.0);
    
    group.throughput(Throughput::Bytes(binary_size));
    group.bench_function("binary_encode", |b| {
        b.iter(|| {
            let mut encoder = BinaryEncoder::new();
            let mut buf = Vec::with_capacity(512);
            encoder.encode(black_box(&binary_msg), &mut buf).unwrap();
        });
    });
    
    group.throughput(Throughput::Bytes(json_size));
    group.bench_function("json_encode", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&json_msg)).unwrap();
        });
    });
    
    group.finish();
}

fn benchmark_binary_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding");
    
    // Prepare encoded data
    let binary_msg = create_binary_message();
    let json_msg = create_json_message();
    
    let mut encoder = BinaryEncoder::new();
    let mut binary_data = Vec::new();
    encoder.encode(&binary_msg, &mut binary_data).unwrap();
    
    let json_data = serde_json::to_string(&json_msg).unwrap();
    
    group.throughput(Throughput::Bytes(binary_data.len() as u64));
    group.bench_function("binary_decode", |b| {
        b.iter(|| {
            let decoder = BinaryDecoder::new();
            decoder.decode(black_box(&binary_data)).unwrap();
        });
    });
    
    group.throughput(Throughput::Bytes(json_data.len() as u64));
    group.bench_function("json_decode", |b| {
        b.iter(|| {
            serde_json::from_str::<WsMessage>(black_box(&json_data)).unwrap();
        });
    });
    
    group.finish();
}

fn benchmark_protocol_negotiation(c: &mut Criterion) {
    use kindly_guard_shield_lib::protocol::ProtocolNegotiator;
    
    let mut group = c.benchmark_group("negotiation");
    
    group.bench_function("create_hello", |b| {
        b.iter(|| {
            let negotiator = ProtocolNegotiator::new();
            negotiator.create_hello().unwrap();
        });
    });
    
    group.finish();
}

fn benchmark_status_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("status_updates");
    
    // Binary status message
    let binary_status = BinaryMessage::Status {
        protection_enabled: true,
        threats_blocked: 12345,
        threats_analyzed: 67890,
    };
    
    // JSON status message
    let json_status = WsMessage::Status {
        protection_enabled: true,
        threats_blocked: 12345,
    };
    
    group.bench_function("binary_status_encode", |b| {
        b.iter(|| {
            let mut encoder = BinaryEncoder::new();
            let mut buf = Vec::with_capacity(64);
            encoder.encode(black_box(&binary_status), &mut buf).unwrap();
        });
    });
    
    group.bench_function("json_status_encode", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&json_status)).unwrap();
        });
    });
    
    // Delta encoding benchmark
    let delta_msg = BinaryMessage::StatsDelta {
        threats_blocked_delta: 5,
        threats_analyzed_delta: 10,
        threat_type_deltas: [1, 0, 2, 0, 0, 1, 0, 0],
    };
    
    group.bench_function("delta_encode", |b| {
        b.iter(|| {
            let mut encoder = BinaryEncoder::new();
            let mut buf = Vec::with_capacity(32);
            encoder.encode(black_box(&delta_msg), &mut buf).unwrap();
        });
    });
    
    group.finish();
}

#[cfg(feature = "enhanced")]
fn benchmark_zero_copy(c: &mut Criterion) {
    use kindly_guard_shield_lib::protocol::encoder::EnhancedBinaryEncoder;
    
    let mut group = c.benchmark_group("zero_copy");
    
    let binary_msg = create_binary_message();
    let mut out_buf = vec![0u8; 1024];
    
    group.bench_function("zero_copy_encode", |b| {
        b.iter(|| {
            let mut encoder = EnhancedBinaryEncoder::new();
            encoder.encode_zero_copy(black_box(&binary_msg), &mut out_buf).unwrap();
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_binary_encoding,
    benchmark_binary_decoding,
    benchmark_protocol_negotiation,
    benchmark_status_updates,
);

#[cfg(feature = "enhanced")]
criterion_group!(
    enhanced_benches,
    benchmark_zero_copy,
);

#[cfg(not(feature = "enhanced"))]
criterion_main!(benches);

#[cfg(feature = "enhanced")]
criterion_main!(benches, enhanced_benches);