//! Performance regression benchmarks for critical paths
//! These benchmarks establish baselines and detect performance regressions

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use kindly_guard_server::{
    SecurityScanner, ScannerConfig,
    auth::{TokenGenerator, TokenValidator, AuthConfig},
    permissions::{ToolPermissionManager, PermissionConfig, PermissionContext, Permission},
    mcp::{JsonRpcRequest, JsonRpcResponse},
    McpServer, ServerConfig,
    ThreatLevel,
};
use std::time::Duration;
use serde_json::json;

// Unicode scanning regression tests
fn bench_unicode_scanning_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode_scanning_regression");
    group.measurement_time(Duration::from_secs(10));
    
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: false,
        path_traversal_detection: false,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };
    
    let scanner = SecurityScanner::new(config).unwrap();
    
    // Different unicode threat scenarios
    let test_cases = vec![
        ("clean_ascii", "Hello World! This is a clean ASCII text without any threats."),
        ("bidi_override", "Hello\u{202E}World\u{202C} - contains BiDi override"),
        ("zero_width", "Pass\u{200B}word - contains zero-width space"),
        ("homoglyphs", "Раураl - contains Cyrillic homoglyphs"),
        ("combining_chars", "e\u{0301}\u{0302}\u{0303} - multiple combining characters"),
        ("mixed_threats", "Admin\u{202E}secret\u{200B}password\u{202C}"),
    ];
    
    for (name, text) in test_cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &text,
            |b, text| {
                b.iter(|| {
                    scanner.scan_text(text)
                });
            },
        );
    }
    
    group.finish();
}

// Auth token validation regression tests
fn bench_auth_token_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_regression");
    group.measurement_time(Duration::from_secs(5));
    
    let config = AuthConfig {
        secret_key: "test-secret-key-for-benchmarking".to_string(),
        token_expiry: Duration::from_secs(3600),
        require_auth: true,
    };
    
    let generator = TokenGenerator::new(config.clone()).unwrap();
    let validator = TokenValidator::new(config).unwrap();
    
    // Generate tokens
    let valid_token = generator.generate_token("bench_user").unwrap();
    let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.invalid";
    let malformed_token = "not.a.valid.jwt.token";
    
    let test_cases = vec![
        ("valid_token", valid_token.as_str()),
        ("expired_token", expired_token),
        ("malformed_token", malformed_token),
    ];
    
    for (name, token) in test_cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &token,
            |b, token| {
                b.iter(|| {
                    let _ = validator.validate_token(token);
                });
            },
        );
    }
    
    group.finish();
}

// Permission checking regression tests
fn bench_permission_check_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("permission_check_regression");
    
    let config = PermissionConfig {
        require_auth: true,
        default_permission: Permission::Deny("Not authorized".to_string()),
        role_permissions: Default::default(),
        custom_rules: vec![],
    };
    
    let manager = ToolPermissionManager::new(config).unwrap();
    
    let scenarios = vec![
        ("authenticated_low_threat", true, ThreatLevel::Low),
        ("authenticated_high_threat", true, ThreatLevel::High),
        ("unauthenticated_no_threat", false, ThreatLevel::None),
        ("unauthenticated_high_threat", false, ThreatLevel::High),
    ];
    
    for (name, authenticated, threat_level) in scenarios {
        let context = PermissionContext {
            authenticated,
            threat_level,
            request_metadata: json!({"source": "benchmark"}),
        };
        
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &context,
            |b, context| {
                b.iter(|| {
                    let _ = manager.check_permission("bench_client", "scan_text", context);
                });
            },
        );
    }
    
    group.finish();
}

// MCP protocol parsing regression tests
fn bench_mcp_parsing_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_parsing_regression");
    
    let test_requests = vec![
        ("simple_request", json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 1
        })),
        ("complex_request", json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "This is a longer text with more content to parse and validate",
                    "options": {
                        "deep_scan": true,
                        "timeout": 30
                    }
                }
            },
            "id": 42
        })),
        ("batch_request", json!([
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "resources/list",
                "params": {},
                "id": 2
            },
            {
                "jsonrpc": "2.0",
                "method": "prompts/list",
                "params": {},
                "id": 3
            }
        ])),
    ];
    
    for (name, request) in test_requests {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &request,
            |b, request| {
                b.iter(|| {
                    let _ = serde_json::from_value::<JsonRpcRequest>(request.clone());
                });
            },
        );
    }
    
    group.finish();
}

// JSON threat scanning regression tests
fn bench_json_scanning_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_scanning_regression");
    group.measurement_time(Duration::from_secs(5));
    
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };
    
    let scanner = SecurityScanner::new(config).unwrap();
    
    let test_cases = vec![
        ("simple_json", json!({
            "name": "test",
            "value": 42
        })),
        ("nested_json", json!({
            "user": {
                "name": "admin",
                "permissions": ["read", "write", "delete"],
                "metadata": {
                    "created": "2024-01-01",
                    "tags": ["important", "verified"]
                }
            }
        })),
        ("array_json", json!([
            {"id": 1, "name": "item1"},
            {"id": 2, "name": "item2"},
            {"id": 3, "name": "item3"},
            {"id": 4, "name": "item4"},
            {"id": 5, "name": "item5"}
        ])),
        ("threat_json", json!({
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
            "path": "../../../etc/passwd",
            "text": "Admin\u{202E}secret\u{202C}"
        })),
    ];
    
    for (name, json_value) in test_cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &json_value,
            |b, json| {
                b.iter(|| {
                    scanner.scan_json(json)
                });
            },
        );
    }
    
    group.finish();
}

// Large payload handling regression
fn bench_large_payload_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_payload_regression");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };
    
    let scanner = SecurityScanner::new(config).unwrap();
    
    // Generate different sized payloads
    let sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];
    
    for (name, size) in sizes {
        let text = "Hello World! ".repeat(size / 13); // ~13 chars per repeat
        group.throughput(Throughput::Bytes(text.len() as u64));
        
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &text,
            |b, text| {
                b.iter(|| {
                    scanner.scan_text(text)
                });
            },
        );
    }
    
    group.finish();
}

// Concurrent request handling regression
fn bench_concurrent_handling_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_handling_regression");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let config = ServerConfig::default();
    let server = std::sync::Arc::new(McpServer::new(config).unwrap());
    
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "tools/list".to_string(),
        params: None,
        id: Some(serde_json::json!(1)),
    };
    
    // Test different concurrency levels
    let concurrency_levels = vec![1, 10, 50, 100];
    
    for level in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("concurrent_{}", level)),
            &level,
            |b, &level| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = vec![];
                        for _ in 0..level {
                            let server = server.clone();
                            let req = request.clone();
                            let handle = tokio::spawn(async move {
                                let _ = server.handle_request(req).await;
                            });
                            handles.push(handle);
                        }
                        for handle in handles {
                            let _ = handle.await;
                        }
                    });
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    regression_benches,
    bench_unicode_scanning_regression,
    bench_auth_token_regression,
    bench_permission_check_regression,
    bench_mcp_parsing_regression,
    bench_json_scanning_regression,
    bench_large_payload_regression,
    bench_concurrent_handling_regression
);
criterion_main!(regression_benches);