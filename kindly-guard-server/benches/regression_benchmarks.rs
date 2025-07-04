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
//! Performance regression benchmarks for critical paths
//! These benchmarks establish baselines and detect performance regressions

use base64::{engine::general_purpose, Engine as _};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kindly_guard_server::{
    auth::{AuthConfig, AuthManager},
    config::Config,
    permissions::{PermissionContext, ThreatLevel, ToolPermissionManager},
    protocol::{JsonRpcRequest, RequestId},
    McpServer, ScannerConfig, SecurityScanner,
};
use serde_json::json;
use std::time::Duration;

// Unicode scanning regression tests
fn bench_unicode_scanning_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode_scanning_regression");
    group.measurement_time(Duration::from_secs(10));

    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: false,
        path_traversal_detection: false,
        xss_detection: Some(false),
        enhanced_mode: Some(false),
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };

    let scanner = SecurityScanner::new(config).unwrap();

    // Different unicode threat scenarios
    let test_cases = vec![
        (
            "clean_ascii",
            "Hello World! This is a clean ASCII text without any threats.",
        ),
        (
            "bidi_override",
            "Hello\u{202E}World\u{202C} - contains BiDi override",
        ),
        ("zero_width", "Pass\u{200B}word - contains zero-width space"),
        ("homoglyphs", "Раураl - contains Cyrillic homoglyphs"),
        (
            "combining_chars",
            "e\u{0301}\u{0302}\u{0303} - multiple combining characters",
        ),
        (
            "mixed_threats",
            "Admin\u{202E}secret\u{200B}password\u{202C}",
        ),
    ];

    for (name, text) in test_cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &text, |b, text| {
            b.iter(|| scanner.scan_text(text));
        });
    }

    group.finish();
}

// Auth token validation regression tests
fn bench_auth_token_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_regression");
    group.measurement_time(Duration::from_secs(5));

    let rt = tokio::runtime::Runtime::new().unwrap();

    let config = AuthConfig {
        enabled: true,
        jwt_secret: Some(general_purpose::STANDARD.encode("test-secret-key-for-benchmarking")),
        require_signature_verification: true,
        ..AuthConfig::default()
    };

    let auth_manager = AuthManager::new(config, "kindlyguard-bench".to_string());

    // Create test tokens
    let valid_token = "Bearer valid.test.token";
    let expired_token = "Bearer expired.test.token";
    let malformed_token = "not.a.valid.jwt.token";

    let test_cases = vec![
        ("valid_token", valid_token),
        ("expired_token", expired_token),
        ("malformed_token", malformed_token),
    ];

    for (name, token) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &token, |b, token| {
            b.iter(|| {
                rt.block_on(async {
                    let auth_header = if token.starts_with("Bearer ") {
                        token.to_string()
                    } else {
                        format!("Bearer {}", token)
                    };
                    let _ = auth_manager.authenticate(Some(&auth_header)).await;
                });
            });
        });
    }

    group.finish();
}

// Permission checking regression tests
fn bench_permission_check_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("permission_check_regression");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let _config = Config::default();
    use kindly_guard_server::permissions::{
        default_tool_definitions, ClientPermissions, PermissionRules,
    };

    let permission_rules = PermissionRules {
        default_permissions: ClientPermissions {
            max_threat_level: ThreatLevel::Medium,
            ..Default::default()
        },
        tools: default_tool_definitions(),
        category_rules: Default::default(),
        global_deny_list: Default::default(),
    };
    let manager = kindly_guard_server::permissions::standard::StandardPermissionManager::new(
        permission_rules,
    );

    let scenarios = vec![
        (
            "authenticated_low_threat",
            Some("Bearer token"),
            ThreatLevel::Low,
        ),
        (
            "authenticated_high_threat",
            Some("Bearer token"),
            ThreatLevel::High,
        ),
        ("unauthenticated_safe", None, ThreatLevel::Safe),
        ("unauthenticated_high_threat", None, ThreatLevel::High),
    ];

    for (name, auth_token, threat_level) in scenarios {
        let context = PermissionContext {
            auth_token: auth_token.map(|s| s.to_string()),
            scopes: vec![],
            threat_level,
            request_metadata: std::collections::HashMap::new(),
        };

        group.bench_with_input(BenchmarkId::from_parameter(name), &context, |b, context| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = manager
                        .check_permission("bench_client", "scan_text", context)
                        .await;
                });
            });
        });
    }

    group.finish();
}

// MCP protocol parsing regression tests
fn bench_mcp_parsing_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_parsing_regression");

    let test_requests = vec![
        (
            "simple_request",
            json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 1
            }),
        ),
        (
            "complex_request",
            json!({
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
            }),
        ),
        (
            "batch_request",
            json!([
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
            ]),
        ),
    ];

    for (name, request) in test_requests {
        group.bench_with_input(BenchmarkId::from_parameter(name), &request, |b, request| {
            b.iter(|| {
                let parsed = serde_json::from_value::<JsonRpcRequest>(request.clone());
                criterion::black_box(parsed);
            });
        });
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
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };

    let scanner = SecurityScanner::new(config).unwrap();

    let test_cases = vec![
        (
            "simple_json",
            json!({
                "name": "test",
                "value": 42
            }),
        ),
        (
            "nested_json",
            json!({
                "user": {
                    "name": "admin",
                    "permissions": ["read", "write", "delete"],
                    "metadata": {
                        "created": "2024-01-01",
                        "tags": ["important", "verified"]
                    }
                }
            }),
        ),
        (
            "array_json",
            json!([
                {"id": 1, "name": "item1"},
                {"id": 2, "name": "item2"},
                {"id": 3, "name": "item3"},
                {"id": 4, "name": "item4"},
                {"id": 5, "name": "item5"}
            ]),
        ),
        (
            "threat_json",
            json!({
                "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
                "path": "../../../etc/passwd",
                "text": "Admin\u{202E}secret\u{202C}"
            }),
        ),
    ];

    for (name, json_value) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &json_value, |b, json| {
            b.iter(|| scanner.scan_json(json));
        });
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
        xss_detection: Some(true),
        enhanced_mode: Some(false),
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

        group.bench_with_input(BenchmarkId::from_parameter(name), &text, |b, text| {
            b.iter(|| scanner.scan_text(text));
        });
    }

    group.finish();
}

// Concurrent request handling regression
fn bench_concurrent_handling_regression(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_handling_regression");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let config = Config::default();
    let server = std::sync::Arc::new(McpServer::new(config).unwrap());

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "tools/list".to_string(),
        params: None,
        id: RequestId::Number { id: 1 },
        authorization: None,
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
                                // Call the public handle_message method
                                let request_json = serde_json::to_string(&req).unwrap();
                                let response = server.handle_message(&request_json).await;
                                criterion::black_box(response);
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
