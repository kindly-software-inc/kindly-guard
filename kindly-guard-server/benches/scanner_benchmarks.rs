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

//! Scanner performance benchmarks
//!
//! Measures throughput (MB/sec) and latency for various threat detection scenarios.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kindly_guard_server::scanner::{SecurityScanner, ThreatType};
use serde_json::json;
use std::time::Duration;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Generate clean text of specified size
fn generate_clean_text(size: usize) -> String {
    "The quick brown fox jumps over the lazy dog. "
        .repeat(size / 45 + 1)
        .chars()
        .take(size)
        .collect()
}

/// Generate text with unicode threats
fn generate_unicode_threats(size: usize) -> String {
    let pattern = "Hello\u{200B}World\u{202E}Test\u{200C}";
    pattern
        .repeat(size / pattern.len() + 1)
        .chars()
        .take(size)
        .collect()
}

/// Generate text with injection patterns
fn generate_injection_patterns(size: usize) -> String {
    let patterns = [
        "SELECT * FROM users WHERE id = ",
        "'; DROP TABLE users; --",
        "cmd.exe /c dir",
        "../../../etc/passwd",
        "{{7*7}}",
    ];
    
    let mut result = String::with_capacity(size);
    let mut i = 0;
    while result.len() < size {
        result.push_str(patterns[i % patterns.len()]);
        result.push(' ');
        i += 1;
    }
    result.truncate(size);
    result
}

/// Generate HTML with XSS patterns
fn generate_xss_content(size: usize) -> String {
    let patterns = [
        "<script>alert('xss')</script>",
        "<img src=x onerror='alert(1)'>",
        "<a href='javascript:void(0)'>click</a>",
        "<iframe src='data:text/html,<script>alert(1)</script>'>",
    ];
    
    let mut result = String::with_capacity(size);
    let mut i = 0;
    while result.len() < size {
        result.push_str(patterns[i % patterns.len()]);
        result.push_str("<p>Normal content</p>");
        i += 1;
    }
    result.truncate(size);
    result
}

/// Generate realistic JSON data
fn generate_json_data(size: usize) -> serde_json::Value {
    let num_entries = size / 100; // Approximate size per entry
    let mut users = Vec::new();
    
    for i in 0..num_entries {
        users.push(json!({
            "id": i,
            "name": format!("User {}", i),
            "email": format!("user{}@example.com", i),
            "bio": "A regular user with normal bio text",
            "created_at": "2025-01-01T00:00:00Z"
        }));
    }
    
    json!({
        "users": users,
        "metadata": {
            "version": "1.0",
            "generated": "2025-01-01"
        }
    })
}

/// Generate JSON with threats
fn generate_json_threats() -> serde_json::Value {
    json!({
        "users": [
            {
                "name": "Admin\u{202E}txt.exe",
                "bio": "'; DROP TABLE users; --",
                "script": "<script>alert('xss')</script>"
            },
            {
                "name": "Test\u{200B}User",
                "command": "cmd.exe /c del *.*",
                "path": "../../../etc/passwd"
            }
        ],
        "config": {
            "url": "javascript:void(0)",
            "template": "{{7*7}}"
        }
    })
}

fn throughput_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_throughput");
    group.measurement_time(Duration::from_secs(10));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Text scanning throughput
    for size in [KB, 10 * KB, 100 * KB, MB].iter() {
        let clean_text = generate_clean_text(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(format!("clean_text_{}", size), |b| {
            b.iter(|| {
                let threats = scanner.scan_text(black_box(&clean_text)).unwrap_or_default();
                black_box(threats);
            })
        });
        
        let unicode_text = generate_unicode_threats(*size);
        group.bench_function(format!("unicode_threats_{}", size), |b| {
            b.iter(|| {
                let threats = scanner.scan_text(black_box(&unicode_text)).unwrap_or_default();
                black_box(threats);
            })
        });
        
        let injection_text = generate_injection_patterns(*size);
        group.bench_function(format!("injection_patterns_{}", size), |b| {
            b.iter(|| {
                let threats = scanner.scan_text(black_box(&injection_text)).unwrap_or_default();
                black_box(threats);
            })
        });
        
        let xss_text = generate_xss_content(*size);
        group.bench_function(format!("xss_content_{}", size), |b| {
            b.iter(|| {
                let threats = scanner.scan_text(black_box(&xss_text)).unwrap_or_default();
                black_box(threats);
            })
        });
    }
    
    // JSON scanning throughput
    for size in [KB, 10 * KB, 100 * KB].iter() {
        let json_data = generate_json_data(*size);
        let json_str = serde_json::to_string(&json_data).unwrap();
        group.throughput(Throughput::Bytes(json_str.len() as u64));
        
        group.bench_function(format!("json_clean_{}", size), |b| {
            b.iter(|| {
                let threats = scanner.scan_json(black_box(&json_data)).unwrap_or_default();
                black_box(threats);
            })
        });
    }
    
    group.finish();
}

fn latency_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_latency");
    group.measurement_time(Duration::from_secs(10));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Small input latency tests
    group.bench_function("detect_invisible_unicode", |b| {
        let text = "Hello\u{200B}World";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(!threats.is_empty());
            assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeInvisible)));
            black_box(threats);
        })
    });
    
    group.bench_function("detect_bidi_override", |b| {
        let text = "file\u{202E}txt.exe";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(!threats.is_empty());
            assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeBiDi)));
            black_box(threats);
        })
    });
    
    group.bench_function("detect_sql_injection", |b| {
        let text = "'; DROP TABLE users; --";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(!threats.is_empty());
            assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::SqlInjection)));
            black_box(threats);
        })
    });
    
    group.bench_function("detect_xss_script", |b| {
        let text = "<script>alert('xss')</script>";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(!threats.is_empty());
            assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::CrossSiteScripting)));
            black_box(threats);
        })
    });
    
    group.bench_function("detect_path_traversal", |b| {
        let text = "../../../etc/passwd";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(!threats.is_empty());
            assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::PathTraversal)));
            black_box(threats);
        })
    });
    
    // JSON threat detection latency
    group.bench_function("detect_json_threats", |b| {
        let json_data = generate_json_threats();
        b.iter(|| {
            let threats = scanner.scan_json(black_box(&json_data)).unwrap();
            assert!(!threats.is_empty());
            black_box(threats);
        })
    });
    
    // No threats (baseline)
    group.bench_function("no_threats_baseline", |b| {
        let text = "This is completely safe text with no threats whatsoever.";
        b.iter(|| {
            let threats = scanner.scan_text(black_box(text)).unwrap();
            assert!(threats.is_empty());
            black_box(threats);
        })
    });
    
    group.finish();
}

fn mixed_content_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_mixed_content");
    group.measurement_time(Duration::from_secs(10));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Realistic mixed content scenarios
    group.bench_function("web_form_submission", |b| {
        let form_data = json!({
            "username": "john_doe",
            "email": "john@example.com",
            "bio": "Software developer. Love coding!",
            "website": "https://example.com",
            "comment": "Great article! Thanks for sharing."
        });
        
        b.iter(|| {
            let threats = scanner.scan_json(black_box(&form_data)).unwrap_or_default();
            black_box(threats);
        })
    });
    
    group.bench_function("api_request_with_threats", |b| {
        let api_request = json!({
            "action": "update_profile",
            "user_id": "1234",
            "data": {
                "name": "Admin\u{202E}gpj.exe",
                "bio": "'; DELETE FROM users; --",
                "avatar": "<img src=x onerror=alert(1)>"
            }
        });
        
        b.iter(|| {
            let threats = scanner.scan_json(black_box(&api_request)).unwrap();
            assert!(!threats.is_empty());
            black_box(threats);
        })
    });
    
    group.bench_function("markdown_document", |b| {
        let markdown = r#"
# Welcome to Our Documentation

This is a normal paragraph with some **bold** and *italic* text.

## Code Example

```javascript
console.log("Hello, World!");
```

Here's a [link](https://example.com) to our website.

![Image](https://example.com/image.png)
        "#;
        
        b.iter(|| {
            let threats = scanner.scan_text(black_box(markdown)).unwrap_or_default();
            black_box(threats);
        })
    });
    
    group.bench_function("code_snippet_analysis", |b| {
        let code = r#"
function processUserInput(input) {
    // Validate input
    if (!input || typeof input !== 'string') {
        return null;
    }
    
    // Process the input
    const query = `SELECT * FROM users WHERE name = '${input}'`;
    return database.execute(query);
}
        "#;
        
        b.iter(|| {
            let threats = scanner.scan_text(black_box(code)).unwrap_or_default();
            black_box(threats);
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    throughput_benchmarks,
    latency_benchmarks,
    mixed_content_benchmarks
);
criterion_main!(benches);