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

//! Real-world performance benchmarks
//!
//! Simulates scanning a large codebase with mixed content types and measures
//! false positive rates and real-world performance characteristics.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kindly_guard_server::scanner::{SecurityScanner, Severity, ThreatType};
use rand::{thread_rng, Rng};
use serde_json::json;
use std::time::Duration;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Represents a file in our simulated codebase
#[derive(Clone)]
struct CodebaseFile {
    path: String,
    content: String,
    file_type: FileType,
}

#[derive(Debug, Clone, Copy)]
enum FileType {
    Rust,
    JavaScript,
    Python,
    Markdown,
    Json,
    Html,
    Config,
    Text,
}

/// Generate a realistic Rust source file
fn generate_rust_file(size: usize) -> String {
    let templates = vec![
        r#"use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    id: u64,
    name: String,
    email: String,
}

impl User {
    pub fn new(id: u64, name: String, email: String) -> Self {
        Self { id, name, email }
    }
    
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        if !self.email.contains('@') {
            return Err(ValidationError::InvalidEmail);
        }
        Ok(())
    }
}
"#,
        r#"async fn process_request(req: Request) -> Result<Response, Error> {
    let body = req.body().await?;
    let data: RequestData = serde_json::from_slice(&body)?;
    
    // Validate input
    if data.user_id == 0 {
        return Err(Error::InvalidUserId);
    }
    
    // Process the request
    let result = database.query(
        "SELECT * FROM users WHERE id = $1",
        &[&data.user_id]
    ).await?;
    
    Ok(Response::json(&result))
}
"#,
    ];
    
    let mut result = String::new();
    let mut rng = thread_rng();
    
    while result.len() < size {
        result.push_str(templates[rng.gen_range(0..templates.len())]);
        result.push_str("\n\n");
    }
    
    result.truncate(size);
    result
}

/// Generate a realistic JavaScript file
fn generate_javascript_file(size: usize) -> String {
    let templates = vec![
        r#"export class UserService {
    constructor(database) {
        this.db = database;
    }
    
    async getUser(userId) {
        if (!userId || typeof userId !== 'number') {
            throw new Error('Invalid user ID');
        }
        
        const query = 'SELECT * FROM users WHERE id = ?';
        const result = await this.db.query(query, [userId]);
        return result[0];
    }
    
    async updateUser(userId, data) {
        const { name, email } = data;
        const query = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
        await this.db.query(query, [name, email, userId]);
    }
}
"#,
        r#"function validateInput(input) {
    // Check for common attack patterns
    const dangerous = ['<script', 'javascript:', 'onerror='];
    const inputLower = input.toLowerCase();
    
    for (const pattern of dangerous) {
        if (inputLower.includes(pattern)) {
            console.warn('Potentially dangerous input detected');
            return false;
        }
    }
    
    return true;
}

const sanitizeHtml = (html) => {
    return html
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};
"#,
    ];
    
    let mut result = String::new();
    let mut rng = thread_rng();
    
    while result.len() < size {
        result.push_str(templates[rng.gen_range(0..templates.len())]);
        result.push_str("\n\n");
    }
    
    result.truncate(size);
    result
}

/// Generate a realistic Python file
fn generate_python_file(size: usize) -> String {
    let templates = vec![
        r#"import sqlite3
from typing import Optional, List, Dict

class UserRepository:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        query = "SELECT * FROM users WHERE id = ?"
        self.cursor.execute(query, (user_id,))
        row = self.cursor.fetchone()
        
        if row:
            return {
                'id': row[0],
                'name': row[1],
                'email': row[2]
            }
        return None
    
    def search_users(self, name: str) -> List[Dict]:
        # Safe parameterized query
        query = "SELECT * FROM users WHERE name LIKE ?"
        self.cursor.execute(query, (f'%{name}%',))
        return [{'id': r[0], 'name': r[1], 'email': r[2]} for r in self.cursor.fetchall()]
"#,
        r#"from flask import Flask, request, jsonify
import re

app = Flask(__name__)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    
    # Validate input
    if not data.get('name') or not data.get('email'):
        return jsonify({'error': 'Name and email are required'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Process the request
    # ... user creation logic ...
    
    return jsonify({'message': 'User created successfully'}), 201
"#,
    ];
    
    let mut result = String::new();
    let mut rng = thread_rng();
    
    while result.len() < size {
        result.push_str(templates[rng.gen_range(0..templates.len())]);
        result.push_str("\n\n");
    }
    
    result.truncate(size);
    result
}

/// Generate a realistic Markdown file
fn generate_markdown_file(size: usize) -> String {
    let template = r#"# API Documentation

## Overview

This API provides secure access to user data with built-in protection against common attacks.

## Authentication

All requests must include a valid API key in the header:

```
Authorization: Bearer YOUR_API_KEY
```

## Endpoints

### GET /api/users/:id

Retrieves a user by ID.

**Parameters:**
- `id` (integer): The user's unique identifier

**Response:**
```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
}
```

### POST /api/users

Creates a new user.

**Request Body:**
```json
{
    "name": "Jane Smith",
    "email": "jane@example.com"
}
```

## Security Considerations

- All inputs are validated and sanitized
- SQL injection protection via parameterized queries
- XSS protection through output encoding
- Rate limiting to prevent abuse

"#;
    
    let mut result = String::new();
    while result.len() < size {
        result.push_str(template);
        result.push_str("\n\n");
    }
    
    result.truncate(size);
    result
}

/// Generate a realistic JSON configuration file
fn generate_json_file() -> String {
    json!({
        "server": {
            "host": "0.0.0.0",
            "port": 8080,
            "workers": 4
        },
        "database": {
            "url": "postgresql://localhost/myapp",
            "pool_size": 10,
            "timeout": 30
        },
        "security": {
            "rate_limit": {
                "requests_per_minute": 60,
                "burst_size": 10
            },
            "cors": {
                "allowed_origins": ["https://example.com"],
                "allowed_methods": ["GET", "POST", "PUT", "DELETE"]
            }
        },
        "logging": {
            "level": "info",
            "format": "json",
            "file": "/var/log/myapp.log"
        }
    }).to_string()
}

/// Generate a realistic HTML file
fn generate_html_file(size: usize) -> String {
    let template = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .user-card { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>User Management System</h1>
    
    <form id="userForm">
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" required>
        
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required>
        
        <button type="submit">Create User</button>
    </form>
    
    <div id="userList">
        <div class="user-card">
            <h3>John Doe</h3>
            <p>Email: john@example.com</p>
        </div>
    </div>
    
    <script>
        document.getElementById('userForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            
            // Validate input
            if (name && email) {
                console.log('Creating user:', name, email);
            }
        });
    </script>
</body>
</html>"#;
    
    let mut result = String::new();
    while result.len() < size {
        result.push_str(template);
        result.push_str("\n\n");
    }
    
    result.truncate(size);
    result
}

/// Generate a simulated codebase
fn generate_codebase(total_size: usize) -> Vec<CodebaseFile> {
    let mut files = Vec::new();
    let mut rng = thread_rng();
    
    // Distribution of file types (roughly matching a real project)
    let distributions = vec![
        (FileType::Rust, 0.25),
        (FileType::JavaScript, 0.20),
        (FileType::Python, 0.15),
        (FileType::Markdown, 0.15),
        (FileType::Json, 0.10),
        (FileType::Html, 0.10),
        (FileType::Config, 0.03),
        (FileType::Text, 0.02),
    ];
    
    let mut current_size = 0;
    let mut file_counter = 0;
    
    while current_size < total_size {
        // Select file type based on distribution
        let mut roll = rng.gen::<f64>();
        let mut selected_type = FileType::Text;
        
        for (file_type, probability) in &distributions {
            if roll < *probability {
                selected_type = *file_type;
                break;
            }
            roll -= probability;
        }
        
        // Generate file content
        let target_file_size = rng.gen_range(1 * KB..50 * KB);
        let content = match selected_type {
            FileType::Rust => generate_rust_file(target_file_size),
            FileType::JavaScript => generate_javascript_file(target_file_size),
            FileType::Python => generate_python_file(target_file_size),
            FileType::Markdown => generate_markdown_file(target_file_size),
            FileType::Json => generate_json_file(),
            FileType::Html => generate_html_file(target_file_size),
            FileType::Config => generate_json_file(),
            FileType::Text => generate_clean_text(target_file_size),
        };
        
        let path = match selected_type {
            FileType::Rust => format!("src/module_{}/file_{}.rs", file_counter / 10, file_counter),
            FileType::JavaScript => format!("frontend/src/file_{}.js", file_counter),
            FileType::Python => format!("scripts/script_{}.py", file_counter),
            FileType::Markdown => format!("docs/doc_{}.md", file_counter),
            FileType::Json => format!("config/config_{}.json", file_counter),
            FileType::Html => format!("templates/page_{}.html", file_counter),
            FileType::Config => format!("config_{}.toml", file_counter),
            FileType::Text => format!("README_{}.txt", file_counter),
        };
        
        current_size += content.len();
        files.push(CodebaseFile {
            path,
            content,
            file_type: selected_type,
        });
        
        file_counter += 1;
    }
    
    files
}

/// Generate clean text (from scanner_benchmarks.rs)
fn generate_clean_text(size: usize) -> String {
    "The quick brown fox jumps over the lazy dog. "
        .repeat(size / 45 + 1)
        .chars()
        .take(size)
        .collect()
}

/// Inject threats into a portion of the codebase
fn inject_threats(files: &mut Vec<CodebaseFile>, threat_percentage: f64) {
    let mut rng = thread_rng();
    let num_files_to_modify = (files.len() as f64 * threat_percentage) as usize;
    
    let threat_patterns = vec![
        // Unicode threats
        "\u{200B}",  // Zero-width space
        "\u{202E}",  // Right-to-left override
        "\u{200C}",  // Zero-width non-joiner
        
        // Injection patterns
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "../../../etc/passwd",
        "{{7*7}}",
        
        // XSS patterns
        "<script>alert('xss')</script>",
        "<img src=x onerror='alert(1)'>",
        "javascript:void(0)",
    ];
    
    for _ in 0..num_files_to_modify {
        let file_idx = rng.gen_range(0..files.len());
        let threat_idx = rng.gen_range(0..threat_patterns.len());
        let threat = threat_patterns[threat_idx];
        
        // Inject threat at a random position
        let file = &mut files[file_idx];
        let position = rng.gen_range(0..file.content.len().saturating_sub(threat.len()));
        file.content.insert_str(position, threat);
    }
}

fn codebase_scanning_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("real_world_codebase");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Generate different sized codebases
    for size in [MB, 10 * MB, 50 * MB].iter() {
        // Clean codebase
        let clean_codebase = generate_codebase(*size);
        let total_bytes: usize = clean_codebase.iter().map(|f| f.content.len()).sum();
        
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_function(format!("clean_codebase_{}MB", size / MB), |b| {
            b.iter(|| {
                let mut total_threats = 0;
                for file in &clean_codebase {
                    let threats = scanner.scan_text(black_box(&file.content)).unwrap_or_default();
                    total_threats += threats.len();
                }
                black_box(total_threats);
            })
        });
        
        // Codebase with 1% threats
        let mut infected_codebase = clean_codebase.clone();
        inject_threats(&mut infected_codebase, 0.01);
        
        group.bench_function(format!("infected_codebase_{}MB", size / MB), |b| {
            b.iter(|| {
                let mut total_threats = 0;
                for file in &infected_codebase {
                    let threats = scanner.scan_text(black_box(&file.content)).unwrap_or_default();
                    total_threats += threats.len();
                }
                black_box(total_threats);
            })
        });
    }
    
    group.finish();
}

fn false_positive_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("false_positive_rates");
    group.measurement_time(Duration::from_secs(20));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Analyze false positives in different content types
    group.bench_function("legitimate_sql_queries", |b| {
        let queries = vec![
            "SELECT * FROM users WHERE id = ?",
            "INSERT INTO logs (message, timestamp) VALUES (?, ?)",
            "UPDATE settings SET value = ? WHERE key = ?",
            "DELETE FROM sessions WHERE expires_at < ?",
        ];
        
        b.iter(|| {
            let mut false_positives = 0;
            for query in &queries {
                let threats = scanner.scan_text(black_box(query)).unwrap_or_default();
                // These should not be detected as SQL injection
                if threats.iter().any(|t| matches!(t.threat_type, ThreatType::SqlInjection)) {
                    false_positives += 1;
                }
            }
            assert_eq!(false_positives, 0, "Legitimate SQL detected as injection");
            black_box(false_positives);
        })
    });
    
    group.bench_function("legitimate_html_content", |b| {
        let html_samples = vec![
            "<p>The price is less than $50</p>",
            "<div>2 < 3 and 5 > 4</div>",
            "<code>if (x < y) { return x; }</code>",
            "<pre>Use &lt;script&gt; tags carefully</pre>",
        ];
        
        b.iter(|| {
            let mut false_positives = 0;
            for html in &html_samples {
                let threats = scanner.scan_text(black_box(html)).unwrap_or_default();
                // These should not be detected as XSS
                if threats.iter().any(|t| matches!(t.threat_type, ThreatType::CrossSiteScripting)) {
                    false_positives += 1;
                }
            }
            black_box(false_positives);
        })
    });
    
    group.bench_function("unicode_in_names", |b| {
        let names = vec![
            "François",
            "José",
            "Björn",
            "Владимир",
            "محمد",
            "李明",
        ];
        
        b.iter(|| {
            let mut false_positives = 0;
            for name in &names {
                let threats = scanner.scan_text(black_box(name)).unwrap_or_default();
                // Legitimate Unicode names should not be flagged
                if threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeHomograph)) {
                    false_positives += 1;
                }
            }
            black_box(false_positives);
        })
    });
    
    group.finish();
}

fn mixed_content_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_content_types");
    group.measurement_time(Duration::from_secs(15));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Real-world API payloads
    group.bench_function("api_payload_batch", |b| {
        let payloads = vec![
            json!({
                "action": "create_post",
                "title": "My First Blog Post",
                "content": "This is a great day to start blogging!",
                "tags": ["introduction", "hello-world"]
            }),
            json!({
                "search": "rust programming",
                "filters": {
                    "category": "tutorials",
                    "difficulty": "beginner"
                },
                "page": 1,
                "limit": 20
            }),
            json!({
                "user": {
                    "name": "Alice Johnson",
                    "bio": "Software engineer | Open source enthusiast",
                    "links": ["https://github.com/alice", "https://alice.dev"]
                }
            }),
        ];
        
        b.iter(|| {
            let mut total_threats = 0;
            for payload in &payloads {
                let threats = scanner.scan_json(black_box(payload)).unwrap_or_default();
                total_threats += threats.len();
            }
            black_box(total_threats);
        })
    });
    
    // Log file analysis
    group.bench_function("log_file_scanning", |b| {
        let log_entries = vec![
            "[2025-01-01 10:23:45] INFO: User login successful for user_id=12345",
            "[2025-01-01 10:24:02] ERROR: Database connection failed: timeout after 30s",
            "[2025-01-01 10:24:15] WARN: Invalid input detected: '; DROP TABLE users; --",
            "[2025-01-01 10:24:30] INFO: Request processed successfully in 125ms",
            "[2025-01-01 10:24:45] DEBUG: Cache hit for key='user:12345:profile'",
        ].join("\n");
        
        b.iter(|| {
            let threats = scanner.scan_text(black_box(&log_entries)).unwrap();
            // Should detect the SQL injection in the log but not flag normal logs
            assert!(!threats.is_empty());
            black_box(threats);
        })
    });
    
    group.finish();
}

fn threat_detection_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("detection_accuracy");
    group.measurement_time(Duration::from_secs(10));
    
    let scanner = SecurityScanner::new(Default::default()).unwrap();
    
    // Measure detection rates for different severity levels
    group.bench_function("severity_classification", |b| {
        let test_cases = vec![
            ("Hello\u{200B}World", Severity::Low),          // Invisible unicode
            ("admin\u{202E}txt.exe", Severity::High),       // BiDi override
            ("'; DROP TABLE users; --", Severity::Critical), // SQL injection
            ("<script>alert(1)</script>", Severity::High),  // XSS
            ("../../../etc/passwd", Severity::High),        // Path traversal
        ];
        
        b.iter(|| {
            let mut correct_severities = 0;
            let total = test_cases.len();
            
            for (input, expected_severity) in &test_cases {
                let threats = scanner.scan_text(black_box(input)).unwrap_or_default();
                if let Some(threat) = threats.first() {
                    if threat.severity == *expected_severity {
                        correct_severities += 1;
                    }
                }
            }
            
            let accuracy = correct_severities as f64 / total as f64;
            assert!(accuracy >= 0.8, "Severity classification accuracy too low");
            black_box(accuracy);
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    codebase_scanning_benchmark,
    false_positive_analysis,
    mixed_content_analysis,
    threat_detection_accuracy
);
criterion_main!(benches);