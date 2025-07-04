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
#!/usr/bin/env rust-script
//! Deep analysis of KindlyGuard threat detection capabilities
//!
//! ```cargo
//! [dependencies]
//! kindly-guard-core = { path = "./kindly-guard-core" }
//! serde_json = "1.0"
//! anyhow = "1.0"
//! ```

use kindly_guard_core::{PatternMatcher, ThreatClassifier, UnicodeNormalizer};
use std::collections::HashMap;

fn main() -> anyhow::Result<()> {
    println!("=== KindlyGuard Threat Detection Analysis ===\n");

    // Initialize components
    let pattern_matcher = PatternMatcher::new_with_defaults()?;
    let unicode_normalizer = UnicodeNormalizer::new();
    let threat_classifier = ThreatClassifier::new()?;

    // Test cases organized by category
    let test_cases = vec![
        // SQL Injection tests
        ("SQL: Basic OR injection", "' OR '1'='1"),
        ("SQL: Union Select", "' UNION SELECT * FROM users--"),
        ("SQL: Drop table", "'; DROP TABLE users;--"),
        ("SQL: Time-based blind", "' AND SLEEP(5)--"),
        ("SQL: Stacked queries", "'; INSERT INTO logs VALUES('hacked');--"),
        ("SQL: Comment injection", "admin'--"),
        ("SQL: Case variation", "' Or '1'='1"),
        ("SQL: Encoded injection", "%27%20OR%20%271%27%3D%271"),
        
        // XSS tests
        ("XSS: Basic script", "<script>alert('xss')</script>"),
        ("XSS: IMG onerror", "<img src=x onerror='alert(1)'>"),
        ("XSS: JavaScript URI", "<a href='javascript:alert(1)'>click</a>"),
        ("XSS: Event handler", "<div onclick='alert(1)'>click</div>"),
        ("XSS: SVG injection", "<svg onload=alert(1)>"),
        ("XSS: Encoded script", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("XSS: CSS injection", "<style>body{background:url('javascript:alert(1)')}</style>"),
        
        // Path Traversal tests
        ("Path: Basic traversal", "../../etc/passwd"),
        ("Path: Windows traversal", "..\\..\\windows\\system32"),
        ("Path: URL encoded", "..%2F..%2Fetc%2Fpasswd"),
        ("Path: Double encoding", "..%252F..%252Fetc%252Fpasswd"),
        ("Path: Unicode encoding", "..%c0%af..%c0%afetc%c0%afpasswd"),
        
        // Command Injection tests  
        ("CMD: Basic injection", "; ls -la"),
        ("CMD: Pipe injection", "| cat /etc/passwd"),
        ("CMD: Backtick injection", "`rm -rf /`"),
        ("CMD: AND injection", "&& whoami"),
        ("CMD: Newline injection", "\nwhoami"),
        
        // Unicode exploit tests
        ("Unicode: RTL Override", "Hello\u{202E}World"),
        ("Unicode: Zero Width Space", "Pass\u{200B}word"),
        ("Unicode: Zero Width Joiner", "Test\u{200D}Case"),
        ("Unicode: Homograph", "pаypal.com"), // Cyrillic 'а'
        ("Unicode: Bidi isolate", "Test\u{2066}Evil\u{2069}Text"),
        
        // Safe texts (should not trigger)
        ("Safe: Normal text", "This is completely safe text"),
        ("Safe: Code snippet", "if (x > 0) { return true; }"),
        ("Safe: JSON", r#"{"name": "John", "age": 30}"#),
        ("Safe: URL", "https://example.com/page?id=123"),
    ];

    let mut results = HashMap::new();
    let mut false_positives = Vec::new();
    let mut false_negatives = Vec::new();

    println!("Running {} test cases...\n", test_cases.len());

    for (name, test_input) in &test_cases {
        // Scan with pattern matcher
        let threats = pattern_matcher.scan(test_input);
        
        // Check unicode
        let unicode_threats = unicode_normalizer.find_hidden_characters(test_input);
        
        let is_safe = name.starts_with("Safe:");
        let threat_found = !threats.is_empty() || unicode_threats.is_some();
        
        if is_safe && threat_found {
            false_positives.push(name.to_string());
        } else if !is_safe && !threat_found {
            false_negatives.push(name.to_string());
        }
        
        results.insert(name.to_string(), (threats.clone(), unicode_threats.clone()));
        
        // Print detailed results
        println!("Test: {}", name);
        println!("Input: {:?}", test_input);
        if !threats.is_empty() {
            for threat in &threats {
                println!("  ✓ Detected: {:?} (confidence: {:.2})", 
                    threat.threat_type, threat.confidence);
            }
        } else if unicode_threats.is_some() {
            println!("  ✓ Unicode threat detected");
        } else {
            println!("  ✗ No threats detected");
        }
        println!();
    }

    // Summary
    println!("\n=== ANALYSIS SUMMARY ===\n");
    
    let total_threats = test_cases.iter()
        .filter(|(name, _)| !name.starts_with("Safe:"))
        .count();
    let detected_threats = total_threats - false_negatives.len();
    let detection_rate = (detected_threats as f64 / total_threats as f64) * 100.0;
    
    println!("Detection Rate: {:.1}% ({}/{})", detection_rate, detected_threats, total_threats);
    println!("False Positives: {} ({:.1}%)", 
        false_positives.len(), 
        (false_positives.len() as f64 / test_cases.len() as f64) * 100.0);
    println!("False Negatives: {} ({:.1}%)", 
        false_negatives.len(),
        (false_negatives.len() as f64 / total_threats as f64) * 100.0);
    
    if !false_positives.is_empty() {
        println!("\nFalse Positives:");
        for fp in &false_positives {
            println!("  - {}", fp);
        }
    }
    
    if !false_negatives.is_empty() {
        println!("\nFalse Negatives (CRITICAL - Not Detected):");
        for fn_case in &false_negatives {
            println!("  - {}", fn_case);
        }
    }

    // Pattern coverage analysis
    println!("\n=== PATTERN COVERAGE ANALYSIS ===\n");
    
    // Check current patterns in implementation
    let patterns = vec![
        ("SQL: UNION SELECT", r"(?i)union.*select"),
        ("SQL: DROP TABLE", r"(?i)drop\s+table"),
        ("XSS: Script tag", r"<script[^>]*>"),
        ("XSS: Event handler", r"onerror\s*="),
        ("CMD: Command separator", r";\s*(ls|cat|rm|wget)"),
        ("Path: Traversal", r"\.\./\.\./"),
    ];
    
    println!("Current Pattern Coverage:");
    for (pattern_name, pattern_regex) in patterns {
        println!("  - {}: {}", pattern_name, pattern_regex);
    }
    
    println!("\n=== RECOMMENDATIONS ===\n");
    
    println!("1. CRITICAL GAPS:");
    println!("   - No detection for SQL time-based blind injection");
    println!("   - Missing encoded injection patterns (URL, HTML entities)");
    println!("   - No detection for advanced XSS (SVG, CSS)");
    println!("   - Limited command injection patterns");
    println!("   - No homograph attack detection");
    
    println!("\n2. FALSE NEGATIVE ISSUES:");
    println!("   - Pattern matching is too simplistic (string contains)");
    println!("   - No regex support in current implementation");
    println!("   - Case sensitivity issues");
    println!("   - No context-aware detection");
    
    println!("\n3. PERFORMANCE CONCERNS:");
    println!("   - String.contains() is O(n*m) worst case");
    println!("   - No actual SIMD optimization despite claims");
    println!("   - JSON scanning is inefficient (converts to string)");
    
    println!("\n4. SECURITY RECOMMENDATIONS:");
    println!("   - Implement proper regex-based pattern matching");
    println!("   - Add context-aware detection");
    println!("   - Implement encoding/decoding detection");
    println!("   - Add machine learning for adaptive threats");
    println!("   - Implement proper Unicode normalization (NFC/NFD)");

    Ok(())
}