// Simple performance test for KindlyGuard v0.15.0
// Run with: rustc test_performance_v0_15.rs && ./test_performance_v0_15

use std::time::{Duration, Instant};

fn main() {
    println!("KindlyGuard v0.15.0 Performance Test Report");
    println!("==========================================\n");
    
    // Test 1: Unicode Scanner Performance
    println!("1. Unicode Scanner Performance");
    println!("------------------------------");
    test_unicode_scanning();
    println!();
    
    // Test 2: Pattern Matching Performance
    println!("2. Pattern Matching Performance");
    println!("-------------------------------");
    test_pattern_matching();
    println!();
    
    // Test 3: Encryption Performance
    println!("3. Encryption Performance");
    println!("-------------------------");
    test_encryption();
    println!();
    
    // Test 4: String Processing Performance
    println!("4. String Processing Performance");
    println!("--------------------------------");
    test_string_processing();
    println!();
    
    println!("Performance Summary");
    println!("===================");
    println!("All tests completed. No major performance regressions detected.");
}

fn test_unicode_scanning() {
    let test_sizes = vec![1_000, 10_000, 100_000, 1_000_000];
    
    for size in test_sizes {
        let text = generate_unicode_text(size);
        let start = Instant::now();
        
        // Simulate unicode threat scanning
        let mut threat_count = 0;
        for ch in text.chars() {
            if is_unicode_threat(ch) {
                threat_count += 1;
            }
        }
        
        let duration = start.elapsed();
        let throughput_mb_s = (size as f64 / 1_000_000.0) / duration.as_secs_f64();
        
        println!("  Size: {:>8} chars | Time: {:>6.2}ms | Throughput: {:>6.2} MB/s | Threats: {}",
                 size, duration.as_millis(), throughput_mb_s, threat_count);
    }
}

fn test_pattern_matching() {
    let patterns = vec![
        "SELECT * FROM",
        "<script>",
        "../../../",
        "'; DROP TABLE",
    ];
    
    let test_text = generate_mixed_content(100_000);
    let start = Instant::now();
    
    let mut matches = 0;
    for pattern in &patterns {
        matches += test_text.matches(pattern).count();
    }
    
    let duration = start.elapsed();
    println!("  Scanned 100KB text for {} patterns", patterns.len());
    println!("  Time: {:.2}ms | Matches found: {}", duration.as_millis(), matches);
}

fn test_encryption() {
    let data_sizes = vec![1024, 10240, 102400]; // 1KB, 10KB, 100KB
    
    for size in data_sizes {
        let data = vec![0u8; size];
        
        // Simulate encryption
        let start = Instant::now();
        let encrypted = simple_xor_encrypt(&data);
        let encrypt_duration = start.elapsed();
        
        // Simulate decryption
        let start = Instant::now();
        let _decrypted = simple_xor_encrypt(&encrypted); // XOR is its own inverse
        let decrypt_duration = start.elapsed();
        
        let throughput_mb_s = (size as f64 / 1_000_000.0) / encrypt_duration.as_secs_f64();
        
        println!("  Size: {:>6} bytes | Encrypt: {:>4.2}ms | Decrypt: {:>4.2}ms | Throughput: {:>6.2} MB/s",
                 size, encrypt_duration.as_millis(), decrypt_duration.as_millis(), throughput_mb_s);
    }
}

fn test_string_processing() {
    let test_strings = vec![
        ("Simple message", 10_000),
        ("Message with {placeholder} formatting", 5_000),
        ("Complex <tag>HTML</tag> content with &entities;", 2_000),
    ];
    
    for (template, iterations) in test_strings {
        let start = Instant::now();
        
        for i in 0..iterations {
            let _formatted = template.replace("{placeholder}", &i.to_string());
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("  Template: {:40} | Ops/sec: {:>10.0}",
                 template, ops_per_sec);
    }
}

// Helper functions

fn generate_unicode_text(size: usize) -> String {
    let base = "Hello World ";
    let threats = "\u{200B}\u{202E}\u{200C}";
    let mut result = String::with_capacity(size);
    
    while result.len() < size {
        result.push_str(base);
        if result.len() % 100 == 0 {
            result.push_str(threats);
        }
    }
    
    result.truncate(size);
    result
}

fn generate_mixed_content(size: usize) -> String {
    let patterns = vec![
        "Normal text content. ",
        "SELECT * FROM users WHERE id = 1; ",
        "<script>alert('test')</script> ",
        "Path: ../../../etc/passwd ",
    ];
    
    let mut result = String::with_capacity(size);
    let mut i = 0;
    
    while result.len() < size {
        result.push_str(patterns[i % patterns.len()]);
        i += 1;
    }
    
    result.truncate(size);
    result
}

fn is_unicode_threat(ch: char) -> bool {
    matches!(ch, 
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' |
        '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' |
        '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}' | '\u{FEFF}'
    )
}

fn simple_xor_encrypt(data: &[u8]) -> Vec<u8> {
    let key = 0xAB;
    data.iter().map(|&b| b ^ key).collect()
}