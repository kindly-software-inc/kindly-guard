#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{SecurityScanner, ScannerConfig};
use serde_json::Value;
use arbitrary::{Arbitrary, Unstructured};

// Custom arbitrary implementation for JSON values
#[derive(Debug)]
struct ArbitraryJson(Value);

impl<'a> Arbitrary<'a> for ArbitraryJson {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let depth = u.int_in_range(0..=5)?;
        Ok(ArbitraryJson(generate_json_value(u, depth)?))
    }
}

fn generate_json_value(u: &mut Unstructured, depth: u32) -> arbitrary::Result<Value> {
    if depth == 0 {
        // Base case: generate primitive values
        match u.int_in_range(0..=4)? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(u.arbitrary()?)),
            2 => Ok(Value::Number(serde_json::Number::from(u.arbitrary::<i64>()?).into())),
            3 => Ok(Value::String(u.arbitrary::<String>()?)),
            _ => Ok(Value::String("test".to_string())),
        }
    } else {
        // Recursive case: generate objects or arrays
        match u.int_in_range(0..=1)? {
            0 => {
                // Generate object
                let size = u.int_in_range(0..=10)?;
                let mut obj = serde_json::Map::new();
                for _ in 0..size {
                    let key = u.arbitrary::<String>()?;
                    let value = generate_json_value(u, depth - 1)?;
                    obj.insert(key, value);
                }
                Ok(Value::Object(obj))
            }
            _ => {
                // Generate array
                let size = u.int_in_range(0..=10)?;
                let mut arr = Vec::new();
                for _ in 0..size {
                    arr.push(generate_json_value(u, depth - 1)?);
                }
                Ok(Value::Array(arr))
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Test with raw JSON parsing
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(json_value) = serde_json::from_str::<Value>(json_str) {
            let config = ScannerConfig {
                unicode_detection: true,
                injection_detection: true,
                path_traversal_detection: true,
                custom_patterns: None,
                max_scan_depth: 10,
                enable_event_buffer: false,
            };
            
            if let Ok(scanner) = SecurityScanner::new(config) {
                let _ = scanner.scan_json(&json_value);
            }
        }
    }
    
    // Test with arbitrary JSON generation
    let mut u = Unstructured::new(data);
    if let Ok(arb_json) = ArbitraryJson::arbitrary(&mut u) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            let _ = scanner.scan_json(&arb_json.0);
            
            // Also test with very deep nesting
            let mut deeply_nested = arb_json.0.clone();
            for _ in 0..50 {
                deeply_nested = Value::Object(
                    serde_json::Map::from_iter(vec![("nested".to_string(), deeply_nested)])
                );
            }
            let _ = scanner.scan_json(&deeply_nested);
        }
    }
});