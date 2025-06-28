#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{McpServer, Config};
use serde_json::Value;
use std::sync::Arc;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct McpTestCase {
    method: String,
    params: ArbitraryJson,
    id: Option<u64>,
    malformed: bool,
}

#[derive(Debug)]
struct ArbitraryJson(Value);

impl Arbitrary<'_> for ArbitraryJson {
    fn arbitrary(u: &mut Unstructured) -> arbitrary::Result<Self> {
        let depth = u.int_in_range(0..=3)?;
        Ok(ArbitraryJson(generate_json(u, depth)?))
    }
}

fn generate_json(u: &mut Unstructured, depth: u32) -> arbitrary::Result<Value> {
    if depth == 0 {
        // Leaf nodes
        match u.int_in_range(0..=5)? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(u.arbitrary()?)),
            2 => Ok(Value::Number(serde_json::Number::from(u.int_in_range(0..=1000)?))),
            3 => Ok(Value::String(u.arbitrary::<String>()?)),
            4 => Ok(Value::String(format!("../../{}", u.arbitrary::<String>()?))), // Path traversal
            5 => Ok(Value::String(format!("'; DROP TABLE users; --", ))), // SQL injection
            _ => unreachable!(),
        }
    } else {
        // Containers
        match u.int_in_range(0..=1)? {
            0 => {
                // Array
                let len = u.int_in_range(0..=5)?;
                let mut arr = Vec::new();
                for _ in 0..len {
                    arr.push(generate_json(u, depth - 1)?);
                }
                Ok(Value::Array(arr))
            }
            1 => {
                // Object
                let len = u.int_in_range(0..=5)?;
                let mut obj = serde_json::Map::new();
                for _ in 0..len {
                    let key = u.arbitrary::<String>()?;
                    let value = generate_json(u, depth - 1)?;
                    obj.insert(key, value);
                }
                Ok(Value::Object(obj))
            }
            _ => unreachable!(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Try to generate structured test case
    let test_case = match Unstructured::new(data).arbitrary::<McpTestCase>() {
        Ok(tc) => tc,
        Err(_) => {
            // Fall back to raw JSON testing
            test_raw_json(data);
            return;
        }
    };

    // Create a runtime for async operations
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        // Create server
        let config = Config::default();
        let server = match McpServer::new(config).await {
            Ok(s) => Arc::new(s),
            Err(_) => return,
        };

        // Test normal JSON-RPC request
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": test_case.method,
            "params": test_case.params.0,
            "id": test_case.id,
        });

        let _ = server.handle_json_rpc(request).await;

        // Test malformed variations
        if test_case.malformed {
            // Missing jsonrpc field
            let malformed1 = serde_json::json!({
                "method": test_case.method,
                "params": test_case.params.0,
            });
            let _ = server.handle_json_rpc(malformed1).await;

            // Wrong jsonrpc version
            let malformed2 = serde_json::json!({
                "jsonrpc": "1.0",
                "method": test_case.method,
                "params": test_case.params.0,
            });
            let _ = server.handle_json_rpc(malformed2).await;

            // Invalid method names
            let invalid_methods = vec![
                "../../../etc/passwd",
                "'; system('rm -rf /'); //",
                "\u{202E}initialize",
                "initialize\x00",
                std::str::from_utf8(&vec![0xFF; 100]).unwrap_or("invalid"),
            ];

            for method in invalid_methods {
                let malformed = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": test_case.params.0,
                    "id": 1,
                });
                let _ = server.handle_json_rpc(malformed).await;
            }
        }

        // Test batch requests
        let batch = vec![request; 3];
        if let Ok(batch_value) = serde_json::to_value(batch) {
            let _ = server.handle_json_rpc(batch_value).await;
        }
    });
});

fn test_raw_json(data: &[u8]) {
    // Try to parse as JSON and test with server
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(value) = serde_json::from_str::<Value>(json_str) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let config = Config::default();
                if let Ok(server) = McpServer::new(config).await {
                    let _ = server.handle_json_rpc(value).await;
                }
            });
        }
    }
}