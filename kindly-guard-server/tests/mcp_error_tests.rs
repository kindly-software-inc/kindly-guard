//! MCP Protocol Error Handling Tests
//! Tests various error conditions and edge cases

use kindly_guard_server::{Config, McpServer};
use serde_json::{json, Value};
use std::sync::Arc;

mod helpers;
use helpers::*;

fn create_test_server() -> Arc<McpServer> {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = false;
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

#[tokio::test]
async fn test_jsonrpc_parse_errors() {
    let server = create_test_server();

    // Test various malformed JSON inputs
    let test_cases = vec![
        ("", "Empty input"),
        ("{", "Unclosed brace"),
        ("null", "Null input"),
        ("[]", "Empty array"),
        ("{\"foo\": }", "Invalid value"),
        ("{'jsonrpc': '2.0'}", "Single quotes"),
        ("{\"jsonrpc\": 2.0}", "Numeric version"),
    ];

    for (input, description) in test_cases {
        let response = server.handle_message(input).await;
        assert!(response.is_some(), "Should return error for: {description}");

        let response_json: Value = serde_json::from_str(&response.unwrap())
            .unwrap_or_else(|_| panic!("Should return valid JSON error for: {description}"));

        validate_jsonrpc_error(&response_json, -32700); // Parse error
    }
}

#[tokio::test]
async fn test_jsonrpc_invalid_request_errors() {
    let server = create_test_server();

    // Test various invalid request structures
    let test_cases = vec![
        (json!({}), "Empty object"),
        (json!({"jsonrpc": "2.0"}), "Missing method"),
        (json!({"method": "test"}), "Missing jsonrpc"),
        (json!({"jsonrpc": "1.0", "method": "test"}), "Wrong version"),
        (
            json!({"jsonrpc": "2.0", "method": 123}),
            "Non-string method",
        ),
        (
            json!({"jsonrpc": "2.0", "method": "test", "params": "invalid"}),
            "String params",
        ),
        (
            json!({"jsonrpc": "2.0", "method": "test", "id": "invalid"}),
            "String id for number",
        ),
    ];

    for (input, description) in test_cases {
        let response = server
            .handle_message(&input.to_string())
            .await
            .unwrap_or_else(|| panic!("Should return response for: {description}"));

        let response_json: Value = serde_json::from_str(&response)
            .unwrap_or_else(|_| panic!("Should return valid JSON for: {description}"));

        assert!(
            response_json["error"].is_object(),
            "Should have error for: {description}"
        );
        assert!(
            response_json["error"]["code"].as_i64().unwrap() < 0,
            "Error code should be negative for: {description}"
        );
    }
}

#[tokio::test]
async fn test_method_not_found_errors() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test non-existent methods
    let test_methods = vec![
        "nonexistent",
        "tools/nonexistent",
        "resources/write",       // We don't support write
        "prompts/create",        // We don't support create
        "../../../etc/passwd",   // Path traversal attempt
        "tools/../admin/delete", // Path traversal in method
        "",                      // Empty method
        "SELECT * FROM methods", // SQL injection attempt
    ];

    for (i, method) in test_methods.iter().enumerate() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": {},
            "id": i + 2
        });

        let response = server
            .handle_message(&request.to_string())
            .await
            .unwrap_or_else(|| panic!("Should return response for method: {method}"));

        let response_json: Value = serde_json::from_str(&response)
            .unwrap_or_else(|_| panic!("Should return valid JSON for method: {method}"));

        validate_jsonrpc_error(&response_json, -32601); // Method not found
    }
}

#[tokio::test]
async fn test_invalid_params_errors() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test invalid parameters for various methods
    let test_cases = vec![
        // Missing required params
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {},
                "id": 2
            }),
            "Missing tool name",
        ),
        // Wrong param types
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": 123,
                    "arguments": {}
                },
                "id": 3
            }),
            "Non-string tool name",
        ),
        // Missing required arguments
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "scan_text",
                    "arguments": {}
                },
                "id": 4
            }),
            "Missing text argument",
        ),
        // Extra unknown params
        (
            json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {
                    "unknown": "param"
                },
                "id": 5
            }),
            "Unknown parameter",
        ),
    ];

    for (request, description) in test_cases {
        let response = server
            .handle_message(&request.to_string())
            .await
            .unwrap_or_else(|| panic!("Should return response for: {description}"));

        let response_json: Value = serde_json::from_str(&response)
            .unwrap_or_else(|_| panic!("Should return valid JSON for: {description}"));

        validate_jsonrpc_error(&response_json, -32602); // Invalid params
    }
}

#[tokio::test]
async fn test_internal_errors() {
    let server = create_test_server();

    // Test scenarios that might cause internal errors

    // Very deeply nested JSON
    let mut deeply_nested = json!({"value": "test"});
    for _ in 0..100 {
        deeply_nested = json!({"nested": deeply_nested});
    }

    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_json",
            "arguments": {
                "json": deeply_nested
            }
        },
        "id": 1
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");

    let response_json: Value = serde_json::from_str(&response).unwrap();

    // Should either succeed or return a proper error (not panic)
    assert!(
        response_json["result"].is_object() || response_json["error"].is_object(),
        "Should handle deeply nested JSON gracefully"
    );
}

#[tokio::test]
async fn test_batch_request_errors() {
    let server = create_test_server();

    // Empty batch
    let empty_batch = json!([]);
    let response = server
        .handle_message(&empty_batch.to_string())
        .await
        .expect("Should return error for empty batch");

    let response_json: Value = serde_json::from_str(&response).unwrap();
    validate_jsonrpc_error(&response_json, -32600); // Invalid request

    // Batch with invalid items
    let invalid_batch = json!([
        {"jsonrpc": "2.0", "method": "test", "id": 1},
        "invalid",
        null,
        {"method": "test2", "id": 2}
    ]);

    let response = server
        .handle_message(&invalid_batch.to_string())
        .await
        .expect("Should return responses for batch");

    let response_json: Value = serde_json::from_str(&response).unwrap();
    assert!(response_json.is_array(), "Should return array for batch");

    let responses = response_json.as_array().unwrap();
    assert!(
        responses.len() >= 2,
        "Should have responses for valid items"
    );
}

#[tokio::test]
async fn test_notification_errors() {
    let server = create_test_server();

    // Invalid notification (notifications shouldn't have id)
    let invalid_notification = json!({
        "jsonrpc": "2.0",
        "method": "notification/test",
        "params": {},
        "id": null  // Null id is still an id
    });

    let response = server
        .handle_message(&invalid_notification.to_string())
        .await;

    // Should return error since null id makes it a request, not notification
    assert!(
        response.is_some(),
        "Should return error for invalid notification"
    );
}

#[tokio::test]
async fn test_concurrent_error_handling() {
    let server = create_test_server();

    // Send multiple error-inducing requests concurrently
    let mut handles = vec![];

    for i in 0..20 {
        let server = server.clone();
        let handle = tokio::spawn(async move {
            let request = if i % 2 == 0 {
                // Invalid JSON
                "{invalid json}".to_string()
            } else {
                // Valid JSON but invalid request
                json!({
                    "jsonrpc": "2.0",
                    "method": format!("invalid_method_{}", i),
                    "id": i
                })
                .to_string()
            };

            server.handle_message(&request).await
        });
        handles.push(handle);
    }

    // All should complete without panicking
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_some(), "Should return error response");
    }
}

#[tokio::test]
async fn test_oversized_id_handling() {
    let server = create_test_server();

    // Test with very large ID numbers
    let large_id_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": u64::MAX
    });

    let response = server
        .handle_message(&large_id_request.to_string())
        .await
        .expect("Should handle large IDs");

    let response_json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response_json["id"], u64::MAX);
}

#[tokio::test]
async fn test_special_characters_in_params() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test with various special characters
    let special_chars = vec![
        "\u{0000}",             // Null byte
        "\u{FFFF}",             // Max BMP character
        "\\",                   // Backslash
        "\"",                   // Quote
        "\n\r\t",               // Whitespace
        "\u{1F4A9}",            // Emoji
        "\u{202E}test\u{202C}", // Bidi override
    ];

    for (i, chars) in special_chars.iter().enumerate() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": format!("Test {} string", chars)
                }
            },
            "id": i + 2
        });

        let response = server
            .handle_message(&request.to_string())
            .await
            .expect("Should handle special characters");

        let response_json: Value = serde_json::from_str(&response).unwrap();

        // Should either scan successfully or return proper error
        assert!(
            response_json["result"].is_object() || response_json["error"].is_object(),
            "Should handle special characters gracefully"
        );
    }
}
