//! Comprehensive MCP Protocol Test Suite
//! Tests all MCP methods, error conditions, and edge cases

use base64::{engine::general_purpose, Engine as _};
use kindly_guard_server::{Config, McpServer};
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_test::io::Builder;

mod helpers;
use helpers::*;

/// Test helper to create a test server
fn create_test_server() -> Arc<McpServer> {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = false; // Disable auth for protocol tests
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

/// Test helper to create an authenticated test server
fn create_auth_server() -> Arc<McpServer> {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = true;
    config.auth.jwt_secret = Some(general_purpose::STANDARD.encode(b"test-secret-key"));
    config.auth.require_signature_verification = true;
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

#[tokio::test]
async fn test_mcp_initialize() {
    let server = create_test_server();

    let request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {
                    "listChanged": true
                },
                "sampling": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], 1);
    assert!(response_json["result"].is_object());

    let result = &response_json["result"];
    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert!(result["capabilities"].is_object());
    assert!(result["serverInfo"].is_object());
    assert_eq!(result["serverInfo"]["name"], "kindly-guard");
}

#[tokio::test]
async fn test_mcp_initialize_wrong_version() {
    let server = create_test_server();

    let request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "1.0.0", // Wrong version
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return error response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["error"].is_object());
    assert_eq!(response_json["error"]["code"], -32602); // Invalid params
}

#[tokio::test]
async fn test_mcp_tools_list() {
    let server = create_test_server();

    // First initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Then list tools
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    let tools = response_json["result"]["tools"].as_array().unwrap();

    // Verify all expected tools are present
    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(tool_names.contains(&"scan_text"));
    assert!(tool_names.contains(&"scan_json"));
    assert!(tool_names.contains(&"verify_signature"));
    assert!(tool_names.contains(&"get_security_info"));
    assert!(tool_names.contains(&"get_shield_status"));
}

#[tokio::test]
async fn test_mcp_tool_call_scan_text() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test clean text
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "This is safe text"
            }
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    println!("Raw response: {}", response);
    let response_json: Value = serde_json::from_str(&response).unwrap();
    println!(
        "Parsed response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );

    let result = &response_json["result"]["content"][0];
    assert_eq!(result["type"], "text");
    let content: Value = serde_json::from_str(result["text"].as_str().unwrap()).unwrap();
    assert_eq!(content["safe"], true);
    assert!(content["threats"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_mcp_tool_call_scan_text_with_threat() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test SQL injection
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
            }
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    println!("Raw response: {}", response);
    let response_json: Value = serde_json::from_str(&response).unwrap();
    println!(
        "Parsed response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );

    let result = &response_json["result"]["content"][0];
    let content: Value = serde_json::from_str(result["text"].as_str().unwrap()).unwrap();
    assert_eq!(content["safe"], false);
    assert!(!content["threats"].as_array().unwrap().is_empty());

    let threat = &content["threats"][0];
    assert_eq!(threat["type"], "sql_injection");
    assert_eq!(threat["severity"], "high");
}

#[tokio::test]
async fn test_mcp_tool_call_invalid_tool() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return error response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["error"].is_object());
    assert_eq!(response_json["error"]["code"], -32602); // Invalid params
    assert!(response_json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Unknown tool"));
}

#[tokio::test]
async fn test_mcp_batch_request() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Batch request with multiple operations
    let batch_request = json!([
        {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        },
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_security_info",
                "arguments": {}
            },
            "id": 3
        },
        {
            "jsonrpc": "2.0",
            "method": "resources/list",
            "params": {},
            "id": 4
        }
    ]);

    let response = server
        .handle_message(&batch_request.to_string())
        .await
        .expect("Should return batch response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json.is_array());
    let responses = response_json.as_array().unwrap();
    assert_eq!(responses.len(), 3);

    // Verify each response
    assert_eq!(responses[0]["id"], 2);
    assert!(responses[0]["result"]["tools"].is_array());

    assert_eq!(responses[1]["id"], 3);
    assert!(responses[1]["result"]["content"].is_array());

    assert_eq!(responses[2]["id"], 4);
    assert!(responses[2]["result"]["resources"].is_array());
}

#[tokio::test]
async fn test_mcp_notification() {
    let server = create_test_server();

    // Notifications don't have an id and shouldn't get a response
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": "test-token",
            "progress": 50,
            "total": 100
        }
    });

    let response = server.handle_message(&notification.to_string()).await;
    assert!(response.is_none()); // No response for notifications
}

#[tokio::test]
async fn test_mcp_auth_required() {
    let server = create_auth_server();

    // Try to call tool without auth
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test"
            }
        },
        "id": 1
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return error response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["error"].is_object());
    assert_eq!(response_json["error"]["code"], -32001); // Unauthorized
}

#[tokio::test]
async fn test_mcp_auth_with_token() {
    let server = create_auth_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Call tool with valid auth token
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test",
                "_meta": {
                    "authToken": "test-token-123"
                }
            }
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    // Debug output
    if response_json["error"].is_object() {
        eprintln!(
            "Auth test failed with error: {}",
            serde_json::to_string_pretty(&response_json["error"]).unwrap()
        );
    }

    assert!(response_json["result"].is_object());
    assert!(response_json["error"].is_null());
}

#[tokio::test]
async fn test_mcp_malformed_json() {
    let server = create_test_server();

    let malformed = "{ invalid json }";

    let response = server
        .handle_message(malformed)
        .await
        .expect("Should return parse error");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["error"].is_object());
    assert_eq!(response_json["error"]["code"], -32700); // Parse error
}

#[tokio::test]
async fn test_mcp_missing_method() {
    let server = create_test_server();

    let request = json!({
        "jsonrpc": "2.0",
        "params": {},
        "id": 1
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return error");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["error"].is_object());
    assert_eq!(response_json["error"]["code"], -32600); // Invalid request
}

#[tokio::test]
async fn test_mcp_resources_list() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    let request = json!({
        "jsonrpc": "2.0",
        "method": "resources/list",
        "params": {},
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    let resources = response_json["result"]["resources"].as_array().unwrap();

    // Should have security config and threat db resources
    assert!(resources.iter().any(|r| r["name"] == "security-config"));
    assert!(resources.iter().any(|r| r["name"] == "threat-database"));
}

#[tokio::test]
async fn test_mcp_prompts_list() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    let request = json!({
        "jsonrpc": "2.0",
        "method": "prompts/list",
        "params": {},
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    let prompts = response_json["result"]["prompts"].as_array().unwrap();

    // Should have security analysis prompts
    assert!(prompts.iter().any(|p| p["name"] == "analyze-security"));
    assert!(prompts.iter().any(|p| p["name"] == "threat-report"));
}

#[tokio::test]
async fn test_mcp_prompts_get() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    let request = json!({
        "jsonrpc": "2.0",
        "method": "prompts/get",
        "params": {
            "name": "analyze-security",
            "arguments": {
                "target": "test input"
            }
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should return response");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    assert!(response_json["result"]["messages"].is_array());

    let messages = response_json["result"]["messages"].as_array().unwrap();
    assert!(!messages.is_empty());
    assert_eq!(messages[0]["role"], "user");
    assert!(messages[0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("test input"));
}

// Performance and edge case tests
#[tokio::test]
async fn test_mcp_large_payload() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Create a large text payload (1MB)
    let large_text = "a".repeat(1024 * 1024);

    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": large_text
            }
        },
        "id": 2
    });

    let response = server
        .handle_message(&request.to_string())
        .await
        .expect("Should handle large payload");
    let response_json: Value = serde_json::from_str(&response).unwrap();

    // Should complete without error
    assert!(response_json["result"].is_object());
}

#[tokio::test]
async fn test_mcp_concurrent_requests() {
    let server = create_test_server();

    // Initialize first
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Send multiple concurrent requests
    let mut handles = vec![];
    for i in 0..10 {
        let server = server.clone();
        let handle = tokio::spawn(async move {
            let request = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "scan_text",
                    "arguments": {
                        "text": format!("test {}", i)
                    }
                },
                "id": i + 2
            });

            server.handle_message(&request.to_string()).await
        });
        handles.push(handle);
    }

    // All requests should complete successfully
    for handle in handles {
        let response = handle.await.unwrap().expect("Should return response");
        let response_json: Value = serde_json::from_str(&response).unwrap();
        assert!(response_json["result"].is_object());
    }
}
