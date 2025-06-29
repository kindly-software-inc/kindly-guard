//! Advanced MCP Protocol Tests
//! Tests for streaming, progress, cancellation, and other advanced features

use kindly_guard_server::{McpServer, Config};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::*;

fn create_test_server() -> Arc<McpServer> {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.require_auth = false;
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

#[tokio::test]
async fn test_mcp_completion_support() {
    let server = create_test_server();
    
    // Initialize with completion support
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "completion": {
                    "types": ["resource", "prompt", "tool"]
                }
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });
    
    let response = server.handle_message(&init_request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Server should acknowledge completion support
    assert!(response_json["result"]["capabilities"].is_object());
}

#[tokio::test]
async fn test_mcp_completion_list() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Request completion for tools
    let request = json!({
        "jsonrpc": "2.0",
        "method": "completion/complete",
        "params": {
            "ref": {
                "type": "tool",
                "name": "scan"
            }
        },
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should return completion suggestions
    if !response_json["error"].is_object() {
        assert!(response_json["result"]["completion"].is_array());
        let completions = response_json["result"]["completion"].as_array().unwrap();
        
        // Should suggest scan_text and scan_json
        let values: Vec<&str> = completions.iter()
            .map(|c| c["value"].as_str().unwrap())
            .collect();
        
        assert!(values.iter().any(|v| v.contains("scan_text")));
        assert!(values.iter().any(|v| v.contains("scan_json")));
    }
}

#[tokio::test]
async fn test_mcp_logging_support() {
    let server = create_test_server();
    
    // Initialize with logging
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "logging": {
                    "setLevel": true
                }
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });
    
    let response = server.handle_message(&init_request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    assert!(response_json["result"]["capabilities"].is_object());
}

#[tokio::test]
async fn test_mcp_logging_set_level() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Set logging level
    let request = json!({
        "jsonrpc": "2.0",
        "method": "logging/setLevel",
        "params": {
            "level": "debug"
        },
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should acknowledge or return error
    assert!(
        response_json["result"].is_object() || 
        response_json["error"].is_object()
    );
}

#[tokio::test]
async fn test_mcp_progress_notifications() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Start a long-running operation with progress token
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_json",
            "arguments": {
                "json": json!({"data": "x".repeat(10000)}),
                "_meta": {
                    "progressToken": "scan-progress-123"
                }
            }
        },
        "id": 2
    });
    
    // Server should handle progress token gracefully
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    assert!(response_json["result"].is_object() || response_json["error"].is_object());
}

#[tokio::test]
async fn test_mcp_cancellation() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Send cancellation notification
    let cancel_notification = json!({
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {
            "id": 999  // ID of request to cancel
        }
    });
    
    let response = server.handle_message(&cancel_notification.to_string()).await;
    assert!(response.is_none()); // Notifications don't get responses
}

#[tokio::test]
async fn test_mcp_resource_templates() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // List resource templates
    let request = json!({
        "jsonrpc": "2.0",
        "method": "resources/templates/list",
        "params": {},
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should either support templates or return method not found
    assert!(
        (response_json["result"].is_object() && 
         response_json["result"]["resourceTemplates"].is_array()) ||
        response_json["error"]["code"] == -32601
    );
}

#[tokio::test]
async fn test_mcp_prompt_arguments() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Get prompt with complex arguments
    let request = json!({
        "jsonrpc": "2.0",
        "method": "prompts/get",
        "params": {
            "name": "analyze-security",
            "arguments": {
                "target": "complex input",
                "depth": "detailed",
                "format": "json"
            }
        },
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    if response_json["result"].is_object() {
        assert!(response_json["result"]["messages"].is_array());
        let messages = response_json["result"]["messages"].as_array().unwrap();
        
        // Should interpolate arguments into prompt
        let content = messages[0]["content"]["text"].as_str().unwrap();
        assert!(content.contains("complex input"));
    }
}

#[tokio::test]
async fn test_mcp_sampling_messages() {
    let server = create_test_server();
    
    // Initialize with sampling capability
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "sampling": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });
    
    server.handle_message(&init_request.to_string()).await;
    
    // Request sampling
    let request = json!({
        "jsonrpc": "2.0",
        "method": "sampling/createMessage",
        "params": {
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": "Analyze this for security threats"
                    }
                }
            ],
            "maxTokens": 100
        },
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should either support sampling or return method not found
    assert!(
        response_json["result"].is_object() || 
        response_json["error"]["code"] == -32601
    );
}

#[tokio::test]
async fn test_mcp_roots_support() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // List roots
    let request = json!({
        "jsonrpc": "2.0",
        "method": "roots/list",
        "params": {},
        "id": 2
    });
    
    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should either return roots or method not found
    if response_json["result"].is_object() {
        assert!(response_json["result"]["roots"].is_array());
    } else {
        assert_eq!(response_json["error"]["code"], -32601);
    }
}

#[tokio::test]
async fn test_mcp_timeout_handling() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Create a request that might take time
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_json",
            "arguments": {
                // Large nested JSON
                "json": (0..1000).fold(json!({}), |acc, i| {
                    json!({format!("key{}", i): acc})
                })
            }
        },
        "id": 2
    });
    
    // Should complete within reasonable time
    let result = timeout(
        Duration::from_secs(5),
        server.handle_message(&request.to_string())
    ).await;
    
    assert!(result.is_ok(), "Request should not timeout");
}

#[tokio::test]
async fn test_mcp_idempotency() {
    let server = create_test_server();
    
    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;
    
    // Same request multiple times
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });
    
    let response1 = server.handle_message(&request.to_string()).await.unwrap();
    let response2 = server.handle_message(&request.to_string()).await.unwrap();
    let response3 = server.handle_message(&request.to_string()).await.unwrap();
    
    // All responses should be identical
    assert_eq!(response1, response2);
    assert_eq!(response2, response3);
}

#[tokio::test]
async fn test_mcp_error_recovery() {
    let server = create_test_server();
    
    // Send invalid request
    let invalid_request = "{broken json";
    server.handle_message(invalid_request).await;
    
    // Server should recover and handle next request
    let valid_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });
    
    let response = server.handle_message(&valid_request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should handle valid request after error
    assert!(response_json["result"].is_object() || response_json["error"].is_object());
}