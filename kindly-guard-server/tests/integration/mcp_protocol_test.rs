use kindly_guard_server::{
    config::Config,
    server::KindlyGuardServer,
    protocol::types::{McpRequest, McpResponse, ToolInfo},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Helper to create a test server
async fn create_test_server() -> Arc<KindlyGuardServer> {
    let config = Config::default();
    let server = KindlyGuardServer::new(config).await
        .expect("Failed to create server");
    Arc::new(server)
}

/// Test the full MCP handshake process
#[tokio::test]
async fn test_mcp_handshake() {
    let server = create_test_server().await;
    
    // Initialize request
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    let response = server.handle_request(
        serde_json::from_value(init_request).unwrap()
    ).await.unwrap();

    // Verify response
    match response {
        McpResponse::Initialize { capabilities, .. } => {
            assert!(capabilities.tools.is_some());
        }
        _ => panic!("Expected Initialize response"),
    }

    // Initialized notification
    let initialized_request = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });

    let response = server.handle_request(
        serde_json::from_value(initialized_request).unwrap()
    ).await;

    assert!(response.is_ok());
}

/// Test that all tool methods work correctly
#[tokio::test]
async fn test_all_tool_methods() {
    let server = create_test_server().await;
    
    // Initialize first
    let init_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            }
        },
        "id": 1
    })).unwrap();
    
    server.handle_request(init_request).await.unwrap();

    // List tools
    let list_tools_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    })).unwrap();

    let response = server.handle_request(list_tools_request).await.unwrap();
    
    let tools = match response {
        McpResponse::ToolsList { tools } => tools,
        _ => panic!("Expected ToolsList response"),
    };

    // Verify we have the expected tools
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"scan_text"));
    assert!(tool_names.contains(&"scan_file"));
    assert!(tool_names.contains(&"get_stats"));
    assert!(tool_names.contains(&"clear_threats"));

    // Test scan_text tool
    let scan_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "Hello World"
            }
        },
        "id": 3
    })).unwrap();

    let response = server.handle_request(scan_request).await.unwrap();
    
    match response {
        McpResponse::ToolCall { content } => {
            assert!(!content.is_empty());
            let result = &content[0];
            assert_eq!(result.type_, "text");
        }
        _ => panic!("Expected ToolCall response"),
    }
}

/// Test error handling for malformed requests
#[tokio::test]
async fn test_malformed_request_handling() {
    let server = create_test_server().await;
    
    // Missing required fields
    let bad_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call"
        // Missing params and id
    });

    let result = serde_json::from_value::<McpRequest>(bad_request);
    assert!(result.is_err(), "Should fail to parse malformed request");

    // Invalid method
    let invalid_method: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "invalid/method",
        "params": {},
        "id": 1
    })).unwrap();

    let response = server.handle_request(invalid_method).await;
    assert!(response.is_err(), "Should fail on invalid method");

    // Wrong tool name
    let wrong_tool: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        },
        "id": 2
    })).unwrap();

    let response = server.handle_request(wrong_tool).await;
    assert!(response.is_err(), "Should fail on nonexistent tool");
}

/// Test concurrent request handling
#[tokio::test]
async fn test_concurrent_requests() {
    let server = create_test_server().await;
    
    // Initialize first
    let init_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            }
        },
        "id": 0
    })).unwrap();
    
    server.handle_request(init_request).await.unwrap();

    // Create multiple concurrent requests
    let mut handles = vec![];
    
    for i in 1..=10 {
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let request: McpRequest = serde_json::from_value(json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "scan_text",
                    "arguments": {
                        "text": format!("Test text {}", i)
                    }
                },
                "id": i
            })).unwrap();
            
            server_clone.handle_request(request).await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;
    
    // Verify all succeeded
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Concurrent request {} failed: {:?}",
            i + 1,
            result
        );
        
        let response = result.as_ref().unwrap();
        assert!(
            response.is_ok(),
            "Request {} returned error: {:?}",
            i + 1,
            response
        );
    }
}

/// Test scan_file with various file types
#[tokio::test]
async fn test_scan_file_tool() {
    let server = create_test_server().await;
    
    // Initialize
    let init_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            }
        },
        "id": 1
    })).unwrap();
    
    server.handle_request(init_request).await.unwrap();

    // Create a test file
    let test_file = std::env::temp_dir().join("test_scan.txt");
    std::fs::write(&test_file, "SELECT * FROM users WHERE id = 1").unwrap();

    // Scan the file
    let scan_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_file",
            "arguments": {
                "path": test_file.to_str().unwrap()
            }
        },
        "id": 2
    })).unwrap();

    let response = server.handle_request(scan_request).await.unwrap();
    
    match response {
        McpResponse::ToolCall { content } => {
            assert!(!content.is_empty());
            // Should detect SQL pattern
            let result_text = &content[0].text;
            assert!(
                result_text.contains("SQL") || result_text.contains("pattern"),
                "Should detect SQL pattern in file"
            );
        }
        _ => panic!("Expected ToolCall response"),
    }

    // Clean up
    std::fs::remove_file(test_file).ok();
}

/// Test get_stats tool
#[tokio::test]
async fn test_get_stats_tool() {
    let server = create_test_server().await;
    
    // Initialize
    let init_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            }
        },
        "id": 1
    })).unwrap();
    
    server.handle_request(init_request).await.unwrap();

    // Scan some text to generate stats
    let scan_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "Test with \u{202E}bidi override"
            }
        },
        "id": 2
    })).unwrap();

    server.handle_request(scan_request).await.unwrap();

    // Get stats
    let stats_request: McpRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_stats",
            "arguments": {}
        },
        "id": 3
    })).unwrap();

    let response = server.handle_request(stats_request).await.unwrap();
    
    match response {
        McpResponse::ToolCall { content } => {
            assert!(!content.is_empty());
            let stats_text = &content[0].text;
            assert!(stats_text.contains("scanned"));
            assert!(stats_text.contains("threat"));
        }
        _ => panic!("Expected ToolCall response"),
    }
}

/// Test protocol version negotiation
#[tokio::test]
async fn test_protocol_version_negotiation() {
    let server = create_test_server().await;
    
    // Try with different protocol versions
    let versions = ["2024-11-05", "2024-10-01", "2023-01-01"];
    
    for version in &versions {
        let init_request: McpRequest = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {
                    "tools": {}
                }
            },
            "id": 1
        })).unwrap();
        
        let response = server.handle_request(init_request).await;
        
        // Should handle all versions gracefully
        assert!(
            response.is_ok(),
            "Failed to handle protocol version {}: {:?}",
            version,
            response
        );
    }
}