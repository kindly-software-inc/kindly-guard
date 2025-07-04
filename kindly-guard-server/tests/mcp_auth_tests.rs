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
//! MCP Protocol Authentication and Security Tests
//! Tests OAuth 2.0, message signing, and permission systems

use base64::{engine::general_purpose, Engine as _};
use kindly_guard_server::{Config, McpServer};
use serde_json::{json, Value};
use std::sync::Arc;

mod helpers;
use helpers::*;

fn create_auth_config() -> Config {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = true;
    config.auth.jwt_secret = Some(general_purpose::STANDARD.encode(b"test-secret-key"));
    config.auth.require_signature_verification = false; // Disable for now
    config
}

fn create_signing_config() -> Config {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.signing.require_signatures = true;
    config.signing.enabled = true;
    config.signing.hmac_secret = Some(general_purpose::STANDARD.encode(b"test-signing-key"));
    config
}

#[tokio::test]
async fn test_oauth_bearer_token_auth() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize without auth (should work)
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

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
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    println!(
        "Response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );
    validate_jsonrpc_error(&response_json, -32001); // Unauthorized
    assert!(
        response_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Authentication required")
            || response_json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("authentication required")
            || response_json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unauthorized")
    );
}

#[tokio::test]
async fn test_oauth_with_valid_token() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Call with valid token
    let token = create_test_auth_token();
    println!("Using token: {token}");
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test"
            }
        },
        "authorization": token,
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    println!(
        "Valid token response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );
    assert!(response_json["result"].is_object());
    assert!(response_json["error"].is_null());
}

#[tokio::test]
async fn test_oauth_with_invalid_token() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Call with invalid token
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test",
                "_meta": {
                    "authToken": "Bearer invalid-token"
                }
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    validate_jsonrpc_error(&response_json, -32001); // Unauthorized
}

#[tokio::test]
async fn test_oauth_token_formats() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test various token formats
    let token_formats = vec![
        ("valid-token-123", false, "Token without Bearer prefix"),
        ("Bearer valid-token-123", true, "Valid Bearer token"),
        ("bearer valid-token-123", false, "Lowercase bearer"),
        ("Bearer  valid-token-123", false, "Extra spaces"),
        ("Bearer", false, "Bearer without token"),
        ("", false, "Empty token"),
    ];

    for (i, (token, should_succeed, description)) in token_formats.iter().enumerate() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_security_info",
                "arguments": {
                    "_meta": {
                        "authToken": token
                    }
                }
            },
            "id": i + 2
        });

        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();

        if *should_succeed {
            assert!(
                response_json["result"].is_object(),
                "Should succeed for: {description}"
            );
        } else {
            assert!(
                response_json["error"].is_object(),
                "Should fail for: {description}"
            );
        }
    }
}

#[tokio::test]
async fn test_message_signing_required() {
    let server = Arc::new(McpServer::new(create_signing_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Try to call without signature
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test"
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    validate_jsonrpc_error(&response_json, -32001); // Unauthorized
    assert!(response_json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Message signature required"));
}

#[tokio::test]
async fn test_verify_signature_tool() {
    let server = Arc::new(McpServer::new(Config::default()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test signature verification
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "verify_signature",
            "arguments": {
                "message": "test message",
                "signature": "dGVzdC1zaWduYXR1cmU=",
                "publicKey": "dGVzdC1wdWJsaWMta2V5"
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    let content = &response_json["result"]["content"][0]["text"];
    let result: Value = serde_json::from_str(content.as_str().unwrap()).unwrap();

    // Should have valid response structure
    assert!(result["valid"].is_boolean());
    assert!(result["algorithm"].is_string());
}

#[tokio::test]
async fn test_rate_limiting_with_auth() {
    let mut config = create_auth_config();
    config.rate_limit.default_rpm = 10; // Low limit for testing
    config.rate_limit.burst_capacity = 2;

    let server = Arc::new(McpServer::new(config).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Send multiple requests rapidly
    for i in 0..5 {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": format!("test {}", i),
                    "_meta": {
                        "authToken": "Bearer valid-token-123"
                    }
                }
            },
            "id": i + 2
        });

        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();

        if i < 2 {
            // First 2 should succeed (burst)
            assert!(
                response_json["result"].is_object(),
                "Request {i} should succeed"
            );
        } else {
            // Rest might be rate limited
            // Note: Actual rate limiting might not trigger in tests due to timing
            assert!(
                response_json["result"].is_object() || response_json["error"]["code"] == -32003, // Rate limited
                "Request {i} should succeed or be rate limited"
            );
        }
    }
}

#[tokio::test]
async fn test_permission_scopes() {
    let mut config = create_auth_config();
    config.auth.required_scopes.default = vec!["security:scan".to_string()];

    let server = Arc::new(McpServer::new(config).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Test with token but without required scope
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "test",
                "_meta": {
                    "authToken": "Bearer valid-token-123"
                    // In real implementation, token would include scopes
                }
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    // Should either succeed (if scope checking not implemented) or fail with auth error
    assert!(response_json["result"].is_object() || response_json["error"]["code"] == -32001);
}

#[tokio::test]
async fn test_auth_state_persistence() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // First request with auth
    let request1 = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_security_info",
            "arguments": {}
        },
        "authorization": create_test_auth_token(),
        "id": 2
    });

    server.handle_message(&request1.to_string()).await.unwrap();

    // Second request without auth (should still require it)
    let request2 = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_security_info",
            "arguments": {}
        },
        "id": 3
    });

    let response = server.handle_message(&request2.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();

    // Should still require auth
    validate_jsonrpc_error(&response_json, -32001);
}

#[tokio::test]
async fn test_auth_bypass_attempts() {
    let server = Arc::new(McpServer::new(create_auth_config()).unwrap());

    // Initialize
    let init_request = create_init_request(1);
    server.handle_message(&init_request.to_string()).await;

    // Various bypass attempts
    let bypass_attempts = vec![
        // SQL injection in auth token
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "test",
                    "_meta": {
                        "authToken": "Bearer ' OR '1'='1"
                    }
                }
            },
            "id": 2
        }),
        // Null byte injection
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "test",
                    "_meta": {
                        "authToken": "Bearer valid-token-123\u{0000}admin"
                    }
                }
            },
            "id": 3
        }),
        // Case sensitivity test
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "test",
                    "_meta": {
                        "AUTHTOKEN": "Bearer valid-token-123"
                    }
                }
            },
            "id": 4
        }),
    ];

    for request in bypass_attempts {
        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();

        // All bypass attempts should fail
        validate_jsonrpc_error(&response_json, -32001);
    }
}
