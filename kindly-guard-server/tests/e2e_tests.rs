//! End-to-End Integration Tests for KindlyGuard
//! Tests complete user scenarios and workflows

use kindly_guard_server::{McpServer, Config, Shield};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use serial_test::serial;
use base64::{Engine as _, engine::general_purpose};

mod helpers;
use helpers::*;

/// Create a fully configured server for E2E tests
fn create_e2e_server() -> Arc<McpServer> {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = true;
    config.shield.detailed_stats = true;
    config.auth.enabled = true;
    config.auth.jwt_secret = Some(general_purpose::STANDARD.encode(b"e2e-test-secret"));
    config.auth.require_signature_verification = false;
    config.signing.require_signatures = false; // Simplify for E2E
    config.signing.enabled = false;
    config.rate_limit.default_rpm = 60;
    
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

#[tokio::test]
#[serial]
async fn test_e2e_complete_security_workflow() {
    let server = create_e2e_server();
    
    // Step 1: Initialize connection
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": true},
                "sampling": {}
            },
            "clientInfo": {
                "name": "security-scanner",
                "version": "1.0.0"
            }
        },
        "id": 1
    });
    
    let response = server.handle_message(&init_request.to_string()).await.unwrap();
    let init_response: Value = serde_json::from_str(&response).unwrap();
    assert!(init_response["result"]["serverInfo"]["name"].as_str().unwrap().contains("kindly-guard"));
    
    // Step 2: List available tools
    let list_tools = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });
    
    let response = server.handle_message(&list_tools.to_string()).await.unwrap();
    let tools_response: Value = serde_json::from_str(&response).unwrap();
    let tools = tools_response["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 5); // Should have multiple security tools
    
    // Step 3: Scan suspicious text with auth
    let scan_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "Hello\u{202E}World' OR '1'='1--",
                "_meta": {
                    "authToken": "Bearer e2e-test-token"
                }
            }
        },
        "id": 3
    });
    
    let response = server.handle_message(&scan_request.to_string()).await.unwrap();
    let scan_response: Value = serde_json::from_str(&response).unwrap();
    let content = scan_response["result"]["content"][0]["text"].as_str().unwrap();
    let scan_result: Value = serde_json::from_str(content).unwrap();
    
    assert_eq!(scan_result["safe"], false);
    assert!(scan_result["threats"].as_array().unwrap().len() >= 2); // Unicode + SQL injection
    
    // Step 4: Get security status
    let status_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_security_info",
            "arguments": {
                "_meta": {
                    "authToken": "Bearer e2e-test-token"
                }
            }
        },
        "id": 4
    });
    
    let response = server.handle_message(&status_request.to_string()).await.unwrap();
    let status_response: Value = serde_json::from_str(&response).unwrap();
    assert!(status_response["result"].is_object());
    
    // Step 5: Check shield status shows threats
    let shield_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_shield_status",
            "arguments": {
                "_meta": {
                    "authToken": "Bearer e2e-test-token"
                }
            }
        },
        "id": 5
    });
    
    let response = server.handle_message(&shield_request.to_string()).await.unwrap();
    let shield_response: Value = serde_json::from_str(&response).unwrap();
    let shield_content = shield_response["result"]["content"][0]["text"].as_str().unwrap();
    let shield_status: Value = serde_json::from_str(shield_content).unwrap();
    
    assert!(shield_status["threats_blocked"].as_u64().unwrap() >= 2);
    assert_eq!(shield_status["status"], "active");
}

#[tokio::test]
#[serial]
async fn test_e2e_multi_client_scenario() {
    let server = create_e2e_server();
    
    // Initialize server
    let init = create_init_request(1);
    server.handle_message(&init.to_string()).await;
    
    // Simulate multiple clients
    let mut handles = vec![];
    
    for client_id in 0..3 {
        let server = server.clone();
        let token = "Bearer e2e-test-token";
        
        let handle = tokio::spawn(async move {
            let mut results = vec![];
            
            // Each client makes several requests
            for req_id in 0..5 {
                let request = json!({
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "scan_text",
                        "arguments": {
                            "text": format!("Client {} request {}", client_id, req_id),
                            "_meta": {
                                "authToken": token
                            }
                        }
                    },
                    "id": client_id * 10 + req_id + 2
                });
                
                let response = server.handle_message(&request.to_string()).await;
                results.push(response.is_some());
                
                // Small delay between requests
                sleep(Duration::from_millis(50)).await;
            }
            
            results
        });
        
        handles.push(handle);
    }
    
    // All clients should complete successfully
    for handle in handles {
        let results = handle.await.unwrap();
        assert!(results.iter().all(|&r| r), "All requests should succeed");
    }
}

#[tokio::test]
#[serial] 
async fn test_e2e_attack_detection_workflow() {
    let server = create_e2e_server();
    
    // Initialize
    let init = create_init_request(1);
    server.handle_message(&init.to_string()).await;
    
    // Simulate attack pattern
    let attack_patterns = vec![
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "SELECT * FROM passwords",
        "../../../etc/passwd",
        "<?php system($_GET['cmd']); ?>",
        "<script>alert('xss')</script>",
    ];
    
    let mut threat_count = 0;
    
    for (i, pattern) in attack_patterns.iter().enumerate() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": format!("User input: {}", pattern),
                    "_meta": {
                        "authToken": "Bearer e2e-test-token"
                    }
                }
            },
            "id": i + 2
        });
        
        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();
        let content = response_json["result"]["content"][0]["text"].as_str().unwrap();
        let result: Value = serde_json::from_str(content).unwrap();
        
        if !result["safe"].as_bool().unwrap() {
            threat_count += result["threats"].as_array().unwrap().len();
        }
    }
    
    // Should detect multiple threats
    assert!(threat_count >= attack_patterns.len());
    
    // Check final shield status
    let shield_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_shield_status",
            "arguments": {
                "_meta": {
                    "authToken": "Bearer e2e-test-token"
                }
            }
        },
        "id": 100
    });
    
    let response = server.handle_message(&shield_request.to_string()).await.unwrap();
    let shield_response: Value = serde_json::from_str(&response).unwrap();
    let shield_content = shield_response["result"]["content"][0]["text"].as_str().unwrap();
    let shield_status: Value = serde_json::from_str(shield_content).unwrap();
    
    assert!(shield_status["threats_blocked"].as_u64().unwrap() >= threat_count as u64);
}

#[tokio::test]
#[serial]
async fn test_e2e_rate_limiting_scenario() {
    let mut config = Config::default();
    config.server.stdio = true;
    config.auth.enabled = true;
    // Note: Authentication is now handled by JWT tokens
    config.rate_limit.default_rpm = 10; // Very low for testing
    config.rate_limit.burst_capacity = 3;
    
    let server = Arc::new(McpServer::new(config).unwrap());
    
    // Initialize
    let init = create_init_request(1);
    server.handle_message(&init.to_string()).await;
    
    let mut success_count = 0;
    let mut rate_limited_count = 0;
    
    // Send rapid requests
    for i in 0..10 {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_security_info",
                "arguments": {
                    "_meta": {
                        "authToken": "Bearer rate-limit-token"
                    }
                }
            },
            "id": i + 2
        });
        
        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();
        
        if response_json["result"].is_object() {
            success_count += 1;
        } else if response_json["error"]["code"] == -32003 {
            rate_limited_count += 1;
        }
    }
    
    // Should have some successes (burst) and some rate limited
    assert!(success_count >= 3, "At least burst size should succeed");
    assert!(rate_limited_count > 0, "Some requests should be rate limited");
}

#[tokio::test]
#[serial]
async fn test_e2e_unicode_attack_scenario() {
    let server = create_e2e_server();
    
    // Initialize
    let init = create_init_request(1);
    server.handle_message(&init.to_string()).await;
    
    // Various unicode attacks
    let unicode_attacks = vec![
        ("admin\u{200B}user", "Zero-width space"),
        ("\u{202E}drowssap\u{202C}", "Right-to-left override"),
        ("раypal.com", "Homograph attack (Cyrillic 'a')"),
        ("test\u{0000}admin", "Null byte injection"),
        ("\u{FEFF}hidden", "Zero-width no-break space"),
    ];
    
    for (i, (text, description)) in unicode_attacks.iter().enumerate() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": text,
                    "_meta": {
                        "authToken": "Bearer e2e-test-token"
                    }
                }
            },
            "id": i + 2
        });
        
        let response = server.handle_message(&request.to_string()).await.unwrap();
        let response_json: Value = serde_json::from_str(&response).unwrap();
        let content = response_json["result"]["content"][0]["text"].as_str().unwrap();
        let result: Value = serde_json::from_str(content).unwrap();
        
        assert_eq!(result["safe"], false, "Should detect: {}", description);
        assert!(!result["threats"].as_array().unwrap().is_empty(), 
            "Should have threats for: {}", description);
    }
}

#[tokio::test]
#[serial]
async fn test_e2e_error_recovery_scenario() {
    let server = create_e2e_server();
    
    // Send various problematic requests
    let problematic_requests = vec![
        "{invalid json}".to_string(),
        "".to_string(),
        "null".to_string(),
        json!({"no": "jsonrpc field"}).to_string(),
    ];
    
    for bad_request in problematic_requests {
        server.handle_message(&bad_request).await;
    }
    
    // Server should still work after errors
    let valid_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });
    
    let response = server.handle_message(&valid_request.to_string()).await.unwrap();
    let response_json: Value = serde_json::from_str(&response).unwrap();
    
    // Should handle valid request after errors
    assert!(response_json["result"]["tools"].is_array());
}

#[tokio::test]
#[serial]
async fn test_e2e_performance_under_load() {
    let server = create_e2e_server();
    
    // Initialize
    let init = create_init_request(1);
    server.handle_message(&init.to_string()).await;
    
    // Measure response time under load
    let start = std::time::Instant::now();
    let request_count = 100;
    
    let mut handles = vec![];
    for i in 0..request_count {
        let server = server.clone();
        let handle = tokio::spawn(async move {
            let request = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "scan_text",
                    "arguments": {
                        "text": format!("Performance test {}", i),
                        "_meta": {
                            "authToken": "Bearer e2e-test-token"
                        }
                    }
                },
                "id": i + 2
            });
            
            timeout(
                Duration::from_secs(5),
                server.handle_message(&request.to_string())
            ).await
        });
        handles.push(handle);
    }
    
    // All requests should complete
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(Some(_))) = handle.await {
            success_count += 1;
        }
    }
    
    let elapsed = start.elapsed();
    
    // Performance assertions
    assert!(success_count > request_count * 90 / 100, 
        "At least 90% should succeed");
    assert!(elapsed < Duration::from_secs(10), 
        "Should complete 100 requests in under 10 seconds");
    
    println!("Processed {} requests in {:?}", success_count, elapsed);
}