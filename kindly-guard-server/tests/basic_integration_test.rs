// Copyright 2025 Kindly Software Inc.
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
//! Basic integration tests for `KindlyGuard`

use kindly_guard_server::{Config, McpServer};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_server_initialization() {
    let config = Config::default();
    let server = McpServer::new(config);
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_basic_initialize() {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;

    let server = Arc::new(McpServer::new(config).unwrap());

    let request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    let response = server.handle_message(&request.to_string()).await;
    assert!(response.is_some());

    let response_json: serde_json::Value = serde_json::from_str(&response.unwrap()).unwrap();
    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], 1);
    assert!(response_json["result"].is_object());
}

#[tokio::test]
async fn test_tools_list() {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;

    let server = Arc::new(McpServer::new(config).unwrap());

    // Initialize first
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    server.handle_message(&init_request.to_string()).await;

    // List tools
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"]["tools"].is_array());
    let tools = response_json["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty());

    // Check that scan_text tool exists
    let has_scan_text = tools
        .iter()
        .any(|tool| tool["name"].as_str() == Some("scan_text"));
    assert!(has_scan_text);
}

#[tokio::test]
async fn test_scan_text_tool() {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = false; // Disable auth for this test

    let server = Arc::new(McpServer::new(config).unwrap());

    // Initialize
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    server.handle_message(&init_request.to_string()).await;

    // Call scan_text tool
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "Hello World"
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    assert!(response_json["result"]["content"].is_array());

    // Should return a scan result
    let content = &response_json["result"]["content"][0];
    assert_eq!(content["type"], "text");

    // Parse the JSON response from the text field
    let scan_result_text = content["text"].as_str().unwrap();
    let scan_result: serde_json::Value = serde_json::from_str(scan_result_text).unwrap();

    // Check that it's safe and has no threats
    assert_eq!(scan_result["safe"], true);
    assert_eq!(scan_result["threats"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_unicode_threat_detection() {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = false;

    let server = Arc::new(McpServer::new(config).unwrap());

    // Initialize
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });

    server.handle_message(&init_request.to_string()).await;

    // Scan text with unicode threat
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "Hello\u{202E}World" // Right-to-left override
            }
        },
        "id": 2
    });

    let response = server.handle_message(&request.to_string()).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(response_json["result"].is_object());
    let content_text = response_json["result"]["content"][0]["text"]
        .as_str()
        .unwrap();

    // Parse the JSON response from the text field
    let scan_result: serde_json::Value = serde_json::from_str(content_text).unwrap();

    // Check that it's not safe and has 1 threat
    assert_eq!(scan_result["safe"], false);
    assert_eq!(scan_result["threats"].as_array().unwrap().len(), 1);

    // Check the threat type
    let threat = &scan_result["threats"][0];
    assert_eq!(threat["type"], "unicode_bidi");
}
