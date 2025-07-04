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
//! Test helpers for MCP protocol testing
#![allow(missing_docs)] // Test utilities

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// Create a standard initialize request
pub fn create_init_request(id: u64) -> Value {
    json!({
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
        "id": id
    })
}

/// Mock stdio transport for testing
pub struct MockStdio {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub read_pos: usize,
}

impl MockStdio {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            read_pos: 0,
        }
    }

    pub fn write_input(&mut self, data: &str) {
        self.input.extend_from_slice(data.as_bytes());
        self.input.push(b'\n');
    }

    pub fn read_output(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }

    pub fn clear_output(&mut self) {
        self.output.clear();
    }
}

impl AsyncRead for MockStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = self.input.len() - self.read_pos;
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let to_read = std::cmp::min(remaining, buf.remaining());
        let data = &self.input[self.read_pos..self.read_pos + to_read];
        buf.put_slice(data);
        self.read_pos += to_read;

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Helper to validate JSON-RPC response structure
pub fn validate_jsonrpc_response(response: &Value, expected_id: u64) {
    assert_eq!(response["jsonrpc"], "2.0", "Missing JSON-RPC version");
    assert_eq!(response["id"], expected_id, "ID mismatch");
    assert!(
        response["result"].is_object()
            || response["result"].is_array()
            || response["error"].is_object(),
        "Response must have either result or error"
    );
}

/// Helper to validate JSON-RPC error response
pub fn validate_jsonrpc_error(response: &Value, expected_code: i32) {
    assert!(response["error"].is_object(), "Missing error object");
    assert_eq!(response["error"]["code"], expected_code, "Wrong error code");
    assert!(
        response["error"]["message"].is_string(),
        "Missing error message"
    );
}

/// Create a mock auth token for testing
pub fn create_test_auth_token() -> String {
    format!(
        "Bearer {}",
        create_test_jwt_token("test-secret-key", "test-client", vec!["security:scan"])
    )
}

/// Create a JWT token for testing
pub fn create_test_jwt_token(secret: &str, client_id: &str, scopes: Vec<&str>) -> String {
    // Create header
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });

    // Create payload with claims
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = json!({
        "sub": client_id,
        "iat": now,
        "exp": now + 3600, // 1 hour expiry
        "scope": scopes.join(" "),
        "client_id": client_id,
    });

    // Encode header and payload
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());

    // Create signature
    let message = format!("{header_b64}.{payload_b64}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature);

    format!("{header_b64}.{payload_b64}.{signature_b64}")
}

/// Create a test signature for message signing tests
pub fn create_test_signature() -> Value {
    json!({
        "signature": "dGVzdC1zaWduYXR1cmU=", // base64 "test-signature"
        "publicKey": "dGVzdC1wdWJsaWMta2V5", // base64 "test-public-key"
        "algorithm": "ed25519"
    })
}
