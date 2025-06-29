#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{McpServer, ServerConfig, mcp::{JsonRpcRequest, JsonRpcNotification}};
use serde_json::{json, Value};
use arbitrary::{Arbitrary, Unstructured};
use std::sync::Arc;

// Arbitrary MCP method names
#[derive(Debug, Clone)]
enum McpMethod {
    Initialize,
    ToolsList,
    ToolsCall,
    ResourcesList,
    ResourcesRead,
    PromptsGet,
    PromptsList,
    Unknown(String),
}

impl<'a> Arbitrary<'a> for McpMethod {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=7)? {
            0 => Ok(McpMethod::Initialize),
            1 => Ok(McpMethod::ToolsList),
            2 => Ok(McpMethod::ToolsCall),
            3 => Ok(McpMethod::ResourcesList),
            4 => Ok(McpMethod::ResourcesRead),
            5 => Ok(McpMethod::PromptsGet),
            6 => Ok(McpMethod::PromptsList),
            _ => Ok(McpMethod::Unknown(u.arbitrary::<String>()?)),
        }
    }
}

// Generate arbitrary MCP requests
fn generate_mcp_request(u: &mut Unstructured) -> arbitrary::Result<Value> {
    let method = McpMethod::arbitrary(u)?;
    let id = u.arbitrary::<Option<u64>>()?;
    
    let mut request = json!({
        "jsonrpc": "2.0",
    });
    
    // Add method
    match &method {
        McpMethod::Initialize => {
            request["method"] = json!("initialize");
            request["params"] = json!({
                "protocolVersion": u.arbitrary::<String>()?,
                "capabilities": generate_capabilities(u)?,
                "clientInfo": {
                    "name": u.arbitrary::<String>()?,
                    "version": u.arbitrary::<String>()?,
                },
            });
        },
        McpMethod::ToolsList => {
            request["method"] = json!("tools/list");
            request["params"] = json!({});
        },
        McpMethod::ToolsCall => {
            request["method"] = json!("tools/call");
            request["params"] = json!({
                "name": u.arbitrary::<String>()?,
                "arguments": generate_arbitrary_json(u, 3)?,
            });
        },
        McpMethod::ResourcesList => {
            request["method"] = json!("resources/list");
            request["params"] = json!({});
        },
        McpMethod::ResourcesRead => {
            request["method"] = json!("resources/read");
            request["params"] = json!({
                "uri": format!("resource://{}", u.arbitrary::<String>()?),
            });
        },
        McpMethod::PromptsGet => {
            request["method"] = json!("prompts/get");
            request["params"] = json!({
                "name": u.arbitrary::<String>()?,
                "arguments": generate_arbitrary_json(u, 2)?,
            });
        },
        McpMethod::PromptsList => {
            request["method"] = json!("prompts/list");
            request["params"] = json!({});
        },
        McpMethod::Unknown(method) => {
            request["method"] = json!(method);
            request["params"] = generate_arbitrary_json(u, 3)?;
        },
    }
    
    // Add ID for request or omit for notification
    if let Some(id) = id {
        request["id"] = json!(id);
    }
    
    Ok(request)
}

fn generate_capabilities(u: &mut Unstructured) -> arbitrary::Result<Value> {
    Ok(json!({
        "tools": if u.arbitrary::<bool>()? {
            Some(json!({}))
        } else {
            None
        },
        "resources": if u.arbitrary::<bool>()? {
            Some(json!({
                "subscribe": u.arbitrary::<bool>()?,
            }))
        } else {
            None
        },
        "prompts": if u.arbitrary::<bool>()? {
            Some(json!({}))
        } else {
            None
        },
    }))
}

fn generate_arbitrary_json(u: &mut Unstructured, max_depth: u32) -> arbitrary::Result<Value> {
    if max_depth == 0 {
        // Base case
        match u.int_in_range(0..=3)? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(u.arbitrary()?)),
            2 => Ok(Value::Number(u.arbitrary::<i64>()?.into())),
            _ => Ok(Value::String(u.arbitrary()?)),
        }
    } else {
        match u.int_in_range(0..=5)? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(u.arbitrary()?)),
            2 => Ok(Value::Number(u.arbitrary::<i64>()?.into())),
            3 => Ok(Value::String(u.arbitrary()?)),
            4 => {
                // Object
                let size = u.int_in_range(0..=5)?;
                let mut obj = serde_json::Map::new();
                for _ in 0..size {
                    let key = u.arbitrary::<String>()?;
                    let value = generate_arbitrary_json(u, max_depth - 1)?;
                    obj.insert(key, value);
                }
                Ok(Value::Object(obj))
            },
            _ => {
                // Array
                let size = u.int_in_range(0..=5)?;
                let mut arr = Vec::new();
                for _ in 0..size {
                    arr.push(generate_arbitrary_json(u, max_depth - 1)?);
                }
                Ok(Value::Array(arr))
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Test with raw JSON parsing
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(value) = serde_json::from_str::<Value>(json_str) {
            // Try to parse as request
            if let Ok(request) = serde_json::from_value::<JsonRpcRequest>(value.clone()) {
                // Create a minimal server to handle the request
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                
                rt.block_on(async {
                    let config = ServerConfig::default();
                    if let Ok(server) = McpServer::new(config) {
                        let server = Arc::new(server);
                        let _ = server.handle_request(request).await;
                    }
                });
            }
            
            // Try to parse as notification
            if let Ok(notification) = serde_json::from_value::<JsonRpcNotification>(value) {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                
                rt.block_on(async {
                    let config = ServerConfig::default();
                    if let Ok(server) = McpServer::new(config) {
                        let server = Arc::new(server);
                        let _ = server.handle_notification(notification).await;
                    }
                });
            }
        }
    }
    
    // Test with generated MCP requests
    let mut u = Unstructured::new(data);
    if let Ok(request_value) = generate_mcp_request(&mut u) {
        // Test request handling
        if let Ok(request) = serde_json::from_value::<JsonRpcRequest>(request_value.clone()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            
            rt.block_on(async {
                let config = ServerConfig::default();
                if let Ok(server) = McpServer::new(config) {
                    let server = Arc::new(server);
                    let _ = server.handle_request(request).await;
                }
            });
        }
        
        // Test batch requests
        if u.arbitrary::<bool>().unwrap_or(false) {
            let batch_size = u.int_in_range(0..=10).unwrap_or(2);
            let mut batch = Vec::new();
            for _ in 0..batch_size {
                if let Ok(req) = generate_mcp_request(&mut u) {
                    batch.push(req);
                }
            }
            
            if !batch.is_empty() {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                
                rt.block_on(async {
                    let config = ServerConfig::default();
                    if let Ok(server) = McpServer::new(config) {
                        let server = Arc::new(server);
                        let _ = server.handle_batch_request(batch).await;
                    }
                });
            }
        }
    }
});