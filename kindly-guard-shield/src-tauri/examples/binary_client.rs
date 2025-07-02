//! Example WebSocket client using the binary protocol

use std::error::Error;

use futures_util::{SinkExt, StreamExt};
use kindly_guard_shield_lib::protocol::{
    BinaryDecoder, BinaryEncoder, BinaryMessage, ProtocolNegotiator,
    binary::{CMD_GET_STATUS, CMD_SUBSCRIBE},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    
    info!("Connecting to KindlyGuard Shield...");
    
    let (ws_stream, _) = connect_async("ws://127.0.0.1:9955").await?;
    info!("Connected to WebSocket server");
    
    let (mut write, mut read) = ws_stream.split();
    
    // Protocol negotiation
    let negotiator = ProtocolNegotiator::new();
    let hello = negotiator.create_hello()?;
    write.send(hello).await?;
    
    // Wait for negotiation response
    if let Some(Ok(msg)) = read.next().await {
        let version = negotiator.parse_response(&msg)?;
        info!("Using protocol version: {}", version.0);
        
        if version.is_binary() {
            run_binary_client(write, read).await?;
        } else {
            info!("Server doesn't support binary protocol, falling back to JSON");
        }
    }
    
    Ok(())
}

async fn run_binary_client(
    mut write: impl SinkExt<Message> + Unpin,
    mut read: impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
) -> Result<(), Box<dyn Error>> {
    let mut encoder = BinaryEncoder::new();
    let decoder = BinaryDecoder::new();
    
    // Subscribe to updates
    let subscribe_cmd = BinaryMessage::Command {
        cmd_type: CMD_SUBSCRIBE,
        params: vec![],
    };
    
    let mut buf = Vec::new();
    encoder.encode(&subscribe_cmd, &mut buf)?;
    write.send(Message::Binary(buf)).await?;
    info!("Subscribed to threat updates");
    
    // Request initial status
    let status_cmd = BinaryMessage::Command {
        cmd_type: CMD_GET_STATUS,
        params: vec![],
    };
    
    buf.clear();
    encoder.encode(&status_cmd, &mut buf)?;
    write.send(Message::Binary(buf)).await?;
    info!("Requested status");
    
    // Message loop
    while let Some(msg) = read.next().await {
        match msg? {
            Message::Binary(data) => {
                match decoder.decode(&data) {
                    Ok((binary_msg, _)) => {
                        handle_binary_message(binary_msg);
                    }
                    Err(e) => {
                        error!("Failed to decode binary message: {}", e);
                    }
                }
            }
            Message::Close(_) => {
                info!("Server closed connection");
                break;
            }
            _ => {}
        }
    }
    
    Ok(())
}

fn handle_binary_message(msg: BinaryMessage) {
    match msg {
        BinaryMessage::Threat { threats } => {
            info!("Received {} threat(s):", threats.len());
            for (i, threat) in threats.iter().enumerate() {
                info!("  [{}] Type: 0x{:02X}, Severity: {}, Blocked: {}", 
                    i, threat.threat_flags, threat.severity, threat.blocked);
            }
        }
        BinaryMessage::Status { protection_enabled, threats_blocked, threats_analyzed } => {
            info!("Status Update:");
            info!("  Protection: {}", if protection_enabled { "ENABLED" } else { "DISABLED" });
            info!("  Threats blocked: {}", threats_blocked);
            info!("  Threats analyzed: {}", threats_analyzed);
        }
        BinaryMessage::StatsDelta { threats_blocked_delta, threats_analyzed_delta, .. } => {
            info!("Stats Delta:");
            info!("  Blocked: {:+}", threats_blocked_delta);
            info!("  Analyzed: {:+}", threats_analyzed_delta);
        }
        BinaryMessage::Heartbeat { uptime_seconds } => {
            info!("Heartbeat - Uptime: {} seconds", uptime_seconds);
        }
        BinaryMessage::Error { code, message } => {
            error!("Error {}: {}", code, message);
        }
        _ => {}
    }
}