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
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

mod config;
mod core;
mod ipc;
mod security;
mod tray;
mod websocket;

use std::sync::Arc;

use tauri::{AppHandle, Manager, RunEvent, WindowEvent};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::{
    config::Config,
    core::{EventProcessorFactory, EventProcessorTrait, ShieldCore},
    ipc::IpcHandlers,
    security::{PatternDetectorFactory, PatternDetectorTrait, SecurityValidator},
    tray::TrayManager,
    websocket::{WebSocketHandlerFactory, WebSocketHandlerTrait, WebSocketServer},
};

#[derive(Clone)]
pub struct AppState {
    pub core: Arc<ShieldCore>,
    pub validator: Arc<SecurityValidator>,
    pub websocket: Arc<RwLock<Option<WebSocketServer>>>,
    pub event_processor: Arc<dyn EventProcessorTrait>,
    pub pattern_detector: Arc<dyn PatternDetectorTrait>,
    pub ws_handler: Arc<dyn WebSocketHandlerTrait>,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("kindly_guard_shield=debug".parse().unwrap()),
        )
        .init();

    info!("Starting KindlyGuard Shield");

    // Load configuration
    let config = Config::load();
    info!("Enhanced mode: {}", config.is_enhanced_available());

    // Create components using factories
    let core = Arc::new(ShieldCore::new());
    let validator = Arc::new(SecurityValidator::new());
    let websocket = Arc::new(RwLock::new(None));
    
    // Create enhanced or standard implementations based on config
    let event_processor = EventProcessorFactory::create(&config)
        .expect("Failed to create event processor");
    let pattern_detector = PatternDetectorFactory::create(&config)
        .expect("Failed to create pattern detector");
    let ws_handler = WebSocketHandlerFactory::create(&config)
        .expect("Failed to create WebSocket handler");

    let app_state = AppState {
        core: core.clone(),
        validator: validator.clone(),
        websocket: websocket.clone(),
        event_processor,
        pattern_detector,
        ws_handler,
    };

    // Build Tauri app
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state.clone())
        .invoke_handler(tauri::generate_handler![
            ipc::show_shield,
            ipc::hide_shield,
            ipc::update_threats,
            ipc::get_statistics,
            ipc::clear_threats,
            ipc::toggle_protection,
            ipc::get_protection_status,
        ])
        .setup(move |app| {
            info!("Setting up KindlyGuard Shield");

            // Set up system tray
            let tray_manager = TrayManager::new(app.handle().clone());
            match tray_manager.setup() {
                Ok(_) => info!("System tray initialized"),
                Err(e) => error!("Failed to initialize system tray: {}", e),
            }

            // Start WebSocket server for Claude Code integration
            let ws_server = WebSocketServer::new(
                app_state.core.clone(),
                app_state.validator.clone(),
            );
            
            let ws_handle = ws_server.clone();
            let websocket_clone = app_state.websocket.clone();
            
            tauri::async_runtime::spawn(async move {
                match ws_handle.start().await {
                    Ok(_) => {
                        info!("WebSocket server started on ws://localhost:9955");
                        let mut ws_lock = websocket_clone.write().await;
                        *ws_lock = Some(ws_server);
                    }
                    Err(e) => error!("Failed to start WebSocket server: {}", e),
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // Run the app
    app.run(|app_handle, event| match event {
        RunEvent::Ready => {
            info!("KindlyGuard Shield is ready");
        }
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } => {
            // Hide window instead of closing
            if label == "main" {
                api.prevent_close();
                if let Some(window) = app_handle.get_webview_window(&label) {
                    let _ = window.hide();
                }
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            info!("Exit requested");
            // Cleanup can be done here
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let core = Arc::new(ShieldCore::new());
        let validator = Arc::new(SecurityValidator::new());
        let websocket = Arc::new(RwLock::new(None));

        // Note: In tests, we use default config and implementations
        let config = Config::default();
        let event_processor = EventProcessorFactory::create(&config).unwrap();
        let pattern_detector = PatternDetectorFactory::create(&config).unwrap();
        let ws_handler = WebSocketHandlerFactory::create(&config).unwrap();
        
        let _app_state = AppState {
            core,
            validator,
            websocket,
            event_processor,
            pattern_detector,
            ws_handler,
        };
    }
}