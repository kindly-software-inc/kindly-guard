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
//! Minimalist web dashboard for `KindlyGuard`
//! Clean, modern interface for security monitoring

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::shield::universal_display::UniversalDisplay;
use crate::shield::{Shield, UniversalShieldStatus};

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Update interval for SSE
    pub update_interval_ms: u64,
    /// Enable authentication
    pub auth_enabled: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([127, 0, 0, 1], 3000).into(),
            update_interval_ms: 1000,
            auth_enabled: false,
        }
    }
}

/// Dashboard server state
#[derive(Clone)]
struct AppState {
    shield: Arc<Shield>,
    config: DashboardConfig,
}

/// Dashboard server
pub struct DashboardServer {
    state: AppState,
}

impl DashboardServer {
    /// Create new dashboard server
    pub const fn new(shield: Arc<Shield>, config: DashboardConfig) -> Self {
        Self {
            state: AppState { shield, config },
        }
    }

    /// Run the dashboard server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/", get(serve_dashboard))
            .route("/api/status", get(get_status))
            .route("/api/shield/toggle", post(toggle_shield))
            .route("/api/mode/toggle", post(toggle_mode))
            .with_state(self.state.clone());

        let listener = tokio::net::TcpListener::bind(&self.state.config.listen_addr).await?;
        tracing::info!(
            "Dashboard running at http://{}",
            self.state.config.listen_addr
        );

        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Serve the main dashboard HTML
async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("../../templates/dashboard.html"))
}

/// Get current shield status as JSON
async fn get_status(State(state): State<AppState>) -> Json<UniversalShieldStatus> {
    let display = UniversalDisplay::new(
        state.shield,
        crate::shield::universal_display::UniversalDisplayConfig {
            color: false,
            detailed: true,
            format: crate::shield::universal_display::DisplayFormat::Json,
            status_file: None,
        },
    );

    Json(display.get_status())
}

/// Toggle shield active state
async fn toggle_shield(State(state): State<AppState>) -> StatusCode {
    let current = state.shield.is_active();
    state.shield.set_active(!current);
    StatusCode::OK
}

/// Toggle enhanced mode
async fn toggle_mode(State(state): State<AppState>) -> StatusCode {
    let current = state.shield.is_event_processor_enabled();
    state.shield.set_event_processor_enabled(!current);
    StatusCode::OK
}

/// API response types
#[derive(Debug, Serialize, Deserialize)]
struct ToggleResponse {
    success: bool,
    new_state: bool,
}

#[derive(Debug, Deserialize)]
struct CommandQuery {
    #[allow(dead_code)]
    cmd: String,
    #[allow(dead_code)]
    args: Option<String>,
}
