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
//! Metrics endpoints for monitoring

use crate::traits::MetricsProvider;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

/// Metrics server state
#[derive(Clone)]
pub struct MetricsState {
    pub registry: Arc<dyn MetricsProvider>,
}

/// Create metrics routes
pub fn metrics_routes(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/metrics.json", get(json_metrics))
        .with_state(state)
}

/// Prometheus metrics endpoint
async fn prometheus_metrics(State(state): State<MetricsState>) -> impl IntoResponse {
    let metrics = state.registry.export_prometheus();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(metrics)
        .unwrap()
}

/// JSON metrics endpoint
async fn json_metrics(State(state): State<MetricsState>) -> impl IntoResponse {
    let metrics = state.registry.export_json();

    (StatusCode::OK, axum::Json(metrics))
}
