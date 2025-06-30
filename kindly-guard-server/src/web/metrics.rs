//! Metrics endpoints for monitoring

use axum::{
    Router,
    routing::get,
    response::{Response, IntoResponse},
    extract::State,
    http::StatusCode,
};
use std::sync::Arc;
use crate::metrics::MetricsRegistry;


/// Metrics server state
#[derive(Clone)]
pub struct MetricsState {
    pub registry: Arc<MetricsRegistry>,
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