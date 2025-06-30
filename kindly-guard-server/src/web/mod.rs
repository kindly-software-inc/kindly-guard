//! Web dashboard module for KindlyGuard

pub mod dashboard;
pub mod metrics;

pub use dashboard::{DashboardServer, DashboardConfig};
pub use metrics::{metrics_routes, MetricsState};