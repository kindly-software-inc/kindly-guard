//! Web dashboard module for `KindlyGuard`

pub mod dashboard;
pub mod metrics;

pub use dashboard::{DashboardConfig, DashboardServer};
pub use metrics::{metrics_routes, MetricsState};
