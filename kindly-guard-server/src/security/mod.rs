//! Security modules for KindlyGuard

pub mod hardening;
pub mod boundaries;

pub use hardening::{
    CommandRateLimiter, ResourceMonitor, SecurityContext, 
    SecurityAuditLogger, FileSandbox, CommandSource
};