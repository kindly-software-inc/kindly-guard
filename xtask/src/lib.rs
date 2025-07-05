//! Xtask library for KindlyGuard build automation

pub mod commands;
pub mod config;
pub mod test;
pub mod utils;

// Re-export commonly used items
pub use utils::Context;