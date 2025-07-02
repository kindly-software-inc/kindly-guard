//! CLI command interface for `KindlyGuard`

pub mod commands;
pub mod validation;

pub use commands::{run_command, KindlyCommand};
pub use validation::CommandValidator;
