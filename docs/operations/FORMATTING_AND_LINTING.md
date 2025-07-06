# Formatting and Linting Guide for KindlyGuard

## Overview

KindlyGuard uses strict formatting and linting rules to maintain code quality and security. This guide explains our tooling setup and how to use it effectively.

## Configuration Files

### `rustfmt.toml`
Our rustfmt configuration enforces:
- 100-character line width for complex security expressions
- Module-level import grouping (std → external → internal)
- Explicit field initialization (no shorthand)
- Tall function parameters for readability
- Conservative formatting that prioritizes clarity

### `clippy.toml`
Security-focused linting configuration:
- Bans `unwrap()` and `expect()` in production code
- Enforces documentation for error conditions
- Limits cognitive complexity (30 per function)
- Requires explicit error handling
- Warns on arithmetic operations that could overflow

### `.cargo/config.toml`
Provides convenient aliases:
- `cargo fmt-check` - Check formatting without changing files
- `cargo lint` - Run comprehensive security lints
- `cargo sec` - Quick security-focused lint check
- `cargo audit` - Check for known vulnerabilities

## Required Lints

### Critical (Deny)
These lints will fail the build:
- `clippy::unwrap_used` - No unwrap in production
- `clippy::expect_used` - No expect in production  
- `clippy::panic` - No explicit panics
- `clippy::todo` - No unfinished code
- `clippy::dbg_macro` - No debug macros
- `clippy::print_stdout/stderr` - No print statements

### Important (Warn)
These lints generate warnings:
- `clippy::pedantic` - Additional quality checks
- `clippy::missing_errors_doc` - Document error conditions
- `clippy::missing_panics_doc` - Document panic conditions
- `clippy::indexing_slicing` - Prefer safe access methods

## VS Code Integration

### Automatic Setup
1. Open the project in VS Code
2. Install recommended extensions when prompted
3. Restart VS Code to activate rust-analyzer

### Features
- Format on save enabled
- Security lints run on every save
- Inline error display with ErrorLens
- Debug configurations for all binaries
- Task shortcuts (Ctrl+Shift+B to build)

### Recommended Workflow
1. Write code with real-time feedback
2. Save to auto-format and lint
3. Run `Tasks: Run Task` → `Security Lint` before committing
4. Use `Pre-commit` task to run all checks

## Command Line Usage

### Daily Development
```bash
# Format all code
cargo fmt

# Run security lints
cargo lint

# Quick security check
cargo sec

# Run tests with formatting check
cargo fmt-check && cargo test
```

### Before Committing
```bash
# Run comprehensive checks
cargo fmt-check && cargo lint && cargo test

# Or use the alias
make pre-commit  # if Makefile exists
```

### CI Integration
Our GitHub Actions automatically:
1. Check formatting (fail on violations)
2. Run security lints (fail on critical issues)
3. Generate security reports
4. Post results to pull requests

## Handling Lint Violations

### When to Allow
Some lints can be allowed with justification:

```rust
// SAFETY: Performance-critical hot path, bounds checked above
#[allow(clippy::indexing_slicing)]
let byte = buffer[index];
```

### When to Refactor
Always prefer refactoring over allowing:

```rust
// Bad: Using unwrap
let value = map.get("key").unwrap();

// Good: Explicit error handling
let value = map.get("key")
    .ok_or_else(|| Error::MissingKey("key".to_string()))?;
```

### Security Exceptions
Security-critical lints should NEVER be allowed without team review:
- `unwrap_used`
- `expect_used`
- `panic`
- `mem_forget`

## Cognitive Complexity

Functions exceeding complexity threshold (30) should be refactored:

```rust
// Bad: Single complex function
fn process_request(req: Request) -> Result<Response> {
    // 100 lines of nested logic
}

// Good: Decomposed into steps
fn process_request(req: Request) -> Result<Response> {
    let validated = validate_request(&req)?;
    let authorized = check_authorization(&validated)?;
    let processed = execute_business_logic(authorized)?;
    build_response(processed)
}
```

## Import Organization

Always group imports as configured:

```rust
// Standard library
use std::{
    collections::HashMap,
    sync::Arc,
};

// External crates
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// Internal modules
use crate::{
    error::Error,
    scanner::SecurityScanner,
};
```

## Documentation Requirements

### Public APIs
All public items must be documented:

```rust
/// Scans text for security threats.
///
/// # Arguments
/// * `text` - The text to scan
///
/// # Returns
/// A vector of detected threats, empty if none found
///
/// # Errors
/// Returns `ScanError` if the scanner is not initialized
pub fn scan_text(&self, text: &str) -> Result<Vec<Threat>, ScanError> {
    // Implementation
}
```

### Error Documentation
Document all error conditions:

```rust
/// Processes the security check.
///
/// # Errors
/// - `ConfigError` - If configuration is invalid
/// - `NetworkError` - If remote validation fails
/// - `TimeoutError` - If operation exceeds 30 seconds
pub fn process(&self) -> Result<(), ProcessError> {
    // Implementation
}
```

## Performance Considerations

Our formatting rules balance security with performance:

1. **Line Width**: 100 chars allows complex security expressions
2. **Import Grouping**: Faster compilation with grouped imports
3. **No Alignment**: Reduces diff noise in security reviews
4. **Explicit Types**: Aids in security auditing

## Troubleshooting

### VS Code Issues
- **Rust-analyzer slow**: Restart VS Code
- **Lints not showing**: Check Output → Rust Analyzer
- **Format on save not working**: Verify `editor.formatOnSave` is true

### CLI Issues
- **Clippy outdated**: Run `rustup update`
- **Unknown lint**: Check clippy version matches MSRV
- **Format differs from CI**: Ensure same rustfmt version

## Best Practices

1. **Run lints frequently**: Don't let violations accumulate
2. **Fix immediately**: Address issues as you code
3. **Document allows**: Always explain why a lint is allowed
4. **Review security**: Get team review for security lint exceptions
5. **Stay updated**: Keep tools updated with `rustup update`

## Additional Resources

- [Clippy Lint Index](https://rust-lang.github.io/rust-clippy/master/)
- [Rustfmt Configuration](https://rust-lang.github.io/rustfmt/)
- [Security Best Practices](./SECURITY_BEST_PRACTICES.md)
- [Code Review Guidelines](./CODE_REVIEW.md)