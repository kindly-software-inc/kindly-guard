# Tool Installation Utilities

This module provides secure and user-friendly utilities for installing cargo tools in the KindlyGuard project.

## Features

- **CI/CD Support**: Automatically detects CI environments (via `CI` environment variable) and installs tools without prompting
- **Interactive Mode**: In non-CI environments, asks users for permission before installing
- **Proper Error Handling**: Follows KindlyGuard standards - no unwrap() or expect()
- **Verification**: Verifies tools are properly installed after installation
- **Batch Installation**: Support for installing multiple tools at once
- **Custom Commands**: Support for custom installation commands

## Usage

### Basic Usage

```rust
use xtask::utils::{Context, ensure_tool_installed};

let ctx = Context {
    dry_run: false,
    verbose: true,
};

// Install a single tool
match ensure_tool_installed(&ctx, "cargo-audit", None)? {
    true => println!("Tool is available"),
    false => println!("User declined or installation failed"),
}
```

### With Custom Configuration

```rust
use xtask::utils::tools::ToolInstallConfig;

let config = ToolInstallConfig {
    ci_auto_install: false,  // Don't auto-install in CI
    interactive: true,       // Prompt in interactive mode
    install_command: None,   // Use default cargo install
};

ensure_tool_installed(&ctx, "cargo-nextest", Some(config))?;
```

### Installing Multiple Tools

```rust
use xtask::utils::{ensure_tools_installed};
use xtask::utils::tools::common_tools;

// Install all security tools
let results = ensure_tools_installed(
    &ctx,
    common_tools::SECURITY_TOOLS,
    None,
)?;
```

### Custom Installation Command

```rust
let config = ToolInstallConfig {
    ci_auto_install: true,
    interactive: true,
    install_command: Some(vec![
        "cargo".to_string(),
        "install".to_string(),
        "--locked".to_string(),
        "cargo-outdated".to_string(),
    ]),
};

ensure_tool_installed(&ctx, "cargo-outdated", Some(config))?;
```

## Environment Detection

The module automatically detects CI environments by checking the `CI` environment variable:
- `CI=true` or `CI=1` → CI environment detected
- Otherwise → Interactive environment

## Common Tools

The module provides constants for commonly used tools:

```rust
pub mod common_tools {
    pub const CARGO_AUDIT: &str = "cargo-audit";
    pub const CARGO_NEXTEST: &str = "cargo-nextest";
    pub const CARGO_DIST: &str = "cargo-dist";
    pub const CARGO_GEIGER: &str = "cargo-geiger";
    
    pub const SECURITY_TOOLS: &[&str] = &[CARGO_AUDIT, CARGO_GEIGER];
    pub const TEST_TOOLS: &[&str] = &[CARGO_NEXTEST];
    pub const RELEASE_TOOLS: &[&str] = &[CARGO_DIST];
}
```

## Security Considerations

1. **No unwrap()/expect()**: All operations return proper `Result<T, E>` types
2. **User Consent**: Always asks for user permission in interactive mode
3. **Verification**: Verifies tool installation after completion
4. **Clear Logging**: Uses Context utility for consistent logging
5. **Dry Run Support**: Respects the Context's dry_run flag

## Integration Example

In your xtask commands:

```rust
pub async fn run(cmd: MyCommand, ctx: Context) -> Result<()> {
    // Ensure required tools are installed
    ensure_tool_installed(&ctx, "cargo-audit", None)?;
    
    // Now use the tool
    ctx.run_command("cargo", &["audit"])?;
    
    Ok(())
}
```