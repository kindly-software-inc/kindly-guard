# Crate Consolidation Plan for v0.11.15

## Current Problem
- `cargo install kindly-guard` installs a wrapper that downloads from GitHub
- `cargo install kindly-guard-server` installs the actual server
- This is confusing for users who expect `kindly-guard` to be the main package

## Solution for v0.11.15

### Option 1: Simple Re-export (Recommended)
Create a new `kindly-guard` v0.11.15 that:
1. Depends on `kindly-guard-server = "0.11.14"`
2. Re-exports the library functionality
3. Has its own `main.rs` that just calls the server's main

```toml
# crates-io-package/kindly-guard/Cargo.toml
[package]
name = "kindly-guard"
version = "0.11.15"

[dependencies]
kindly-guard-server = { version = "0.11.14" }

[[bin]]
name = "kindly-guard"
path = "src/main.rs"
```

```rust
// src/main.rs
fn main() {
    kindly_guard_server::cli::main()
}
```

### Option 2: Direct Publishing
1. Create new directory `crates-io-package/kindly-guard-v2`
2. Copy all code from `kindly-guard-server`
3. Rename package to `kindly-guard`
4. Publish as v0.11.15

### Option 3: Yank and Replace
1. Yank `kindly-guard` v0.11.14
2. Wait a few minutes
3. Re-publish `kindly-guard-server` code as `kindly-guard` v0.11.14

## Recommendation: Option 1

### Why Option 1?
- Minimal code changes
- Maintains backward compatibility
- Clear upgrade path
- No need to maintain duplicate code
- Users get the actual server when they install `kindly-guard`

### Implementation Steps:
1. Update `crates-io-package/kindly-guard/Cargo.toml`
2. Replace installer code with simple re-export
3. Bump version to 0.11.15
4. Publish to crates.io

### User Experience:
```bash
# New users:
cargo install kindly-guard  # Gets the actual server v0.11.15

# Existing users with v0.11.14:
cargo install --force kindly-guard  # Upgrades to actual server

# Direct server install still works:
cargo install kindly-guard-server
```

### Impact on kindly-tools:
- `kindly-tools install kindly-guard` can now just run `cargo install kindly-guard`
- Or continue using GitHub releases for pre-built binaries

## Timeline
1. Implement Option 1 now for v0.11.15
2. Update documentation
3. Publish immediately
4. Monitor user feedback
5. Consider full consolidation for v0.12.0