# Validate Dist Command

The `validate-dist` command helps catch distribution configuration problems before pushing to GitHub.

## Usage

```bash
# Validate all workspace members
cargo xtask validate-dist

# Show detailed validation output
cargo xtask validate-dist --detailed

# Validate a specific package
cargo xtask validate-dist --package kindly-guard-server

# Dry run mode (no changes)
cargo xtask validate-dist --dry-run
```

## What It Checks

### 1. Binary Naming Conventions
- Validates that binary names follow expected patterns
- Checks for consistency with package names
- Warns about underscore vs hyphen usage

### 2. Cargo.toml Structure
- Verifies explicit `[[bin]]` sections for binaries
- Checks for dist-related metadata
- Validates package configuration

### 3. Cargo Dist Plan
- Runs `cargo dist plan --output-format=json`
- Parses and validates the output
- Checks for:
  - Announcement tags
  - Release definitions
  - Artifact generation
  - Installer configurations

### 4. Expected Patterns

The validator expects binary names to follow these patterns:
- Match the package name exactly (e.g., `kindly-guard-server`)
- Shortened version without "-guard" (e.g., `kindly-server`)
- Main command names (e.g., `kindlyguard` for CLI)

## Error Types

### Issues (Must Fix)
- Missing cargo-dist installation
- cargo dist plan failures
- No releases defined
- Missing artifacts

### Warnings (Should Consider)
- Missing announcement tags
- Non-standard naming conventions
- Missing installer configurations
- Implicit binary targets

## Integration with CI

This command can be added to your CI pipeline:

```yaml
- name: Validate dist configuration
  run: cargo xtask validate-dist
```

## Troubleshooting

If `cargo-dist` is not installed:
```bash
cargo install cargo-dist
```

If the plan fails, check:
1. Workspace.metadata.dist configuration in root Cargo.toml
2. Binary definitions in package Cargo.toml files
3. Target platform specifications