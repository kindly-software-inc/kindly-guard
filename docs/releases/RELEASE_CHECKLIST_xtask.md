# Release Checklist Feature

The `xtask` release command now includes an interactive pre-release checklist feature that ensures all necessary checks are completed before creating a release.

## Usage

### Run the interactive checklist:
```bash
cargo xtask release --checklist
```

### Run checklist with a target version:
```bash
cargo xtask release --checklist 1.2.3
```

## Pre-Release Checks

The checklist performs the following automated checks:

### 1. **Version Consistency** ❗ Critical
- Verifies all version numbers are synchronized across:
  - `Cargo.toml` (workspace and individual crates)
  - `package.json` (if present)
  - Other configured version files
- **Failure Action**: Offers to automatically update all versions

### 2. **Changelog Updates** ⚠️ Warning
- Checks if `CHANGELOG.md` exists
- Verifies entry for target version (if specified)
- **Failure Action**: Warns but allows continuation

### 3. **Documentation Status** ⚠️ Warning
- Verifies required documentation files exist:
  - `README.md`
  - `LICENSE`
- Runs `cargo doc` to ensure docs build successfully
- **Failure Action**: Warns for missing files, fails for doc build errors

### 4. **Test Coverage** ❗ Critical
- Runs all unit tests (`cargo test` or `cargo nextest`)
- Runs documentation tests
- **Failure Action**: Blocks release on test failures

### 5. **Security Audit** ❗ Critical
- Runs `cargo audit` to check for known vulnerabilities
- **Failure Action**: Blocks release if vulnerabilities found
- **Skip if**: `cargo-audit` not installed (warning issued)

### 6. **License Verification** ❗ Critical/⚠️ Warning
- Checks for `LICENSE` file existence (critical)
- Runs `cargo deny check licenses` if available (warning)
- **Failure Action**: Blocks if LICENSE missing, warns for compliance issues

### 7. **Build Verification** ❗ Critical
- Builds in debug mode
- Builds in release mode
- **Failure Action**: Blocks release on build failures

### 8. **Git Repository Status** ⚠️ Warning
- Checks for uncommitted changes
- Verifies current branch (warns if not on main/master)
- **Failure Action**: Warns but allows continuation

### 9. **Dependency Check** ⚠️ Warning
- Checks for unused dependencies using `cargo machete` (if installed)
- **Failure Action**: Warns about unused dependencies

### 10. **MSRV Compatibility** ⚠️ Warning
- Tests build against Minimum Supported Rust Version (1.81)
- **Failure Action**: Warns if MSRV build fails
- **Skip if**: MSRV toolchain not installed

## Interactive Features

### Version Update
If a target version is provided and all checks pass, the checklist offers to:
- Update all version files automatically
- Synchronize versions across the workspace

### Release Notes Generation
After successful checks, the tool can interactively generate release notes:
- Prompts for items in each changelog category:
  - Added (new features)
  - Changed (modifications)
  - Deprecated (soon-to-be removed)
  - Removed (deleted features)
  - Fixed (bug fixes)
  - Security (security updates)
- Automatically formats entries
- Updates `CHANGELOG.md` with the new release section

## Summary Report

After all checks complete, the tool provides:
- Current version
- Target version (if specified)
- Total errors (blocks release)
- Total warnings (informational)
- Next steps for completing the release

## Integration with Release Command

The checklist is designed to be run before the main release command:

```bash
# First, run the checklist
cargo xtask release --checklist 1.2.3

# If all checks pass, proceed with release
cargo xtask release 1.2.3
```

## Configuration

The checklist uses the same configuration as other xtask commands:
- Version locations from `version-locations.json`
- Release configuration from `release-config.toml`
- Standard Cargo workspace configuration

## Error Handling

- **Critical Errors** (❗): Block the release process
- **Warnings** (⚠️): Informational, allow continuation
- **Skipped Checks**: When optional tools aren't installed

## Benefits

1. **Consistency**: Ensures all files have matching versions
2. **Quality**: Verifies tests pass and docs build
3. **Security**: Checks for known vulnerabilities
4. **Compliance**: Verifies license requirements
5. **Documentation**: Helps maintain changelog
6. **Automation**: Reduces manual release steps

## Requirements

### Required Tools
- Rust toolchain
- Git

### Optional Tools (for enhanced checks)
- `cargo-nextest`: Better test runner
- `cargo-audit`: Security vulnerability scanner
- `cargo-deny`: Supply chain security
- `cargo-machete`: Unused dependency detector
- MSRV toolchain (1.81): For compatibility testing

Install optional tools:
```bash
cargo install cargo-nextest cargo-audit cargo-deny cargo-machete
rustup toolchain install 1.81
```