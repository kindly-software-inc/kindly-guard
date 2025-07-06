# KindlyGuard Crate Consolidation Plan

## Current State Analysis

### Existing Crates Structure
1. **kindly-guard-server** (v0.11.14)
   - The actual implementation of KindlyGuard
   - Contains all security scanning, MCP protocol, and core functionality
   - Binary name: `kindly-guard`
   - Published as main implementation crate

2. **kindly-guard** (v0.11.14) - in `crates-io-package/`
   - Installer/wrapper crate that downloads the actual binary
   - Downloads from GitHub releases
   - Installs to `~/.kindlyguard/bin/`
   - Acts as a shim that runs the downloaded binary

3. **kindly-tools** (v0.11.14)
   - Development tools and utilities
   - Depends on kindly-guard-server
   - Has `install` subcommand (unclear current purpose)

## Consolidation Options

### Option A: Move Server Code to crates-io-package/kindly-guard
**Pros:**
- Clean namespace - single `kindly-guard` crate
- No breaking changes for users who installed via `cargo install kindly-guard`
- Maintains the existing crate name on crates.io

**Cons:**
- Requires moving all server code to different directory
- May confuse development workflow
- The installer pattern becomes obsolete

**Implementation Steps:**
1. Move all code from `kindly-guard-server/` to `crates-io-package/kindly-guard/`
2. Update workspace members in root Cargo.toml
3. Remove the installer code, make it the actual implementation
4. Update all internal dependencies
5. Bump version to 0.11.15

### Option B: Rename kindly-guard-server to kindly-guard
**Pros:**
- Minimal code movement
- Clear that this is the main implementation
- Workspace structure stays mostly the same

**Cons:**
- **CRITICAL**: Cannot rename on crates.io - would need to yank existing kindly-guard
- Users who installed `kindly-guard` would get the installer, not the server
- Breaking change for existing users

**Implementation Steps:**
1. Yank kindly-guard 0.11.14 from crates.io
2. Rename kindly-guard-server directory and package name
3. Remove crates-io-package/kindly-guard
4. Publish renamed crate as kindly-guard 0.11.15

### Option C: Create New kindly-guard that Re-exports kindly-guard-server
**Pros:**
- No breaking changes
- Clean public API
- Can gradually migrate users
- Keeps both crates functional

**Cons:**
- Still have two crates
- Added complexity in maintenance
- Not really consolidating, just hiding complexity

**Implementation Steps:**
1. Replace installer in crates-io-package/kindly-guard with re-export wrapper
2. Make it depend on and re-export kindly-guard-server
3. Version bump to 0.11.15

### Option D: Deprecate Installer Pattern, Keep Server as Main (RECOMMENDED)
**Pros:**
- Acknowledges that cargo install is the primary distribution method
- No complex binary downloading needed
- Simpler maintenance
- Clear separation of concerns

**Cons:**
- Users need to know to install `kindly-guard-server`
- The `kindly-guard` name is "taken" by installer

**Implementation Steps:**
1. Update kindly-guard installer to show deprecation notice
2. Point users to install kindly-guard-server directly
3. Eventually yank old kindly-guard versions
4. Consider publishing kindly-guard as alias/re-export in future

## Version Numbering Strategy

### Current State:
- All crates at 0.11.14
- Last published to crates.io

### Options:
1. **Bump to 0.11.15**: Normal version progression
2. **Yank 0.11.14**: If we made breaking changes (required for Option B)
3. **Jump to 0.12.0**: If we want to signal major restructuring

## Impact on kindly-tools Install Command

The `kindly-tools install` command needs to be evaluated:
- If it installs kindly-guard components, update to new structure
- Consider deprecating if cargo install is preferred method
- Update documentation accordingly

## Recommendation: Hybrid Approach

1. **Short Term (v0.11.15)**:
   - Keep current structure
   - Update kindly-guard installer to show message: "Installing kindly-guard-server..."
   - Make installer smarter - check if kindly-guard-server is available via cargo first
   - Update documentation to prefer `cargo install kindly-guard-server`

2. **Medium Term (v0.12.0)**:
   - Deprecate the installer pattern officially
   - Convert crates-io-package/kindly-guard to re-export wrapper
   - This gives users time to migrate

3. **Long Term (v1.0.0)**:
   - Single consolidated crate
   - Clear naming and structure
   - Yank old installer versions

## Implementation Checklist

- [ ] Decision on consolidation approach
- [ ] Update version numbers in all Cargo.toml files
- [ ] Update GitHub Actions workflows
- [ ] Update installation documentation
- [ ] Test cargo install flow
- [ ] Update kindly-tools if needed
- [ ] Prepare release notes explaining changes
- [ ] Consider impact on existing users

## Migration Guide for Users

### If using cargo install kindly-guard:
```bash
# Old way (installer)
cargo install kindly-guard

# New recommended way
cargo install kindly-guard-server
```

### If using pre-built binaries:
- No change, still download from GitHub releases

### If using kindly-tools:
- Update to latest version
- Commands remain the same