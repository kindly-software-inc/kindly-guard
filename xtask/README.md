# xtask - Build Automation for KindlyGuard

A comprehensive build automation tool for the KindlyGuard project, providing release management, multi-platform builds, testing, security audits, and publishing capabilities.

## Installation

```bash
# From the project root
cargo install --path xtask
```

## Commands

### Release

Orchestrates the entire release process including tests, builds, tagging, and publishing.

```bash
# Interactive release (prompts for version)
cargo xtask release

# Release specific version
cargo xtask release 1.0.0

# Create pre-release
cargo xtask release 1.0.0-rc.1 --prerelease

# Skip certain steps
cargo xtask release --skip-tests --skip-publish

# Dry run
cargo xtask release --dry-run
```

### Build

Build the project for multiple platforms with cross-compilation support.

```bash
# Build for all default platforms
cargo xtask build

# Build for specific targets
cargo xtask build --targets x86_64-unknown-linux-gnu,x86_64-apple-darwin

# Build with release optimizations and stripping
cargo xtask build --release --strip --archive

# Custom output directory
cargo xtask build --output-dir dist/
```

Supported targets:
- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

### Test

Run comprehensive test suites with coverage and benchmarking support.

```bash
# Run all tests
cargo xtask test

# Run specific test types
cargo xtask test --unit
cargo xtask test --integration
cargo xtask test --security
cargo xtask test --bench

# Generate coverage report
cargo xtask test --coverage

# Use nextest runner
cargo xtask test --nextest

# Test specific package
cargo xtask test --package kindly-guard-server
```

### Security

Run security audits and dependency checks.

```bash
# Run all security checks
cargo xtask security --all

# Run specific tools
cargo xtask security --audit
cargo xtask security --deny

# Generate SARIF report
cargo xtask security --sarif

# Strict mode (fail on warnings)
cargo xtask security --strict
```

### Version

Manage version numbers across all project files.

```bash
# Show current versions
cargo xtask version --show

# Check version consistency
cargo xtask version --check

# Update to new version
cargo xtask version 1.0.0

# Update version and changelog
cargo xtask version 1.0.0 --changelog

# Update and commit
cargo xtask version 1.0.0 --changelog --commit
```

### Publish

Publish packages to various registries.

```bash
# Publish to all registries
cargo xtask publish

# Publish to specific registries
cargo xtask publish --crates-io
cargo xtask publish --npm
cargo xtask publish --docker

# Skip verification
cargo xtask publish --skip-verification

# Dry run
cargo xtask publish --dry-run
```

## Configuration

### Release Configuration

Create a `release-config.toml` file to customize release behavior:

```toml
[registries]
crates_io = true
npm = true
docker = true
github_releases = true

[platforms]
targets = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
]
strip_binaries = true
compress = true

[github]
owner = "kindly-software"
repo = "kindlyguard"
draft = false
prerelease = false
generate_notes = true

[security]
audit = true
deny = true
sarif_report = true
fail_on_warnings = true
```

### Version Locations

Define where version numbers should be updated in `version-locations.json`:

```json
{
  "files": [
    {
      "path": "Cargo.toml",
      "pattern": "^version = \".*\"$",
      "replacement": "version = \"{VERSION}\""
    },
    {
      "path": "package.json",
      "pattern": "\"version\": \".*\"",
      "replacement": "\"version\": \"{VERSION}\""
    }
  ]
}
```

## Environment Variables

- `GITHUB_TOKEN` - Required for creating GitHub releases
- `CARGO_REGISTRY_TOKEN` - Required for publishing to crates.io
- `NPM_TOKEN` - Required for publishing to npm
- `DOCKER_USERNAME` / `DOCKER_PASSWORD` - Required for Docker Hub

## Typical Workflow

1. **Development**: Make changes and commit them
2. **Version Bump**: `cargo xtask version 1.0.0 --changelog`
3. **Release**: `cargo xtask release`
   - Runs tests
   - Runs security audits
   - Updates versions
   - Builds for all platforms
   - Creates git tag
   - Publishes to registries
   - Creates GitHub release

## Troubleshooting

### Build Failures

- Ensure `cross` is installed for cross-compilation: `cargo install cross`
- Check that Docker is running (required for `cross`)
- Verify target toolchains are installed

### Publishing Issues

- Ensure authentication tokens are set in environment
- Check that versions haven't already been published
- Verify git tag exists before publishing

### Security Audit Failures

- Run `cargo update` to update dependencies
- Check `deny.toml` configuration
- Review and fix reported vulnerabilities

## Development

To work on xtask itself:

```bash
# Run from xtask directory
cargo run -- <command>

# Example: dry run a release
cargo run -- release --dry-run
```

## License

Part of the KindlyGuard project. See the main project LICENSE file.