# Release v0.11.14

## CI/CD Fixes

### Fixed
- Fixed `cargo xtask` command not found error by adding alias to .cargo/config.toml
- Fixed xtask test import errors by correcting module paths
- Fixed GitHub release workflow by replacing deprecated create-release action with gh CLI

### Changes
- Added cargo alias for xtask: `xtask = "run --package xtask --"`
- Fixed import path for `ensure_tool_installed` function in xtask tests

These changes resolve the CI failures that were preventing successful builds and releases.
