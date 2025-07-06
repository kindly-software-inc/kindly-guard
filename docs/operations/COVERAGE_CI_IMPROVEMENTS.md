# Coverage Command CI Environment Improvements

## Summary

Updated the xtask coverage command to be smarter about GitHub Actions environment, distinguishing between different CI systems and providing appropriate behavior for each.

## Changes Made

### 1. Enhanced CI Environment Detection (`xtask/src/utils/tools.rs`)

- Added `is_github_actions()` function to specifically detect GitHub Actions
- Created `CiEnvironment` enum with three states:
  - `None`: Not in CI (local/interactive environment)
  - `GitHubActions`: Running in GitHub Actions
  - `Other`: Running in other CI systems

### 2. Improved Tool Installation Logic

The `ensure_tool_installed` function now behaves differently based on environment:

- **GitHub Actions**: Only checks if tools exist, never attempts installation
  - Provides clear error messages with installation instructions
  - Respects that GitHub Actions workflows should handle tool installation
  
- **Other CI Systems**: Attempts auto-installation via `cargo install`
  - Maintains backward compatibility with existing CI setups
  
- **Local/Interactive**: Prompts user for permission to install

### 3. Better Error Messages (`xtask/src/commands/coverage.rs`)

- Added environment detection at the start of coverage command
- Provides context-specific error messages when tools are missing
- In GitHub Actions, suggests using `taiki-e/install-action` or `cargo install`

## Example Error Messages

### GitHub Actions
```
cargo-llvm-cov is required but not installed in GitHub Actions.
Please ensure the workflow installs required tools.
For example, use 'taiki-e/install-action@cargo-llvm-cov' or add to the workflow:
  - run: cargo install cargo-llvm-cov
```

### Other CI
```
CI environment detected - auto-installing cargo-llvm-cov
```

### Local
```
cargo-llvm-cov is required but not installed. Would you like to install it now? [Y/n]
```

## Benefits

1. **Respects GitHub Actions workflows**: No unexpected tool installations that could interfere with caching or pre-installed tools
2. **Clear guidance**: Developers know exactly what to add to their workflows
3. **Maintains convenience**: Other CI systems still get automatic installation
4. **Better debugging**: Environment detection is logged for troubleshooting

## Testing

Run the included test script to verify behavior:
```bash
./test_ci_environment.sh
```

This will test the coverage command in three environments:
1. No CI (local)
2. GitHub Actions
3. Other CI

## Migration

No changes needed for existing workflows that already install tools. The new behavior is backward compatible and only affects workflows that rely on auto-installation.