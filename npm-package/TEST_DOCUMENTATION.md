# KindlyGuard NPM Package Test Documentation

## Overview

This document describes the comprehensive test suite created for the KindlyGuard NPM package. The tests verify installation, platform compatibility, and various usage scenarios.

## Test Structure

### 1. Installation Tests (`test-install.sh`)

A comprehensive shell script that tests the full installation process:

- **Platform Detection**: Verifies correct detection of OS and architecture
- **Clean Install**: Simulates fresh npm install in a clean directory
- **Binary Download**: Tests URL construction and download simulation
- **Postinstall Script**: Validates the postinstall process
- **NPX Usage**: Tests execution via npx
- **Programmatic API**: Validates the JavaScript API
- **Error Handling**: Tests various error scenarios
- **Security Checks**: Validates file permissions and security

### 2. Platform-Specific Test Harnesses

Located in `test-harness/` directory:

#### `test-platform-linux.js`
- Platform detection (linux)
- Architecture detection (x64/arm64)
- File permissions (chmod 755)
- Symlink support
- Shell wrapper scripts
- Case sensitivity checks

#### `test-platform-darwin.js`
- Platform detection (darwin)
- Architecture detection (x64/arm64 for Apple Silicon)
- Code signing awareness
- Gatekeeper implications
- Quarantine attribute handling
- Rosetta 2 compatibility

#### `test-platform-win32.js`
- Platform detection (win32)
- Architecture detection (x64 only)
- Executable extension (.exe)
- Path separator (backslash)
- Drive letter handling
- UAC considerations
- Windows Defender awareness

#### `run-tests.js`
- Main test harness runner
- Automatically selects appropriate platform tests
- Runs common installation tests
- Provides comprehensive output

### 3. Integration Tests

Located in `integration-tests/` directory:

#### `test-claude-desktop.js`
- Configuration structure validation
- Config file path detection
- STDIO mode communication protocol
- Tool registration format
- Error handling in STDIO mode
- Alternative configuration formats

#### `test-npx-usage.js`
- Basic npx execution
- NPX with --stdio flag
- One-time execution
- Version-specific usage
- Environment variable passing
- Piped input handling
- Error handling
- Cache behavior

#### `test-programmatic-api.js`
- API structure validation
- Scan function (clean text and threats)
- Instance creation and configuration
- File scanning capability
- Monitoring functionality
- Batch scanning
- Stream processing
- Error handling
- Performance testing

#### `test-cli-commands.js`
- Help command
- Version command
- Scan command (with/without threats)
- Monitor command
- Status command
- Config commands (show/set)
- Unknown command handling
- Pipe support
- Output formats
- Exit codes

#### `run-all-tests.sh`
- Master test runner
- Executes all test suites
- Generates comprehensive reports
- Tracks success/failure rates
- Creates timestamped results directory

## Known Issues and Solutions

### Issue 1: Platform-Specific Binary Distribution

**Problem**: NPM doesn't natively support platform-specific binaries well.

**Solution**: 
- Use optional dependencies for platform packages
- Implement postinstall script to copy correct binary
- Provide fallback instructions for manual installation

### Issue 2: Binary Download During Install

**Problem**: Downloading binaries during npm install can fail due to network issues.

**Solution**:
- Pre-publish platform-specific packages to npm
- Use optional dependencies instead of download-on-install
- Provide clear error messages with manual installation steps

### Issue 3: Permission Issues on Unix Systems

**Problem**: Binaries need executable permissions on Unix-like systems.

**Solution**:
- Postinstall script uses `fs.chmodSync(path, 0o755)`
- Create wrapper scripts with proper shebang
- Test for permission errors and provide helpful messages

### Issue 4: Windows Path and Extension Handling

**Problem**: Windows requires .exe extension and has different path handling.

**Solution**:
- Detect Windows platform and add .exe extension
- Use path.join() for cross-platform paths
- Handle drive letters correctly

### Issue 5: Claude Desktop Integration Path

**Problem**: Config file location varies by platform.

**Solution**:
- Detect platform and construct appropriate path
- Provide example configurations for each platform
- Document the integration process clearly

## Test Execution

### Running Individual Tests

```bash
# Platform tests
node test-harness/run-tests.js

# Integration tests
node integration-tests/test-claude-desktop.js
node integration-tests/test-npx-usage.js
node integration-tests/test-programmatic-api.js
node integration-tests/test-cli-commands.js

# Installation test
./test-install.sh
```

### Running All Tests

```bash
cd integration-tests
./run-all-tests.sh
```

## Test Results Format

The test suite generates:
- Individual log files for each test suite
- Summary report with pass/fail statistics
- Timestamped results directory
- NPM audit report (if applicable)

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
test:
  runs-on: ${{ matrix.os }}
  strategy:
    matrix:
      os: [ubuntu-latest, macos-latest, windows-latest]
      node: [14, 16, 18]
  steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-node@v3
      with:
        node-version: ${{ matrix.node }}
    - run: cd npm-package && npm install
    - run: cd npm-package/integration-tests && ./run-all-tests.sh
```

## Future Improvements

1. **Mock Binary Testing**: Create actual mock binaries for more realistic tests
2. **Network Failure Simulation**: Test behavior when GitHub releases are unavailable
3. **Performance Benchmarks**: Add performance regression tests
4. **Security Scanning**: Integrate security scanning tools
5. **Cross-Platform Docker Tests**: Use Docker to test all platforms from any host

## Troubleshooting

### Common Test Failures

1. **"Platform not supported"**
   - Ensure you're on a supported platform (Linux x64/arm64, macOS x64/arm64, Windows x64)

2. **"npm: command not found"**
   - Install Node.js and npm before running tests

3. **"Permission denied"**
   - On Unix systems, ensure test scripts have execute permissions
   - Run `chmod +x *.sh *.js` in test directories

4. **"Cannot find module"**
   - Run tests from the correct directory
   - Ensure all test files are present

## Conclusion

This comprehensive test suite ensures KindlyGuard can be reliably installed and used across different platforms and scenarios. The tests cover:

- ✅ Multi-platform support (Linux, macOS, Windows)
- ✅ Multiple architectures (x64, arm64)
- ✅ Various installation methods (npm, npx, global, local)
- ✅ All usage patterns (CLI, API, MCP server)
- ✅ Error handling and edge cases
- ✅ Security considerations

Regular execution of these tests helps maintain quality and catch regressions early.