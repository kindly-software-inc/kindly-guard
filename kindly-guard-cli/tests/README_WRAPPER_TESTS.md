# CLI Wrapper Security Tests

This directory contains comprehensive security tests for the `kindly-guard-cli wrap` command.

## Test Coverage

### 1. Command Injection Prevention
- `test_command_injection_prevention_semicolon` - Tests semicolon injection prevention
- `test_command_injection_prevention_backticks` - Tests backtick command substitution prevention
- `test_command_injection_prevention_dollar_parens` - Tests $() command substitution prevention

### 2. Environment Variable Security
- `test_environment_variable_security` - Ensures sensitive env vars are not leaked
- `test_environment_injection_prevention` - Prevents env var injection attacks

### 3. Signal Handling and Process Isolation
- `test_signal_handling_sigint` - Verifies SIGINT forwarding to child process
- `test_signal_handling_sigterm` - Verifies SIGTERM handling
- `test_process_isolation_file_descriptors` - Ensures file descriptors aren't leaked

### 4. Input/Output Stream Security
- `test_input_stream_unicode_injection` - Detects unicode injection attacks
- `test_input_stream_sql_injection` - Detects SQL injection attempts
- `test_input_stream_command_injection` - Detects command injection in input
- `test_input_stream_xss_injection` - Detects XSS attempts
- `test_output_stream_passthrough` - Verifies clean output passes through
- `test_null_byte_injection` - Handles null byte injection
- `test_ansi_escape_injection` - Detects ANSI escape sequence injection

### 5. Blocking vs Warning Mode
- `test_blocking_mode_blocks_threats` - Verifies blocking mode prevents threats
- `test_warning_mode_allows_threats` - Verifies warning mode allows but warns

### 6. AI CLI Integration
- `test_ai_cli_integration_gemini_style` - Tests Gemini CLI compatibility
- `test_ai_cli_integration_codex_style` - Tests Codex CLI compatibility
- `test_interactive_prompt_handling` - Handles interactive prompts

### 7. Additional Security Tests
- `test_path_traversal_prevention` - Prevents path traversal attacks
- `test_resource_exhaustion_prevention` - Handles resource exhaustion attempts
- `test_malformed_utf8_handling` - Handles malformed UTF-8 gracefully
- `test_symlink_resolution` - Safely resolves symbolic links
- `test_working_directory_isolation` - Ensures proper directory isolation

## Running the Tests

```bash
# Run all wrapper security tests
cargo test -p kindly-guard-cli cli_wrapper_security_tests

# Run a specific test
cargo test -p kindly-guard-cli test_command_injection_prevention_semicolon

# Run with output for debugging
cargo test -p kindly-guard-cli cli_wrapper_security_tests -- --nocapture

# Run tests in release mode (recommended for performance tests)
cargo test -p kindly-guard-cli cli_wrapper_security_tests --release
```

## Test Requirements

- Unix-like system (Linux/macOS) for signal handling tests
- Cargo and Rust toolchain
- `nix` crate for signal handling (included in dev-dependencies)

## Test Helpers

The tests use several helper functions:
- `wrap_cmd()` - Creates a command builder for the wrap subcommand
- `create_mock_cli()` - Creates a mock AI CLI script for testing

## Adding New Tests

When adding new security tests:
1. Follow the existing test naming convention: `test_<category>_<specific_test>`
2. Use descriptive assertions with `predicates`
3. Clean up any temporary files or resources
4. Document the threat being tested in comments

## Security Considerations

These tests verify that the wrapper:
- Never executes injected commands
- Properly isolates the wrapped process
- Detects and handles various attack vectors
- Maintains security in both blocking and warning modes
- Works correctly with real AI CLI tools