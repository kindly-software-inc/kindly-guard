# Test Data Directory

This directory contains various test files for validating KindlyGuard's threat detection capabilities.

## Directory Structure

- **threats/**: Files containing known security threats
  - `sql_injection.txt`: Common SQL injection patterns
  - `xss_attacks.html`: Various XSS attack vectors
  - `unicode_threats.txt`: Unicode homograph and bidi attacks
  - `command_injection.sh`: Shell command injection attempts
  - `ldap_injection.txt`: LDAP injection patterns

- **benign/**: Files with legitimate content that should not trigger alerts
  - `technical_documentation.md`: Technical docs mentioning security terms
  - `shakespeare.txt`: Classic literature
  - `lorem_ipsum.txt`: Standard placeholder text
  - `recipe.json`: Harmless JSON data

- **mixed/**: Files containing both legitimate content and threats
  - `blog_post.html`: Blog post with hidden threats in comments
  - `user_data.json`: User data with some malicious entries

- **large/**: Large files for performance testing
  - `large_mixed_content.txt`: 5MB file with 5% threat content

## Usage

These files are used by the integration tests to verify:
1. Threat detection accuracy
2. False positive rates
3. Performance under load
4. Mixed content handling

## Running Tests

```bash
# Run all integration tests
cargo test --test '*' --features integration

# Run specific test suites
cargo test --test threat_detection_scenarios
cargo test --test cli_tests
cargo test --test mcp_protocol_test
```