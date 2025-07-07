# Advanced Threat Testing Suite for KindlyGuard

This comprehensive test suite validates KindlyGuard's quarantine system against sophisticated security threats.

## Overview

The `test_advanced_threats.py` script tests KindlyGuard's ability to detect and quarantine:

1. **Advanced Unicode Attacks**
   - Bidirectional text manipulation
   - Zero-width character injection
   - Homograph attacks across multiple scripts
   - Unicode normalization exploits
   - Control character injection
   - Emoji-based attacks

2. **Multi-Stage SQL Injection**
   - Time-based blind SQL injection
   - Stacked queries
   - Second-order injection
   - Advanced UNION attacks
   - WAF bypass techniques
   - NoSQL injection patterns

3. **Sophisticated XSS Payloads**
   - Event handler variations
   - Encoding bypass techniques
   - DOM-based XSS
   - Mutation XSS (mXSS)
   - Filter evasion
   - Advanced JavaScript payloads

4. **Command Injection Chains**
   - Command chaining techniques
   - Subshell execution
   - Encoding bypasses
   - Time-based attacks
   - Network-based exploits
   - Reverse shell attempts

5. **Path Traversal Attacks**
   - Classic directory traversal
   - Various encoding methods
   - Null byte injection
   - UNC path exploitation
   - Filter bypass techniques

6. **Prompt Injection Attacks**
   - Direct instruction override
   - Context manipulation
   - Encoded instructions
   - Social engineering
   - Multi-turn attacks
   - Hidden command smuggling

## Usage

### Prerequisites

1. Build KindlyGuard in release mode:
   ```bash
   cd ../
   cargo build --release
   ```

2. Ensure Python 3 is installed

### Running the Tests

From the `demo` directory:

```bash
./test_advanced_threats.py
```

### Understanding the Output

The script provides color-coded output:
- 🟢 **Green (✓)**: Threat successfully detected
- 🔴 **Red (✗)**: Threat not detected (security gap)
- 🟡 **Yellow**: Summary information
- 🟣 **Purple**: Category headers and quarantine status
- 🔵 **Blue**: Section headers
- 🔷 **Cyan**: Cleaned/neutralized text

### Results Interpretation

For each threat, the output shows:
- **Test name**: Description of the attack
- **Payload**: The actual malicious content (truncated if long)
- **Threats detected**: Number and types of threats found
- **Severity**: Risk level (critical/high/medium/low)
- **Quarantine status**: Whether the threat was quarantined
- **Cleaned text**: Neutralized version of the input

### Summary Metrics

The final summary provides:
- **Total tests run**: Number of threat payloads tested
- **Detection rate**: Percentage of threats detected
- **Quarantine rate**: Percentage of detected threats that were quarantined

### Success Criteria

- **Excellent**: ≥95% detection rate
- **Good**: ≥80% detection rate
- **Needs Improvement**: <80% detection rate

### Output Files

Results are saved to `test_results_[timestamp].json` containing:
- Test timestamp
- Summary statistics
- Detailed results for each test

## Customization

### Adding New Threats

To add new threat categories, create a generator function:

```python
def generate_new_threat_type() -> List[Tuple[str, str]]:
    return [
        ("Test name", "payload"),
        # Add more test cases
    ]
```

Then add it to the `test_categories` list in `main()`.

### Adjusting Test Parameters

- **Timeout**: Modify the `time.sleep()` between tests
- **Binary path**: Change `kindlyguard_path` in `ThreatTester.__init__`
- **Context**: Modify the `context` parameter in `test_threat()`

## Integration with CI/CD

This test suite can be integrated into CI pipelines:

```yaml
- name: Run advanced threat tests
  run: |
    cd demo
    python test_advanced_threats.py
    # Check exit code or parse results JSON
```

## Security Notes

⚠️ **Warning**: This script contains actual malicious payloads for testing purposes. 
- Only run in isolated test environments
- Do not use these payloads against production systems
- Ensure proper containment when testing

## Troubleshooting

### Common Issues

1. **Binary not found**: Ensure KindlyGuard is built in release mode
2. **Permission denied**: Make the script executable with `chmod +x`
3. **JSON parse errors**: Check KindlyGuard output format compatibility

### Debug Mode

Set environment variable for verbose output:
```bash
RUST_LOG=debug ./test_advanced_threats.py
```

## Next Steps

After running these tests:
1. Review detection gaps in the results
2. Update KindlyGuard's scanners for missed threats
3. Enhance quarantine rules for new attack patterns
4. Re-run tests to verify improvements

## Contributing

To contribute new test cases:
1. Identify emerging threat patterns
2. Add them to appropriate generator functions
3. Ensure payloads are properly documented
4. Submit PR with test results