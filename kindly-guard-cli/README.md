# kindly-guard-cli

Command-line interface for KindlyGuard - a security-focused tool for detecting and neutralizing threats in text content.

## Installation

```bash
cargo install kindly-guard-cli
```

Or download pre-built binaries from the [releases page](https://github.com/kindly-software-inc/kindly-guard/releases).

## Usage

### Scan a file or directory

```bash
kindly-guard-cli scan <path>
```

### Start the security server

```bash
kindly-guard-cli server
```

### Real-time monitoring

```bash
kindly-guard-cli monitor
```

## Features

- 🛡️ **Unicode Security**: Detects homograph attacks, invisible characters, and BiDi overrides
- 🚫 **Injection Prevention**: SQL, command, LDAP, and XPath injection detection
- 🔍 **XSS Protection**: Context-aware cross-site scripting prevention
- 📊 **Pattern Matching**: Custom security patterns and ML-based detection
- ⚡ **High Performance**: Optimized scanning with minimal overhead

## Examples

### Scan a single file
```bash
kindly-guard-cli scan document.txt
```

### Scan with JSON output
```bash
kindly-guard-cli scan --format json file.txt
```

### Interactive mode with real-time protection
```bash
kindly-guard-cli monitor --shield
```

## Configuration

Place a `kindly-guard.toml` file in your project root or use `--config` flag:

```toml
[scanner]
enabled_scanners = ["unicode", "injection", "xss", "patterns"]
severity_threshold = "medium"

[output]
format = "pretty"
verbose = false
```

## License

Apache-2.0 - See [LICENSE](../LICENSE) for details.

## More Information

For complete documentation, visit [https://docs.kindlyguard.dev](https://docs.kindlyguard.dev)