# Contributing to KindlyGuard

Thank you for your interest in contributing to KindlyGuard! We're excited to have you join our community of developers working to make the digital world safer through advanced security threat detection.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Security Issues](#security-issues)
- [Community Guidelines](#community-guidelines)
- [License](#license)

## Development Environment Setup

### Prerequisites

- **Rust toolchain** (1.81 or newer - see [MSRV Policy](docs/MSRV_POLICY.md))
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustup install 1.81  # Install our MSRV
  ```
- **Git** for version control
- **SQLite3** development libraries (for storage features)
  - Ubuntu/Debian: `sudo apt-get install libsqlite3-dev`
  - macOS: `brew install sqlite3`
  - Windows: Included with Rust

### Getting Started

1. **Fork the repository**
   ```bash
   # Visit https://github.com/kindlyguard/kindlyguard and click "Fork"
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/<your-username>/kindlyguard.git
   cd kindlyguard
   ```

3. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/kindlyguard/kindlyguard.git
   ```

4. **Build the project**
   ```bash
   # Standard build
   cargo build
   
   # Security-focused build (recommended)
   cargo build --profile=secure
   
   # Build with all features
   cargo build --all-features
   ```

5. **Run the development server**
   ```bash
   RUST_LOG=kindly_guard=debug cargo run
   ```

### Recommended Development Tools

Essential tools for KindlyGuard development:

- **rust-analyzer** - IDE support for VS Code, Vim, Emacs
- **cargo-nextest** - Next-generation test runner (60% faster)
  ```bash
  cargo install cargo-nextest
  cargo nextest run  # Instead of cargo test
  ```
- **bacon** - Background compiler with instant feedback
  ```bash
  cargo install bacon
  bacon  # Runs in terminal, shows errors as you code
  ```
- **cargo-deny** - Supply chain security auditing
  ```bash
  cargo install cargo-deny
  cargo deny check  # Run before every PR
  ```
- **cargo-audit** - CVE vulnerability scanner
  ```bash
  cargo install cargo-audit
  cargo audit  # Check for known vulnerabilities
  ```
- **typos** - Fast spell checker for code and docs
  ```bash
  cargo install typos-cli
  typos  # Check for typos before committing
  ```
- **committed** - Conventional commit linter
  ```bash
  cargo install committed
  committed --install  # Install as git hook
  ```

See [docs/DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) for complete tool documentation.

### Pre-commit Hooks (Security Shift-Left)

KindlyGuard uses pre-commit hooks to catch security issues before they enter the repository. This "security shift-left" approach makes secure coding the default path.

**Install pre-commit hooks:**
```bash
# Run the installation script
./scripts/install-hooks.sh

# Or manually install pre-commit
pip install --user pre-commit
pre-commit install --install-hooks
pre-commit install --hook-type commit-msg
```

**What the hooks check:**
- **rustfmt** - Prevents unicode hiding in weird formatting
- **clippy** - Catches common security vulnerabilities  
- **unsafe code** - Ensures all `unsafe` blocks have `SAFETY:` comments
- **detect-secrets** - Prevents API keys/passwords in commits
- **file size limits** - Prevents binary smuggling (>1MB files)
- **conventional commits** - Enables security audit trails
- **cargo audit** (pre-push) - Scans for known vulnerabilities

**Using the hooks:**
```bash
# Test all hooks manually
pre-commit run --all-files

# Skip hooks in emergency (document why in PR)
git commit --no-verify -m "fix: emergency fix for production"

# Update hooks to latest versions
pre-commit autoupdate
```

**Manual fallback:** If pre-commit isn't available, use the shell scripts in `.git-hooks/`

### Dependency Management

We use cargo-machete to detect unused dependencies, reducing attack surface:

```bash
# Install cargo-machete
cargo install cargo-machete

# Check for unused dependencies
cargo machete

# CI runs this weekly and on all PRs touching Cargo.toml
```

**Security implications of dependencies:**
- Every dependency is potential attack surface
- Unused dependencies still get downloaded and compiled
- Supply chain attacks can hide in unused code
- Regular auditing prevents dependency creep

## Code Style

We maintain high code quality standards to ensure security and maintainability.

### Formatting

- **Always run rustfmt before committing**
  ```bash
  cargo fmt
  ```

- **Check formatting in CI**
  ```bash
  cargo fmt -- --check
  ```

### Linting

- **Run clippy with all warnings enabled**
  ```bash
  cargo clippy -- -W clippy::all -W clippy::pedantic
  ```

- **Fix clippy warnings before submitting PR**
  ```bash
  cargo clippy --fix
  ```

### Code Guidelines

1. **Error Handling**
   - Always use `Result<T, E>` for fallible operations
   - NEVER use `unwrap()` or `expect()` in production code
   - Provide meaningful error messages

   ```rust
   // Good
   match dangerous_operation() {
       Ok(value) => process(value),
       Err(e) => {
           tracing::error!("Operation failed: {}", e);
           return Err(KindlyError::from(e));
       }
   }
   
   // Bad
   let value = dangerous_operation().unwrap(); // FORBIDDEN
   ```

2. **Security First**
   - Validate ALL external input
   - Use checked arithmetic operations
   - Document safety invariants for any unsafe blocks
   - Security comparisons must be constant-time

3. **Performance**
   - Prefer borrowing over cloning
   - Use `&str` instead of `String` for function parameters
   - Mark SIMD-optimizable sections with comments

4. **Documentation**
   - Document all public APIs
   - Include examples in doc comments
   - Explain security implications

## Testing

Testing is crucial for maintaining KindlyGuard's security guarantees.

### Running Tests

We use cargo-nextest for better test output and performance:

```bash
# Install nextest (one-time)
cargo install cargo-nextest

# Run all tests (replaces cargo test)
cargo nextest run

# Run tests with all features
cargo nextest run --all-features

# Run a specific test
cargo nextest run test_unicode_injection

# Run only failed tests from last run
cargo nextest run --failed

# Run tests in CI mode (with retries)
cargo nextest run --profile ci

# Traditional cargo test (if needed)
cargo test -- --nocapture

# Run property tests (fuzzing)
cargo test --test property_tests

# Generate coverage report
cargo nextest run --profile coverage
grcov . -s . -t html -o target/coverage/
```

### Writing Tests

1. **Unit Tests** - Place in the same file as the code
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       #[test]
       fn test_threat_detection() {
           let scanner = SecurityScanner::new();
           let threats = scanner.scan_text("Hello\u{202E}World");
           assert!(!threats.is_empty());
       }
   }
   ```

2. **Integration Tests** - Place in `tests/` directory
3. **Property Tests** - Use proptest for fuzzing
   ```rust
   proptest! {
       #[test]
       fn doesnt_crash(input: String) {
           let _ = scanner.scan_text(&input);
       }
   }
   ```

### Test Requirements

- Add tests for all new features
- Ensure tests cover edge cases
- Include security-specific test cases
- Test error conditions explicitly
- No test should depend on external services

## Submitting Changes

### Branching Strategy

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Keep your branch updated**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Commit Guidelines

We follow conventional commits for clear history and use git-cliff for automated changelog generation. Use the `committed` tool to ensure compliance:

```bash
# Install commit linter and changelog generator
cargo install committed git-cliff
committed --install  # Installs git hook

# Check your commit message
committed --staged

# Preview changelog generation
git-cliff --unreleased
```

#### Commit Types

**Security (Always Priority)**
- `security: <description>` - Security fixes and improvements
- `vuln: <description>` - Vulnerability patches
- `cve: <description>` - CVE-related fixes
- `audit: <description>` - Audit-related changes

**Standard Types**
- `feat(scope): <description>` - New features
- `fix(scope): <description>` - Bug fixes
- `perf(scope): <description>` - Performance improvements
- `docs: <description>` - Documentation only
- `test(scope): <description>` - Test additions or changes
- `refactor(scope): <description>` - Code refactoring
- `build: <description>` - Build system changes
- `ci: <description>` - CI/CD changes
- `deps: <description>` - Dependency updates
- `chore: <description>` - Other maintenance tasks

#### Scopes

Use these scopes to identify which component is affected:

**Scanner Components**
- `scanner` - General scanner functionality
- `unicode` - Unicode threat detection
- `injection` - Injection prevention
- `xss` - XSS protection
- `patterns` - Pattern detection

**Server Components**
- `server` - Server functionality
- `protocol` - MCP protocol handling
- `handler` - Request handling

**Other Components**
- `shield` - Shield UI
- `storage` - Storage layer
- `cache` - Caching functionality
- `resilience` - Circuit breakers, retry logic
- `config` - Configuration
- `cli` - Command-line interface
- `neutralizer` - Threat neutralization

#### Commit Message Format

```
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```

**Examples:**

```bash
# Security fix (no scope needed for security commits)
git commit -m "security: fix timing attack in token validation

Use constant-time comparison from subtle crate to prevent
timing attacks on authentication tokens.

Fixes: CVE-2024-XXXXX"

# Feature with scope
git commit -m "feat(scanner): add Windows command injection detection

- Detect cmd.exe injection patterns
- Add PowerShell-specific patterns
- Support Windows path traversal detection

Closes #123"

# Breaking change
git commit -m "feat(api)!: change scan endpoint response format

BREAKING CHANGE: scan endpoint now returns threats array
instead of single threat object to support multiple
threat detection."

# Performance improvement
git commit -m "perf(scanner): optimize unicode scanning with SIMD

Implement SIMD-accelerated unicode validation for 8x
faster homograph detection on x86_64 platforms."
```

**Commit Message Rules:**
- First line: type(scope): description (max 72 chars, 50 preferred)
- Blank line
- Body: detailed explanation (wrap at 72 chars)
- Footer: issue references, breaking changes, CVE references

#### Best Practices

1. **Security First**: Always prioritize security-related commits
2. **Clear Subject**: Keep the subject line under 72 characters
3. **Use Imperative**: Write as if giving a command ("add" not "added")
4. **Reference Issues**: Use "Fixes #123" or "Closes #123" in the footer
5. **Breaking Changes**: Add `!` after type/scope and explain in footer
6. **Multi-line Messages**: Use the body to explain the "why"

#### Audit Trail

For security and compliance, all commits are:
- Signed with GPG when possible
- Include author information
- Tracked in automated changelogs
- Subject to security review for sensitive changes

Configure git for signing:
```bash
git config --global user.signingkey YOUR_GPG_KEY
git config --global commit.gpgsign true
```

### Pull Request Process

1. **Before submitting:**
   - [ ] Run `cargo fmt` - Format code
   - [ ] Run `cargo clippy -- -W clippy::all -W clippy::pedantic` - Fix lints
   - [ ] Run `cargo nextest run --all-features` - All tests pass
   - [ ] Run `cargo deny check` - Dependencies are secure
   - [ ] Run `cargo audit` - No known vulnerabilities
   - [ ] Run `cargo +nightly udeps` - No unused dependencies
   - [ ] Run `typos` - No spelling errors
   - [ ] Run `committed` - Commit messages follow convention
   - [ ] Update documentation if needed
   - [ ] Add tests for new functionality (aim for >80% coverage)

2. **PR Title Format:**
   ```
   type(scope): clear description
   
   Example: feat(scanner): add Unicode normalization support
   ```

3. **PR Description Template:**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Performance improvement
   - [ ] Security fix
   
   ## Testing
   - [ ] Unit tests pass
   - [ ] Integration tests pass
   - [ ] Security tests added
   - [ ] Performance benchmarks show no regression
   
   ## Checklist
   - [ ] No new unsafe code
   - [ ] No unwrap() or expect()
   - [ ] Documentation updated
   - [ ] Follows code style guidelines
   ```

4. **Review Process:**
   - All PRs require at least one review
   - Security-related changes require security team review
   - CI must pass before merging

## Reporting Issues

### Creating Issues

Use GitHub Issues for:
- Bug reports
- Feature requests
- Documentation improvements
- Questions about the codebase

### Issue Template

```markdown
## Description
Clear description of the issue

## Steps to Reproduce (for bugs)
1. Step one
2. Step two
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.75.0]
- KindlyGuard version: [e.g., 0.1.0]

## Additional Context
Any other relevant information
```

### Good First Issues

Look for issues labeled `good first issue` if you're new to the project.

## Security Issues

**IMPORTANT:** Security vulnerabilities should NOT be reported through public GitHub issues.

### Reporting Security Vulnerabilities

1. **Email:** samuel@kindly.software
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes (if any)

3. **Response Time:**
   - Acknowledgment within 48 hours
   - Status update within 7 days
   - Fix timeline communicated ASAP

### Security Fix Process

1. Security team validates the issue
2. Fix developed in private
3. Security advisory prepared
4. Coordinated disclosure
5. Public release with credits

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Assume good intentions
- No harassment or discrimination

### Getting Help

- **Discord:** [Join our community](https://github.com/kindly-software/kindly-guard/discussions)
- **Documentation:** Check `/docs` folder
- **Examples:** See `/examples` directory
- **Discussions:** Use GitHub Discussions for questions

### Recognition

We value all contributions:
- Code contributions
- Bug reports
- Documentation improvements
- Community support
- Security research

Contributors are recognized in:
- Release notes
- CONTRIBUTORS.md file
- Security advisories (for security researchers)

## License

By contributing to KindlyGuard, you agree that your contributions will be licensed under the Apache License 2.0, the same as the project.

See the [LICENSE](LICENSE) file for details.

---

## Quick Start Commands

```bash
# Setup
git clone https://github.com/<your-username>/kindlyguard.git
cd kindlyguard
cargo build

# Install dev tools (one-time)
./scripts/install-dev-tools.sh

# Development
bacon                                       # Start background compiler
cargo fmt                                   # Format code
cargo clippy -- -W clippy::all              # Lint code
cargo nextest run --all-features            # Run tests (faster!)
RUST_LOG=kindly_guard=debug cargo run      # Run with debug logs

# Pre-commit checks
cargo fmt                                   # Format
cargo clippy --fix                         # Auto-fix lints
typos --write-changes                      # Fix typos
cargo nextest run                          # Test
cargo deny check                           # Security check
committed --staged                         # Check commit message

# Security checks
cargo deny check                           # Supply chain security
cargo audit                                # CVE scanning
cargo geiger                              # Check for unsafe code
cargo +nightly udeps                      # Find unused deps

# Maintenance
cargo outdated                            # Check for updates
cargo machete                             # Find unused dependencies
cargo msrv verify                         # Check MSRV

# Benchmarks
cargo bench                               # Run performance tests
cargo criterion                           # Better benchmarking
```

## Pre-Push Hook

Save this as `.git/hooks/pre-push` and make it executable:

```bash
#!/bin/bash
echo "🛡️ Running pre-push security checks..."

cargo fmt -- --check || { echo "❌ Format check failed"; exit 1; }
cargo clippy -- -D warnings || { echo "❌ Clippy check failed"; exit 1; }
cargo nextest run || { echo "❌ Tests failed"; exit 1; }
cargo deny check || { echo "❌ Dependency check failed"; exit 1; }

echo "✅ All checks passed!"
```

Thank you for helping make KindlyGuard better and more secure! 🛡️