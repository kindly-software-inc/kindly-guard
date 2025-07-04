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

- **Rust toolchain** (1.75 or newer)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
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

- **rust-analyzer** - IDE support for VS Code, Vim, Emacs
- **cargo-watch** - Auto-rebuild on file changes
  ```bash
  cargo install cargo-watch
  cargo watch -x test -x run
  ```
- **cargo-audit** - Security vulnerability scanner
  ```bash
  cargo install cargo-audit
  ```

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

```bash
# Run all tests
cargo test

# Run tests with all features
cargo test --all-features

# Run a specific test
cargo test test_unicode_injection

# Run tests with output
cargo test -- --nocapture

# Run property tests (fuzzing)
cargo test --test property_tests
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

We follow conventional commits for clear history:

- `feat(module): add new feature` - New features
- `fix(module): fix bug description` - Bug fixes
- `perf(module): improve performance` - Performance improvements
- `security: fix vulnerability` - Security fixes
- `docs: update documentation` - Documentation only
- `test: add test coverage` - Test additions
- `refactor(module): refactor code` - Code refactoring
- `chore: update dependencies` - Maintenance tasks

**Example commit:**
```bash
git commit -m "feat(scanner): add LDAP injection detection

- Implement LDAP query validation
- Add comprehensive test coverage
- Update documentation"
```

### Pull Request Process

1. **Before submitting:**
   - [ ] Run `cargo fmt`
   - [ ] Run `cargo clippy -- -W clippy::all`
   - [ ] Run `cargo test --all-features`
   - [ ] Run `cargo audit`
   - [ ] Update documentation if needed
   - [ ] Add tests for new functionality

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

# Development
cargo fmt                                    # Format code
cargo clippy -- -W clippy::all              # Lint code
cargo test --all-features                   # Run tests
RUST_LOG=kindly_guard=debug cargo run      # Run with debug logs

# Security checks
cargo audit                                 # Check dependencies
cargo geiger                               # Check for unsafe code

# Benchmarks
cargo bench                                # Run performance tests
```

Thank you for helping make KindlyGuard better and more secure! 🛡️