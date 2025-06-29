# Contributing to KindlyGuard

Thank you for your interest in contributing to KindlyGuard! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Environment details (OS, Rust version, etc.)
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- A clear and descriptive title
- Detailed description of the proposed enhancement
- Rationale for why this would be useful
- Examples of how it would be used
- Any potential drawbacks or considerations

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run linting (`cargo clippy -- -D warnings`)
6. Format code (`cargo fmt`)
7. Commit your changes (see commit guidelines below)
8. Push to your branch
9. Open a Pull Request

## Development Setup

### Prerequisites

- Rust 1.75.0 or later
- Git
- cargo-nextest (optional, for faster tests): `cargo install cargo-nextest`
- cargo-llvm-cov (optional, for coverage): `cargo install cargo-llvm-cov`

### Building

```bash
git clone https://github.com/yourusername/kindly-guard.git
cd kindly-guard
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with nextest (faster)
cargo nextest run

# Run with coverage
cargo llvm-cov test

# Run specific test category
cargo test --test security_tests
```

### Running Benchmarks

```bash
cargo bench
```

## Coding Standards

### Rust Guidelines

- Follow standard Rust naming conventions
- Use `rustfmt` for formatting
- Address all `clippy` warnings
- Write documentation for public APIs
- Add tests for new functionality
- Maintain backwards compatibility

### Security Requirements

KindlyGuard is a security-focused project. All contributions must:

- **Never use `unwrap()` or `expect()` in production code**
- Always validate external input
- Use `Result<T, E>` for fallible operations
- Document any security considerations
- Add security tests for security-related changes
- Never expose sensitive information in logs or errors

### Performance Considerations

- Avoid unnecessary allocations
- Use borrowing instead of cloning when possible
- Consider using `Arc` for shared immutable data
- Profile performance-critical code
- Add benchmarks for performance-sensitive changes

## Testing Requirements

### Test Coverage

- Minimum 70% code coverage required
- Security-critical code should have 90%+ coverage
- Add tests for all new functionality
- Include both positive and negative test cases

### Test Categories

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test component interactions
3. **Security Tests**: Test threat detection and prevention
4. **Property Tests**: Use proptest for edge cases
5. **Fuzz Tests**: Add fuzz targets for parsing code

### Writing Tests

```rust
#[test]
fn test_descriptive_name() {
    // Arrange
    let input = create_test_input();
    
    // Act
    let result = function_under_test(input);
    
    // Assert
    assert_eq!(result, expected_value);
}
```

## Commit Guidelines

### Commit Message Format

Follow the conventional commits format:

```
type(scope): description

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/changes
- `chore`: Build process or auxiliary tool changes
- `security`: Security improvements

Examples:
```
feat(scanner): add support for detecting homoglyph attacks
fix(auth): properly validate JWT signature
docs: update API documentation for v1.1
security: implement constant-time token comparison
```

### Commit Best Practices

- Keep commits atomic and focused
- Write clear, descriptive commit messages
- Reference issues in commit messages when applicable
- Sign your commits with GPG when possible

## Pull Request Process

1. **Before Submitting**
   - Ensure all tests pass
   - Update documentation as needed
   - Add entries to CHANGELOG.md
   - Verify no security vulnerabilities

2. **PR Description**
   - Clearly describe what changes were made
   - Explain why the changes are necessary
   - Note any breaking changes
   - Include screenshots for UI changes

3. **Review Process**
   - PRs require at least one review
   - Address all feedback constructively
   - Keep PRs focused and reasonably sized
   - Be patient and respectful

## Documentation

### Code Documentation

- Document all public APIs
- Include examples in documentation
- Explain complex algorithms
- Document security considerations

### README Updates

Update the README when:
- Adding new features
- Changing installation process
- Modifying configuration options
- Adding new dependencies

## Release Process

1. Update version in Cargo.toml files
2. Update CHANGELOG.md
3. Create release PR
4. After merge, tag the release
5. GitHub Actions will build and publish

## Getting Help

- Check the [documentation](docs/)
- Search existing issues
- Ask in discussions
- Contact maintainers

## Recognition

Contributors will be recognized in:
- The CHANGELOG.md file
- The project README
- Release notes

Thank you for contributing to KindlyGuard! Your efforts help make MCP communications more secure for everyone.