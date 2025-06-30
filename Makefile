.PHONY: test test-fast test-coverage test-security bench lint fmt clean help

# Default target
.DEFAULT_GOAL := help

## help: Show this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## test: Run all tests with cargo nextest
test:
	@echo "🧪 Running all tests..."
	@./scripts/test-nextest.sh

## test-fast: Run tests without enhanced features (faster)
test-fast:
	@echo "⚡ Running tests (fast mode)..."
	@cargo nextest run --workspace --exclude private-deps

## test-coverage: Run tests with coverage reporting
test-coverage:
	@echo "📊 Running tests with coverage..."
	@./scripts/coverage.sh

## test-security: Run security-focused tests
test-security:
	@echo "🔒 Running security tests..."
	@cargo nextest run --workspace --profile security test_security test_unicode test_injection

## test-property: Run property-based tests
test-property:
	@echo "🎲 Running property tests..."
	@cargo test --test property_tests -- --nocapture

## test-mock: Run mock-based tests
test-mock:
	@echo "🎭 Running mock tests..."
	@cargo nextest run mock_tests mock_auth_tests

## bench: Run benchmarks
bench:
	@echo "📈 Running benchmarks..."
	@cargo bench --all-features

## lint: Run clippy linter
lint:
	@echo "🔍 Running clippy..."
	@cargo clippy --all-features --all-targets -- -D warnings

## fmt: Format code
fmt:
	@echo "✨ Formatting code..."
	@cargo fmt --all

## fmt-check: Check code formatting
fmt-check:
	@echo "🔍 Checking formatting..."
	@cargo fmt --all -- --check

## clean: Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	@cargo clean
	@rm -rf coverage/ lcov.info target/nextest

## audit: Run security audit
audit:
	@echo "🔐 Running security audit..."
	@cargo audit

## doc: Generate documentation
doc:
	@echo "📚 Generating documentation..."
	@cargo doc --all-features --no-deps --open

## install: Install the project
install:
	@echo "📦 Installing..."
	@cargo install --path kindly-guard-server
	@cargo install --path kindly-guard-cli

## dev: Run development server with logging
dev:
	@echo "🚀 Starting development server..."
	@RUST_LOG=kindly_guard=debug cargo run -- --stdio --shield