# KindlyGuard Fuzzing Infrastructure

This directory contains fuzzing targets for security testing KindlyGuard components.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

Note: Fuzzing requires the nightly Rust toolchain.

## Available Fuzz Targets

1. **fuzz_unicode_scanner** - Tests Unicode threat detection with malformed UTF-8 and edge cases
2. **fuzz_injection_detector** - Tests injection detection with nested payloads and polyglots
3. **fuzz_mcp_protocol** - Tests MCP protocol handling with malformed JSON-RPC
4. **fuzz_event_buffer** - Tests concurrent access patterns on the Atomic Event Buffer

## Running Fuzz Tests

Use the provided script for easier management:

```bash
# List all targets
./scripts/fuzz.sh list

# Run a specific target for 1 hour
./scripts/fuzz.sh run fuzz_unicode_scanner

# Run a specific target for custom duration
./scripts/fuzz.sh run fuzz_unicode_scanner -t 7200  # 2 hours

# Run all targets with 30 minutes each
./scripts/fuzz.sh run-all -t 1800

# Show corpus information
./scripts/fuzz.sh corpus fuzz_unicode_scanner

# Clean all fuzzing artifacts
./scripts/fuzz.sh clean
```

## Manual Fuzzing

If you prefer to run cargo-fuzz directly:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_unicode_scanner -- -max_total_time=3600
```

## Reproducing Crashes

If fuzzing finds a crash, it will be saved in `fuzz/artifacts/<target_name>/`. To reproduce:

```bash
cd fuzz
cargo +nightly fuzz run <target_name> artifacts/<target_name>/<crash_file>
```

## Corpus Management

Fuzz test corpuses are stored in `fuzz/corpus/<target_name>/`. These contain interesting inputs that increase code coverage. You should commit particularly interesting corpus files to help future fuzzing sessions.

## Security Testing Strategy

Our fuzzing targets test:

1. **Input Validation** - Malformed UTF-8, extreme Unicode edge cases
2. **Parser Robustness** - Deeply nested JSON, malformed protocols
3. **Concurrency Safety** - Race conditions, concurrent access patterns
4. **Memory Safety** - Buffer overflows, out-of-bounds access
5. **DoS Prevention** - Resource exhaustion, algorithmic complexity

## CI Integration

Fuzzing runs automatically in CI with short smoke tests (60 seconds per target). For thorough testing, run locally with longer durations:

```bash
# Recommended for thorough testing before release
./scripts/fuzz.sh run-all -t 3600  # 1 hour per target
```

## Adding New Fuzz Targets

1. Create a new file in `fuzz_targets/`
2. Add the binary to `fuzz/Cargo.toml`
3. Follow the pattern of existing targets
4. Test with a short run

Example:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Your fuzzing logic here
});
```