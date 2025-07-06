# KindlyGuard Project Structure

## Overview

KindlyGuard is a security-focused MCP (Model Context Protocol) server organized as a Rust workspace with multiple crates. The project contains **231 Rust source files**, **15 TOML configurations**, and **123 documentation files**.

## Workspace Structure

```
kindly-guard/                              # Root workspace directory
├── Cargo.toml                            # Workspace manifest (defines member crates)
├── Cargo.lock                            # Dependency lock file
├── LICENSE                               # MIT License
├── README.md                             # Project overview
├── CLAUDE.md                             # Claude AI instructions & configuration
├── ARCHITECTURE.md                       # System architecture documentation
├── FEATURES.md                           # Feature inventory
├── ROADMAP.md                            # Development roadmap
├── TESTING.md                            # Testing guide
└── PROJECT_PRIMER.md                     # Quick start guide
```

## Core Crates (Workspace Members)

### 🛡️ kindly-guard-server/ (Main MCP Server)
The heart of KindlyGuard - implements the MCP protocol with security scanning.

```
kindly-guard-server/
├── Cargo.toml                            # Package manifest
├── src/
│   ├── main.rs                          # Server entry point (binary)
│   ├── lib.rs                           # Library root (public API)
│   ├── server.rs                        # MCP server implementation
│   ├── daemon.rs                        # Background daemon mode
│   ├── traits.rs                        # Core trait definitions
│   ├── config.rs                        # Configuration management
│   ├── signing.rs                       # Request signing/verification
│   ├── auth.rs                          # Authentication handling
│   ├── rate_limit.rs                    # Rate limiting
│   ├── logging.rs                       # Structured logging setup
│   ├── versioning.rs                    # API versioning
│   ├── event_processor.rs               # Event handling
│   ├── component_selector.rs            # Dynamic component selection
│   ├── standard_impl.rs                 # Standard implementations
│   ├── enhanced_impl.rs                 # Enhanced implementations (feature-gated)
│   │
│   ├── scanner/                         # 🔍 Threat Detection Engine
│   │   ├── mod.rs                       # Scanner trait & orchestration
│   │   ├── unicode.rs                   # Unicode attack detection
│   │   ├── injection.rs                 # SQL/Command injection detection
│   │   ├── xss_scanner.rs               # Cross-site scripting detection
│   │   ├── patterns.rs                  # Pattern-based detection
│   │   └── sync_wrapper.rs              # Sync wrapper for async scanners
│   │
│   ├── neutralizer/                     # 🧹 Threat Neutralization
│   │   ├── mod.rs                       # Neutralizer trait & factory
│   │   ├── standard.rs                  # Basic neutralization
│   │   ├── enhanced.rs                  # Advanced neutralization
│   │   ├── validation.rs                # Input validation
│   │   ├── security_aware.rs            # Context-aware neutralization
│   │   ├── rate_limited.rs              # Rate-limited neutralization
│   │   ├── traced.rs                    # Traced neutralization
│   │   ├── rollback.rs                  # Rollback support
│   │   ├── recovery.rs                  # Error recovery
│   │   ├── health.rs                    # Health monitoring
│   │   └── api.rs                       # Public API
│   │
│   ├── shield/                          # 🎨 UI Components
│   │   ├── mod.rs                       # Shield trait definitions
│   │   ├── display.rs                   # Terminal UI display
│   │   ├── cli.rs                       # CLI shield implementation
│   │   └── universal_display.rs         # Cross-platform display
│   │
│   ├── transport/                       # 🔌 Protocol Transports
│   │   ├── mod.rs                       # Transport trait
│   │   ├── stdio.rs                     # Standard I/O transport (MCP)
│   │   ├── http.rs                      # HTTP transport
│   │   ├── websocket.rs                 # WebSocket transport
│   │   ├── claude_code.rs               # Claude Code specific
│   │   └── proxy.rs                     # Proxy support
│   │
│   ├── protocol/                        # 📡 MCP Protocol (Private)
│   │   ├── mod.rs                       # Protocol handling
│   │   ├── handler.rs                   # Request handler
│   │   ├── types.rs                     # Protocol types
│   │   └── errors.rs                    # Protocol errors
│   │
│   ├── storage/                         # 💾 Data Persistence
│   │   ├── mod.rs                       # Storage trait
│   │   ├── memory.rs                    # In-memory storage
│   │   └── enhanced.rs                  # Enhanced storage
│   │
│   ├── resilience/                      # 🔄 Fault Tolerance
│   │   ├── mod.rs                       # Resilience traits
│   │   ├── circuit_breaker.rs           # Circuit breaker pattern
│   │   ├── retry.rs                     # Retry with backoff
│   │   ├── standard.rs                  # Standard implementations
│   │   ├── enhanced.rs                  # Enhanced implementations
│   │   └── config.rs                    # Resilience configuration
│   │
│   ├── security/                        # 🔐 Security Hardening
│   │   ├── mod.rs                       # Security utilities
│   │   ├── boundaries.rs                # Security boundaries
│   │   └── hardening.rs                 # System hardening
│   │
│   ├── telemetry/                       # 📊 Observability
│   │   ├── mod.rs                       # Telemetry traits
│   │   ├── metrics.rs                   # Metrics collection
│   │   ├── distributed.rs               # Distributed tracing
│   │   ├── standard.rs                  # Standard telemetry
│   │   └── enhanced.rs                  # Enhanced telemetry
│   │
│   ├── audit/                           # 📝 Audit Logging
│   │   ├── mod.rs                       # Audit traits
│   │   ├── file.rs                      # File-based audit
│   │   ├── memory.rs                    # In-memory audit
│   │   ├── enhanced.rs                  # Enhanced audit
│   │   └── neutralization.rs            # Neutralization audit
│   │
│   ├── permissions/                     # 🔑 Access Control
│   │   ├── mod.rs                       # Permission system
│   │   ├── standard.rs                  # Basic permissions
│   │   └── enhanced.rs                  # Advanced permissions
│   │
│   ├── plugins/                         # 🔌 Plugin System
│   │   ├── mod.rs                       # Plugin traits
│   │   ├── manager.rs                   # Plugin manager
│   │   ├── native.rs                    # Native plugins
│   │   └── wasm.rs                      # WASM plugins
│   │
│   ├── web/                             # 🌐 Web Interface
│   │   ├── mod.rs                       # Web server
│   │   ├── dashboard.rs                 # Web dashboard
│   │   └── metrics.rs                   # Metrics endpoint
│   │
│   ├── cli/                             # 💻 CLI Commands
│   │   ├── mod.rs                       # CLI module
│   │   ├── commands.rs                  # Command implementations
│   │   └── validation.rs                # Input validation
│   │
│   ├── metrics/                         # 📈 Metrics System
│   │   ├── mod.rs                       # Metrics traits
│   │   ├── standard.rs                  # Standard metrics
│   │   └── enhanced_interface.rs        # Enhanced metrics
│   │
│   ├── config/                          # ⚙️ Configuration
│   │   ├── reload.rs                    # Hot reload support
│   │   └── SECURITY_CONFIG_GUIDE.md     # Configuration guide
│   │
│   └── error/                           # ❌ Error Handling
│       └── mod.rs                       # Error types
│
├── benches/                             # Performance benchmarks
│   ├── critical_path_benchmarks.rs
│   ├── regression_benchmarks.rs
│   ├── simple_benchmark.rs
│   ├── neutralization.rs
│   ├── display_bench.rs
│   ├── memory_profile_bench.rs
│   └── cli_bench.rs
│
├── tests/                               # Integration tests
│   ├── integration_test.rs
│   ├── security_tests.rs
│   ├── property_tests.rs
│   ├── mcp_protocol_tests.rs
│   ├── multi_protocol_security_tests.rs
│   └── common/                          # Test utilities
│
├── examples/                            # Usage examples
│   ├── performance_test.rs
│   ├── realistic_performance_test.rs
│   └── neutralizer_tracing.rs
│
├── templates/                           # HTML templates
│   └── dashboard.html
│
└── assets/                              # Static assets
    ├── css/
    ├── js/
    ├── icons/
    └── svg/
```

### 🖥️ kindly-guard-cli/ (Command Line Interface)
User-friendly CLI wrapper around the server functionality.

```
kindly-guard-cli/
├── Cargo.toml
├── src/
│   ├── main.rs                          # CLI entry point
│   └── output.rs                        # Output formatting
└── tests/
    ├── cli_wrapper_security_tests.rs
    └── simple_wrapper_test.rs
```

### 🛡️ kindly-guard-shield/ (Desktop UI)
Tauri-based desktop application for visual security monitoring.

```
kindly-guard-shield/
├── Cargo.toml
├── package.json                         # Node.js dependencies
├── tsconfig.json                        # TypeScript config
├── vite.config.ts                       # Vite bundler config
├── index.html                           # Web entry point
├── src/                                 # Rust library code
│   └── lib.rs
├── src-tauri/                           # Tauri backend
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── src/
│   │   └── main.rs
│   └── icons/
└── src/                                 # Frontend code
    ├── main.ts
    ├── App.tsx
    └── styles/
```

### 📦 crates-io-package/kindlyguard/
Published crate for crates.io distribution.

```
crates-io-package/kindlyguard/
├── Cargo.toml
└── src/
    └── lib.rs                           # Re-exports from main crate
```

## Supporting Directories

### 📊 analysis/ (Codebase Analysis)
Generated analysis and visualization files.

```
analysis/
├── kindlyguard_analysis_report.md       # Comprehensive analysis
├── dependency_graph.html                # Interactive dependency graph
├── file_importance_ranking.md           # Critical file ranking
├── critical_paths.mermaid               # Critical path diagrams
└── module_structure.html                # Module visualization
```

### 📚 docs/ (Documentation)
Comprehensive project documentation.

```
docs/
├── architecture/                        # Architecture decisions
├── development/                         # Development guides
├── features/                           # Feature documentation
├── guides/                             # User guides
└── archive/                            # Historical docs
```

### 🧪 Testing Infrastructure

```
kindly-guard-server/tests/
├── attack_patterns/                     # Attack test patterns
├── security/                           # Security-specific tests
│   ├── auth/
│   ├── neutralizer/
│   └── scanner/
├── common/                             # Shared test utilities
├── helpers/                            # Test helpers
└── snapshots/                          # Test snapshots
```

### 🚀 npm-package/ (NPM Distribution)
Node.js package for easy installation.

```
npm-package/
├── package.json
├── bin/                                # Binary wrappers
├── lib/                                # JavaScript interface
├── scripts/                            # Installation scripts
└── npm/                                # Platform-specific binaries
    ├── kindlyguard-darwin-arm64/
    ├── kindlyguard-darwin-x64/
    ├── kindlyguard-linux-x64/
    └── kindlyguard-win32-x64/
```

### 🔧 Scripts and Tools

```
scripts/
├── run-all-tests.sh                    # Run complete test suite
├── run-unit-tests.sh                   # Unit tests only
├── run-integration-tests.sh            # Integration tests
├── run-comprehensive-benchmarks.sh     # Full benchmark suite
└── analyze-benchmarks.py               # Benchmark analysis
```

### 🎯 Demo and Examples

```
demo/
└── threats/                            # Example threat payloads
```

## File Statistics

| File Type | Count | Primary Locations |
|-----------|-------|-------------------|
| Rust source (*.rs) | 231 | `src/`, `tests/`, `benches/` |
| TOML configs | 15 | `Cargo.toml` files |
| Markdown docs | 123 | `docs/`, root, `*.md` |
| TypeScript/JavaScript | ~20 | `kindly-guard-shield/`, `npm-package/` |
| Shell scripts | 6 | Root directory |
| HTML/CSS | ~15 | `assets/`, `templates/` |

## Public vs Internal APIs

### Public API Surface
- `kindly-guard-server/src/lib.rs` - Main library exports
- `kindly-guard-server/src/traits.rs` - Public trait definitions
- `kindly-guard-server/src/scanner/mod.rs` - Scanner traits
- `kindly-guard-server/src/neutralizer/api.rs` - Neutralizer public API
- `kindly-guard-cli/src/main.rs` - CLI interface

### Internal Implementation
- `src/enhanced_impl/` - Enhanced implementations (feature-gated)
- `src/protocol/` - MCP protocol internals
- `src/resilience/enhanced.rs` - Proprietary resilience features
- `kindly-guard-core/` - Private core dependency (not in workspace)

## Key Integration Points

1. **MCP Protocol**: `src/transport/stdio.rs` - Standard MCP communication
2. **Security Scanning**: `src/scanner/` - Pluggable scanner implementations
3. **UI Integration**: `src/shield/` - Multiple UI backends
4. **Configuration**: `src/config.rs` - TOML-based configuration
5. **Plugin System**: `src/plugins/` - Native and WASM plugins

## Development Workflow

1. **Entry Points**:
   - Server: `kindly-guard-server/src/main.rs`
   - CLI: `kindly-guard-cli/src/main.rs`
   - Desktop: `kindly-guard-shield/src-tauri/src/main.rs`

2. **Core Logic**:
   - Scanner implementations in `src/scanner/`
   - Neutralization in `src/neutralizer/`
   - Transport handling in `src/transport/`

3. **Testing**:
   - Unit tests alongside source files
   - Integration tests in `tests/`
   - Benchmarks in `benches/`

4. **Documentation**:
   - API docs in source code
   - Architecture in `docs/`
   - Examples in `examples/`

## Build Artifacts

```
target/                                 # Cargo build directory
├── debug/                             # Debug builds
├── release/                           # Release builds
├── secure/                            # Security-hardened builds
└── criterion/                         # Benchmark results
```

## Configuration Files

- `Cargo.toml` - Rust package manifests
- `.github/` - GitHub Actions workflows
- `package.json` - Node.js packages
- `tauri.conf.json` - Tauri configuration
- Various `.toml` test configurations

---

This structure supports KindlyGuard's security-first architecture with clear separation between public APIs, internal implementations, and supporting infrastructure.