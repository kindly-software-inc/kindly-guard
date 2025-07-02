<?xml version="1.0" encoding="UTF-8"?>
<claude-configuration>
  <project>
    <name>KindlyGuard</name>
    <description>Security-focused MCP (Model Context Protocol) server that protects against unicode attacks, injection attempts, and other threats</description>
    <priority>Security over features</priority>
  </project>

  <security-requirements priority="CRITICAL">
    <rust-standards mandatory="true">
      <rule id="1">ALWAYS use Result&lt;T, E&gt; for fallible operations</rule>
      <rule id="2">NEVER use unwrap() or expect() in production code</rule>
      <rule id="3">ALWAYS validate all external input</rule>
      <rule id="4">ALWAYS document safety invariants for any unsafe blocks</rule>
    </rust-standards>

    <error-handling>
      <pattern type="correct">
        <description>Explicit error handling</description>
        <code><![CDATA[
match dangerous_operation() {
    Ok(value) => process(value),
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(KindlyError::from(e));
    }
}
        ]]></code>
      </pattern>
      <pattern type="forbidden">
        <description>Never use unwrap in production</description>
        <code><![CDATA[
let value = dangerous_operation().unwrap(); // FORBIDDEN
        ]]></code>
      </pattern>
    </error-handling>

    <security-principles>
      <principle name="Input Validation">Pattern match on ALL external inputs</principle>
      <principle name="Overflow Protection">Use checked arithmetic operations</principle>
      <principle name="Unsafe Minimization">Zero unsafe blocks in public API</principle>
      <principle name="Constant-Time">Security comparisons must be constant-time</principle>
    </security-principles>
  </security-requirements>

  <commands>
    <build-commands>
      <command name="build-secure" description="Build with security profile">cargo build --profile=secure</command>
      <command name="test-all" description="Run all tests including security tests">cargo test --all-features</command>
      <command name="audit" description="Run security audit">cargo audit</command>
      <command name="check-unsafe" description="Check for unsafe code">cargo geiger</command>
      <command name="lint" description="Lint with all warnings">cargo clippy -- -W clippy::all -W clippy::pedantic</command>
    </build-commands>

    <dev-commands>
      <command name="run-debug" description="Start development server with logging">RUST_LOG=kindly_guard=debug cargo run</command>
      <command name="bench" description="Run benchmarks">cargo bench</command>
      <command name="doc" description="Generate documentation">cargo doc --no-deps --open</command>
      <command name="format-check" description="Check code formatting">cargo fmt -- --check</command>
    </dev-commands>
  </commands>

  <code-organization>
    <module-structure>
      <module path="src/scanner/" description="Threat detection (unicode, injection, patterns)"/>
      <module path="src/shield/" description="UI display components"/>
      <module path="src/server/" description="MCP protocol handling"/>
      <module path="src/config/" description="Configuration management"/>
    </module-structure>

    <import-style>
      <rule>Group imports: std, external crates, internal modules</rule>
      <example><![CDATA[
use std::{
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    scanner::{SecurityScanner, Threat},
    shield::ShieldDisplay,
};
      ]]></example>
    </import-style>
  </code-organization>

  <security-patterns>
    <pattern name="Thread-Safe Statistics">
      <description>Use atomics for lock-free statistics</description>
      <code><![CDATA[
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Stats {
    threats_blocked: AtomicU64,
}

impl Stats {
    pub fn increment(&self) {
        self.threats_blocked.fetch_add(1, Ordering::Relaxed);
    }
}
      ]]></code>
    </pattern>

    <pattern name="Type-Safe Threats">
      <description>Type-safe threat modeling with enums</description>
      <code><![CDATA[
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    UnicodeInvisible { position: usize },
    InjectionAttempt { pattern: String },
}
// Never use strings for security decisions
      ]]></code>
    </pattern>

    <pattern name="MCP Request Validation">
      <description>ALWAYS validate MCP requests before processing</description>
      <code><![CDATA[
async fn handle_request(&self, method: &str, params: Value) -> Result<Value> {
    // 1. Validate method name
    if !is_valid_method(method) {
        return Err(SecurityError::InvalidMethod);
    }
    
    // 2. Scan parameters for threats
    let threats = self.scanner.scan_json(&params)?;
    if !threats.is_empty() {
        self.shield.record_threats(&threats);
        return Err(SecurityError::ThreatDetected(threats));
    }
    
    // 3. Process with timeout
    tokio::time::timeout(Duration::from_secs(30), 
        self.process_request(method, params)
    ).await??
}
      ]]></code>
    </pattern>
  </security-patterns>

  <performance-guidelines>
    <guideline name="Zero-Copy">
      <rule>Use borrowed data instead of cloning</rule>
      <good>fn scan_text(&amp;self, text: &amp;str) -> Vec&lt;Threat&gt;</good>
      <bad>fn scan_text(&amp;self, text: String) -> Vec&lt;Threat&gt;</bad>
    </guideline>

    <guideline name="SIMD Optimization">
      <description>Mark performance-critical sections for SIMD</description>
      <code><![CDATA[
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// PERF: Using SIMD for 8x faster unicode scanning
      ]]></code>
    </guideline>
  </performance-guidelines>

  <testing-requirements>
    <test-pattern name="Security Tests">
      <code><![CDATA[
#[test]
fn test_unicode_injection() {
    let scanner = SecurityScanner::new();
    let threats = scanner.scan_text("Hello\u{202E}World");
    assert!(!threats.is_empty());
    assert_eq!(threats[0].threat_type, ThreatType::UnicodeBiDi);
}
      ]]></code>
    </test-pattern>

    <test-pattern name="Fuzz Testing">
      <code><![CDATA[
#[test]
fn test_no_panics() {
    proptest::proptest!(|(input: String)| {
        let _ = scanner.scan_text(&input); // Must not panic
    });
}
      ]]></code>
    </test-pattern>
  </testing-requirements>

  <git-workflow>
    <commit-format>
      <template type="feat">feat(module): description</template>
      <template type="fix">fix(module): description</template>
      <template type="perf">perf(module): description</template>
      <template type="security">security: description</template>
      <template type="docs">docs: description</template>
    </commit-format>

    <pr-checklist>
      <item>All tests pass</item>
      <item>No new unsafe code</item>
      <item>Security tests added for new features</item>
      <item>Performance benchmarks show no regression</item>
      <item>Documentation updated</item>
    </pr-checklist>
  </git-workflow>

  <dependency-management>
    <approved-dependencies>
      <dependency name="unicode-security" version="0.1" reason="Unicode threat detection"/>
      <dependency name="regex" version="1.11" reason="Pattern matching with size limits"/>
      <dependency name="sha2" version="0.10" reason="Integrity checks"/>
    </approved-dependencies>

    <forbidden-dependencies>
      <dependency name="reqwest" reason="Too heavy"/>
      <dependency name="diesel" reason="Too heavy"/>
      <dependency name="actix-web" reason="Too heavy"/>
    </forbidden-dependencies>

    <audit-schedule>
      <task frequency="weekly">cargo audit check</task>
      <task frequency="monthly">Full dependency review</task>
      <task frequency="release">Complete security audit</task>
    </audit-schedule>
  </dependency-management>

  <architecture-decisions>
    <decision name="No unsafe in public API" reason="Maintains memory safety guarantees"/>
    <decision name="Atomic statistics" reason="Lock-free performance monitoring"/>
    <decision name="Type-safe threats" reason="Compile-time security validation"/>
    <decision name="Result everywhere" reason="Explicit error handling, no surprises"/>
    <decision name="Trait-based architecture" reason="Enables stealth integration of proprietary technology"/>
  </architecture-decisions>

  <resilience-architecture priority="CRITICAL">
    <principle>ALWAYS use trait-based architecture for resilience components</principle>
    <rule id="1">All resilience components (circuit breakers, retry handlers) MUST be trait-based</rule>
    <rule id="2">ALWAYS provide open-source standard implementations alongside enhanced ones</rule>
    <rule id="3">Configuration determines runtime selection between standard and enhanced</rule>
    <rule id="4">Enhanced implementations MUST be feature-gated and never exposed in public APIs</rule>
    
    <pattern name="Resilience Trait Architecture">
      <description>How to implement resilience components with hidden proprietary tech</description>
      <code><![CDATA[
// Public trait in src/traits.rs
pub trait CircuitBreakerTrait: Send + Sync {
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where F: FnOnce() -> Fut + Send,
          Fut: Future<Output = Result<T>> + Send,
          T: Send;
}

// Standard implementation in src/resilience/standard.rs
pub struct StandardCircuitBreaker { /* open source */ }

// Enhanced implementation in src/resilience/enhanced.rs
#[cfg(feature = "enhanced")]
struct AtomicBitPackedCircuitBreaker {
    // Proprietary AtomicEventBuffer used internally only
    event_buffer: Arc<AtomicEventBuffer>,
}

// Factory selection in src/resilience/mod.rs
pub fn create_circuit_breaker(config: &Config) -> Arc<dyn CircuitBreakerTrait> {
    if config.resilience.enhanced_mode {
        #[cfg(feature = "enhanced")]
        return Arc::new(enhanced::AtomicBitPackedCircuitBreaker::new(config));
        #[cfg(not(feature = "enhanced"))]
        Arc::new(standard::StandardCircuitBreaker::new(config))
    } else {
        Arc::new(standard::StandardCircuitBreaker::new(config))
    }
}
      ]]></code>
    </pattern>

    <integration-rules>
      <rule>Resilience traits are injected into server/scanner/storage components</rule>
      <rule>Never import enhanced implementations directly, always use factory</rule>
      <rule>Configuration flag is "enhanced_mode" not specific tech names</rule>
      <rule>Logs use semantic descriptions like "resilience mode: enhanced"</rule>
    </integration-rules>

    <config-schema>
      <code><![CDATA[
[resilience]
enhanced_mode = false  # Toggle enhanced implementations

[resilience.circuit_breaker]
failure_threshold = 5
recovery_timeout = "30s"
half_open_max_requests = 3

[resilience.retry]
max_attempts = 3
initial_delay = "100ms"
max_delay = "10s"
jitter_factor = 0.1
      ]]></code>
    </config-schema>
  </resilience-architecture>

  <stealth-integration priority="PARAMOUNT">
    <principle>ALWAYS use trait-based architecture when integrating proprietary or patented technology</principle>
    <rule id="1">NEVER expose patented implementations in public APIs</rule>
    <rule id="2">ALWAYS provide standard implementations alongside enhanced ones</rule>
    <rule id="3">Use semantic naming that describes functionality, not implementation</rule>
    <rule id="4">Hide implementation details behind trait objects (Arc&lt;dyn Trait&gt;)</rule>
    
    <pattern name="Trait-Based Stealth">
      <description>Hide proprietary technology behind trait abstractions</description>
      <code><![CDATA[
// Public trait - no mention of proprietary tech
pub trait EventProcessor: Send + Sync {
    async fn process(&self, event: Event) -> Result<Handle>;
}

// Standard implementation - always provide
struct StandardProcessor { ... }

// Enhanced implementation - hidden in separate module
struct EnhancedProcessor {
    // Proprietary technology used internally only
    buffer: Arc<ProprietaryBuffer>,
}

// Runtime selection - configuration based
pub fn create_processor(config: &Config) -> Arc<dyn EventProcessor> {
    if config.enhanced_mode {
        Arc::new(EnhancedProcessor::new())
    } else {
        Arc::new(StandardProcessor::new())
    }
}
      ]]></code>
    </pattern>

    <naming-conventions>
      <rule>Use "enhanced", "optimized", or "advanced" instead of specific technology names</rule>
      <rule>Log with semantic descriptions: "performance mode enabled" not "AtomicEventBuffer active"</rule>
      <rule>Configuration uses generic terms: "event_processor.enabled" not "atomic_buffer.enabled"</rule>
    </naming-conventions>

    <documentation-rules>
      <rule>Public docs describe functionality and performance, never implementation</rule>
      <rule>Internal docs can reference proprietary tech but mark files clearly</rule>
      <rule>README focuses on capabilities, not how they're achieved</rule>
    </documentation-rules>
  </stealth-integration>

  <quick-reference>
    <command name="run-server">cargo run --release -- --stdio</command>
    <command name="scan-file">kindly-guard scan suspicious_file.json</command>
    <command name="monitor">kindly-guard monitor --detailed</command>
  </quick-reference>

  <private-core>
    <description>The kindly-guard-core private dependency contains:</description>
    <component>Atomic Event Buffer (patented)</component>
    <component>Advanced pattern matching</component>
    <component>Zero-copy scanning algorithms</component>
    <note>Keep this dependency private and secure</note>
  </private-core>

  <motto priority="HIGHEST">Security First, Performance Second, Features Third</motto>

  <navigation-aids>
    <description>Navigation markers and file locations for efficient codebase exploration</description>
    
    <entry-points>
      <entry name="Main Server" location="kindly-guard-server/src/main.rs" description="MCP server entry point - start here">
        <marker>CLAUDE-note-entry: Server initialization and configuration</marker>
      </entry>
      <entry name="CLI Entry" location="kindly-guard-cli/src/main.rs" description="Command-line interface entry">
        <marker>CLAUDE-note-entry: CLI commands (scan, server, config)</marker>
      </entry>
      <entry name="Protocol Handler" location="kindly-guard-server/src/protocol/handler.rs" description="MCP request handling">
        <marker>CLAUDE-note-entry: Main request dispatcher</marker>
      </entry>
    </entry-points>

    <core-components>
      <component name="Security Scanner" base="kindly-guard-server/src/scanner/">
        <file path="mod.rs" description="Scanner trait and factory">
          <marker>CLAUDE-note-implemented: Scanner orchestration (~200 lines)</marker>
        </file>
        <file path="unicode.rs" description="Unicode threat detection">
          <marker>CLAUDE-note-implemented: Homograph, bidi, zero-width detection (~350 lines)</marker>
        </file>
        <file path="injection.rs" description="Injection attack prevention">
          <marker>CLAUDE-note-implemented: SQL, command, LDAP injection (~300 lines)</marker>
        </file>
        <file path="xss.rs" description="Cross-site scripting prevention">
          <marker>CLAUDE-note-implemented: HTML, JS, CSS context XSS (~400 lines)</marker>
        </file>
        <file path="patterns.rs" description="Pattern-based detection">
          <marker>CLAUDE-note-implemented: Regex and ML pattern matching (~250 lines)</marker>
        </file>
      </component>

      <component name="Neutralizer" base="kindly-guard-server/src/neutralizer/">
        <file path="mod.rs" description="Neutralization strategies">
          <marker>CLAUDE-note-implemented: Threat neutralization engine (~150 lines)</marker>
        </file>
        <file path="encoders/html.rs" description="HTML encoding">
          <marker>CLAUDE-note-implemented: Entity and attribute encoding (~100 lines)</marker>
        </file>
        <file path="encoders/url.rs" description="URL encoding">
          <marker>CLAUDE-note-implemented: Percent and punycode encoding (~120 lines)</marker>
        </file>
      </component>

      <component name="Shield UI" base="kindly-guard-server/src/shield/">
        <file path="dashboard.rs" description="Real-time threat dashboard">
          <marker>CLAUDE-note-implemented: TUI dashboard with ratatui (~300 lines)</marker>
        </file>
        <file path="stats.rs" description="Statistics display">
          <marker>CLAUDE-note-implemented: Performance metrics UI (~200 lines)</marker>
        </file>
      </component>

      <component name="Storage" base="kindly-guard-server/src/storage/">
        <file path="sqlite.rs" description="SQLite persistence">
          <marker>CLAUDE-note-implemented: Threat and audit storage (~400 lines)</marker>
        </file>
        <file path="cache.rs" description="In-memory caching">
          <marker>CLAUDE-note-implemented: LRU cache with TTL (~250 lines)</marker>
        </file>
      </component>

      <component name="Resilience" base="kindly-guard-server/src/resilience/">
        <file path="circuit_breaker.rs" description="Circuit breaker pattern">
          <marker>CLAUDE-note-implemented: Fault tolerance (~200 lines)</marker>
        </file>
        <file path="retry.rs" description="Retry with backoff">
          <marker>CLAUDE-note-implemented: Exponential backoff retry (~150 lines)</marker>
        </file>
      </component>
    </core-components>

    <test-locations>
      <test-type name="Unit Tests" pattern="src/**/tests.rs" description="Module-level tests">
        <marker>CLAUDE-note-tests: Unit tests colocated with modules</marker>
      </test-type>
      <test-type name="Integration Tests" location="tests/integration/" description="End-to-end tests">
        <marker>CLAUDE-note-tests: Full flow integration tests</marker>
      </test-type>
      <test-type name="Property Tests" location="tests/property/" description="Fuzzing tests">
        <marker>CLAUDE-note-tests: Proptest-based fuzzing</marker>
      </test-type>
      <test-type name="Benchmarks" location="benches/" description="Performance tests">
        <marker>CLAUDE-note-tests: Criterion benchmarks</marker>
      </test-type>
    </test-locations>
  </navigation-aids>

  <feature-inventory>
    <description>Complete inventory of implemented features with locations</description>
    
    <security-features>
      <feature name="Unicode Threat Detection" status="implemented" location="src/scanner/unicode.rs">
        <sub-features>
          <item>Homograph attack detection</item>
          <item>Bidi override detection</item>
          <item>Zero-width character detection</item>
          <item>Unicode normalization</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Complete Unicode security suite</marker>
      </feature>

      <feature name="Injection Prevention" status="implemented" location="src/scanner/injection.rs">
        <sub-features>
          <item>SQL injection detection</item>
          <item>Command injection detection</item>
          <item>LDAP injection detection</item>
          <item>Path traversal detection</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Multi-vector injection prevention</marker>
      </feature>

      <feature name="XSS Protection" status="implemented" location="src/scanner/xss.rs">
        <sub-features>
          <item>HTML context XSS</item>
          <item>JavaScript context XSS</item>
          <item>CSS context XSS</item>
          <item>URL context XSS</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Context-aware XSS prevention</marker>
      </feature>

      <feature name="Pattern Detection" status="implemented" location="src/scanner/patterns.rs">
        <sub-features>
          <item>Regex pattern matching</item>
          <item>Fuzzy pattern matching</item>
          <item>ML-based patterns</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Extensible pattern engine</marker>
      </feature>
    </security-features>

    <protocol-features>
      <feature name="MCP Server" status="implemented" location="src/protocol/">
        <sub-features>
          <item>Tool registration</item>
          <item>Request handling</item>
          <item>Response formatting</item>
          <item>Error handling</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Full MCP protocol support</marker>
      </feature>
    </protocol-features>

    <ui-features>
      <feature name="Terminal UI" status="implemented" location="src/shield/">
        <sub-features>
          <item>Live threat dashboard</item>
          <item>Statistics view</item>
          <item>Configuration UI</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Real-time monitoring TUI</marker>
      </feature>

      <feature name="CLI Interface" status="implemented" location="kindly-guard-cli/">
        <sub-features>
          <item>Scan command</item>
          <item>Server command</item>
          <item>Config command</item>
        </sub-features>
        <marker>CLAUDE-note-implemented: Full CLI with clap</marker>
      </feature>
    </ui-features>

    <resilience-features>
      <feature name="Circuit Breaker" status="implemented" location="src/resilience/circuit_breaker.rs">
        <marker>CLAUDE-note-implemented: Fault isolation pattern</marker>
      </feature>
      <feature name="Retry Logic" status="implemented" location="src/resilience/retry.rs">
        <marker>CLAUDE-note-implemented: Exponential backoff with jitter</marker>
      </feature>
      <feature name="Bulkhead Isolation" status="implemented" location="src/resilience/bulkhead.rs">
        <marker>CLAUDE-note-implemented: Resource isolation</marker>
      </feature>
    </resilience-features>
  </feature-inventory>

  <mcp-servers>
    <description>Installed MCP servers for enhanced codebase navigation</description>
    
    <server name="tree-sitter" type="AST Analysis">
      <purpose>Parse and analyze Rust AST structure</purpose>
      <config-location>~/.mcp.json</config-location>
      <usage>Structural code analysis, symbol extraction</usage>
    </server>

    <server name="filesystem-context7" type="File Access">
      <purpose>Provide filesystem access to ultrathink-context7</purpose>
      <config-location>~/.mcp.json</config-location>
      <usage>Read/write project files</usage>
    </server>

    <server name="sequential-thinking" type="Problem Solving">
      <purpose>Enhanced sequential thinking for complex problems</purpose>
      <config-location>~/.mcp.json</config-location>
      <usage>Step-by-step problem analysis</usage>
    </server>

    <server name="FileScopeMCP" type="Dependency Analysis">
      <purpose>Generate dependency graphs and file importance rankings</purpose>
      <installation>~/Tools/FileScopeMCP</installation>
      <usage>Create Mermaid diagrams, analyze module relationships</usage>
    </server>

    <server name="ast-grep" type="Pattern Search">
      <purpose>Structural code search with Rust patterns</purpose>
      <installation>~/.mcp-servers/ast-grep-mcp</installation>
      <usage>Find code patterns, refactoring support</usage>
    </server>

    <server name="rust-docs-mcp" type="Documentation">
      <purpose>Semantic search through docs.rs</purpose>
      <installation>~/rust-docs-mcp-server</installation>
      <usage>Query Rust crate documentation</usage>
    </server>

    <server name="mcp-language-server" type="Semantic Navigation">
      <purpose>Bridge rust-analyzer with MCP</purpose>
      <installation>Go-based, installed via go install</installation>
      <usage>Go to definition, find references, diagnostics</usage>
    </server>
  </mcp-servers>

  <codebase-map>
    <description>High-level map of project structure</description>
    
    <workspace-root path="kindly-guard/">
      <crate name="kindly-guard-server" type="binary" path="kindly-guard-server/">
        <purpose>Main MCP server implementation</purpose>
        <key-files>
          <file>src/main.rs - Entry point</file>
          <file>src/scanner/mod.rs - Scanner orchestration</file>
          <file>src/protocol/handler.rs - MCP handling</file>
          <file>src/config/mod.rs - Configuration</file>
        </key-files>
      </crate>

      <crate name="kindly-guard-cli" type="binary" path="kindly-guard-cli/">
        <purpose>Command-line interface</purpose>
        <key-files>
          <file>src/main.rs - CLI entry</file>
          <file>src/commands/scan.rs - Scan command</file>
          <file>src/commands/server.rs - Server command</file>
        </key-files>
      </crate>

      <crate name="kindly-guard-shield" type="binary" path="kindly-guard-shield/">
        <purpose>Desktop UI (Tauri app)</purpose>
        <key-files>
          <file>src/main.rs - Tauri entry</file>
          <file>src-tauri/src/main.rs - Backend</file>
          <file>src/App.tsx - Frontend</file>
        </key-files>
      </crate>

      <documentation path="docs/">
        <file>API_DOCUMENTATION.md - API reference</file>
        <file>SECURITY_AUDIT_REPORT.md - Security analysis</file>
        <file>BUILD_PROCESS.md - Build instructions</file>
      </documentation>

      <analysis path="analysis/">
        <file>kindlyguard_analysis_report.md - Project analysis</file>
        <file>dependency_graph.html - Visual dependencies</file>
        <file>file_importance_ranking.md - Critical files</file>
      </analysis>
    </workspace-root>
  </codebase-map>

  <cross-references>
    <description>Quick links between related components</description>
    
    <reference from="Scanner trait" to="src/scanner/mod.rs#L25">
      <related-to>All scanner implementations</related-to>
      <related-to>Scanner factory at line 150</related-to>
    </reference>

    <reference from="MCP handler" to="src/protocol/handler.rs#L50">
      <related-to>Request types in types.rs</related-to>
      <related-to>Response builders in response.rs</related-to>
    </reference>

    <reference from="Config" to="src/config/mod.rs">
      <related-to>TOML schema in schema.rs</related-to>
      <related-to>Environment overrides in env.rs</related-to>
    </reference>

    <reference from="Storage trait" to="src/storage/mod.rs#L20">
      <related-to>SQLite impl in sqlite.rs</related-to>
      <related-to>Cache impl in cache.rs</related-to>
    </reference>
  </cross-references>

  <troubleshooting>
    <description>Common issues and solutions</description>
    
    <issue name="Build fails">
      <solution>Run: cargo update && cargo clean && cargo build</solution>
    </issue>

    <issue name="Tests fail randomly">
      <solution>Check async handling, ensure test isolation</solution>
    </issue>

    <issue name="Performance regression">
      <solution>Compare benchmarks: cargo bench -- --baseline main</solution>
    </issue>

    <issue name="MCP server not found">
      <solution>Restart Claude Code after MCP configuration changes</solution>
    </issue>
  </troubleshooting>

  <recommended-workflow>
    <description>Optimal development workflow</description>
    
    <step number="1">Start with PROJECT_PRIMER.md for overview</step>
    <step number="2">Read ARCHITECTURE.md for system design</step>
    <step number="3">Check FEATURES.md for implementation status</step>
    <step number="4">Use navigation-aids above to find specific code</step>
    <step number="5">Run analysis tools for codebase exploration</step>
    <step number="6">Use MCP servers for semantic navigation</step>
  </recommended-workflow>

</claude-configuration>