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
</claude-configuration>