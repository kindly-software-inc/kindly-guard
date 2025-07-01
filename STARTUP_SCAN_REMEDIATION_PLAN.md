# Comprehensive Plan: Startup Scan & Threat Remediation

## Part 1: Startup Repository/System Scan Feature

### 1.1 Architecture Overview
- **Trait-based design:** Create `StartupScannerTrait` and `FilesystemWalkerTrait` for clean abstraction
- **Standard implementation:** Basic recursive directory walking
- **Enhanced implementation:** High-performance parallel scanning with optimized I/O (hidden behind trait)
- **User consent flow:** Interactive Y/N/A prompt before scanning

### 1.2 Implementation Structure
```
src/startup_scan/
├── mod.rs           # Public trait definitions
├── standard.rs      # Standard implementation  
├── enhanced.rs      # Enhanced implementation (feature-gated)
└── prompt.rs        # User interaction logic
```

### 1.3 Key Components
1. **StartupScannerTrait:**
   - `prompt_user()` → Shows scan options
   - `scan_repository()` → Scans current git repo
   - `scan_system()` → Scans entire computer
   - `report_findings()` → Displays results

2. **Integration point:** In `server.rs::run_stdio()` after line 1772:
   ```rust
   // After shield.set_active(true)
   let startup_scanner = self.component_manager.startup_scanner();
   startup_scanner.run_startup_scan().await?;
   ```

3. **Scan options:**
   - **Y (Yes):** Scan current repository only
   - **N (No):** Skip startup scan
   - **A (All):** Scan entire computer (with warnings)

## Part 2: Threat Remediation Strategy

### 2.1 Remediation Modes
1. **Report-Only (Default):**
   - Lists threats without modifying files
   - Generates remediation script for user review
   - Safe default option

2. **Interactive:**
   - Shows each threat with context
   - Options: Skip, Sanitize, Quarantine, View Details
   - User approves each action

3. **Automatic (Opt-in):**
   - Sanitizes safe threats automatically
   - Quarantines dangerous files
   - Logs all actions for audit

### 2.2 Remediation Actions

1. **Sanitize:** Remove/replace dangerous unicode
   - BiDi overrides → visible markers `[BIDI]`
   - Zero-width spaces → removed
   - Homoglyphs → converted to ASCII equivalents

2. **Quarantine:** Move dangerous files
   - Create `.kindlyguard/quarantine/` directory
   - Move files with metadata preservation
   - Generate restoration script

3. **Report:** Generate detailed reports
   - HTML report with visual threat highlighting
   - JSON report for CI/CD integration
   - Remediation commands for manual fixes

### 2.3 Implementation Structure
```
src/remediation/
├── mod.rs           # RemediationTrait definition
├── standard.rs      # Basic remediation
├── enhanced.rs      # Advanced remediation with ML
├── sanitizer.rs     # Unicode sanitization logic
└── quarantine.rs    # File quarantine system
```

## Part 3: Enhanced Features (Hidden Implementation)

### 3.1 Performance Optimizations
- **Parallel scanning:** Use rayon for CPU-bound operations
- **Memory-mapped I/O:** For large file scanning (hidden as "optimized I/O")
- **Smart caching:** Skip unchanged files based on mtime/hash

### 3.2 Advanced Detection
- **Context-aware scanning:** Understand file types
- **Pattern correlation:** Link related threats across files
- **Predictive analysis:** Identify likely attack vectors

## Part 4: Configuration

```toml
[startup_scan]
enabled = true
prompt_timeout_seconds = 30
default_action = "repository"  # repository, skip, or all
max_file_size_mb = 100
exclude_patterns = [".git", "node_modules", "target"]

[remediation]
mode = "report_only"  # report_only, interactive, automatic
backup_before_sanitize = true
quarantine_path = ".kindlyguard/quarantine"
generate_reports = true
```

## Part 5: Safety & Security Considerations

1. **Resource limits:** Cap CPU/memory usage during scans
2. **Timeout protection:** Prevent infinite scanning loops  
3. **Permission checks:** Only scan readable files
4. **Audit logging:** Record all scan and remediation actions
5. **Rollback support:** Undo remediation if needed

This approach provides powerful security scanning while maintaining the trait-based architecture that keeps implementation details hidden. The standard implementation offers solid functionality, while the enhanced version provides blazing-fast performance without exposing proprietary technology.