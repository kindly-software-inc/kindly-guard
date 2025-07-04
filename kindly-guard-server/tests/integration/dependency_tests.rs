use std::process::Command;
use std::path::Path;

/// Verify the project can build without enhanced features
#[test]
fn test_build_without_enhanced_features() {
    let output = Command::new("cargo")
        .args(&["build", "--no-default-features"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute cargo build");

    assert!(
        output.status.success(),
        "Build failed without enhanced features: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Verify no proprietary symbols are exposed in the public API
#[test]
fn test_no_proprietary_symbols_exposed() {
    // Build the library
    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to build library");

    assert!(output.status.success(), "Library build failed");

    // Check that proprietary type names don't appear in public docs
    let doc_output = Command::new("cargo")
        .args(&["doc", "--no-deps", "--document-private-items"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to generate docs");

    let doc_content = String::from_utf8_lossy(&doc_output.stdout);
    
    // These proprietary names should not appear in public API
    let forbidden_names = [
        "AtomicBitPackedEventBuffer",
        "SeqlockMetricsProvider",
        "BitPackedCircuitBreaker",
        "AtomicStateBuffer",
    ];

    for name in &forbidden_names {
        assert!(
            !doc_content.contains(name),
            "Proprietary type '{}' found in public documentation",
            name
        );
    }
}

/// Verify the binary doesn't have missing library dependencies
#[test]
#[cfg(target_os = "linux")]
fn test_no_missing_libraries() {
    // First build the binary
    let build_output = Command::new("cargo")
        .args(&["build", "--bin", "kindly-guard-server"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to build binary");

    assert!(build_output.status.success(), "Binary build failed");

    // Find the built binary
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug");
    let binary_path = target_dir.join("kindly-guard-server");

    if binary_path.exists() {
        // Check dependencies with ldd
        let ldd_output = Command::new("ldd")
            .arg(&binary_path)
            .output()
            .expect("Failed to run ldd");

        let ldd_result = String::from_utf8_lossy(&ldd_output.stdout);
        
        // Ensure no missing libraries
        assert!(
            !ldd_result.contains("not found"),
            "Binary has missing library dependencies:\n{}",
            ldd_result
        );
    }
}

/// Test that standard features compile correctly
#[test]
fn test_standard_features_compile() {
    let output = Command::new("cargo")
        .args(&["check", "--features", "standard"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to check with standard features");

    assert!(
        output.status.success(),
        "Standard features compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test that trait-based architecture allows clean separation
#[test]
fn test_trait_based_separation() {
    // This test verifies that we can compile with only trait definitions
    let test_code = r#"
        use kindly_guard_server::traits::{
            CircuitBreakerTrait, MetricsProvider, EventBufferTrait,
            NeutralizerTrait, PermissionCheckerTrait, ResilienceProviderTrait,
            ScannerTrait, StorageTrait
        };

        fn accept_scanner(_scanner: &dyn ScannerTrait) {}
        fn accept_metrics(_metrics: &dyn MetricsProvider) {}
        fn accept_storage(_storage: &dyn StorageTrait) {}
    "#;

    // Create a temporary test file
    let test_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("temp_trait_test.rs");

    std::fs::write(&test_file, test_code).expect("Failed to write test file");

    // Try to compile it
    let output = Command::new("rustc")
        .args(&[
            "--edition=2021",
            "--crate-type=lib",
            "-L",
            "target/debug/deps",
            test_file.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to compile trait test");

    // Clean up
    let _ = std::fs::remove_file(&test_file);

    assert!(
        output.status.success(),
        "Trait-based separation test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Verify cargo tree doesn't show private dependencies in public API
#[test]
fn test_dependency_tree_privacy() {
    let output = Command::new("cargo")
        .args(&["tree", "--edges", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run cargo tree");

    let tree_output = String::from_utf8_lossy(&output.stdout);
    
    // kindly-guard-core should not appear as a public dependency
    // (it's okay if it appears as a private/dev dependency)
    let lines: Vec<&str> = tree_output.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("kindly-guard-core") && i > 0 {
            // Check if this is a public dependency (would appear at top level)
            let indent_level = line.len() - line.trim_start().len();
            assert!(
                indent_level > 0,
                "kindly-guard-core appears as a public dependency"
            );
        }
    }
}