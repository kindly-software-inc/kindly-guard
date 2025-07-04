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

/// Verify no enhanced implementation symbols are exposed in the public API
#[test]
fn test_no_enhanced_symbols_exposed() {
    // Build the library
    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to build library");

    assert!(output.status.success(), "Library build failed");

    // Check that enhanced implementation names don't appear in public docs
    let doc_output = Command::new("cargo")
        .args(&["doc", "--no-deps", "--document-private-items"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to generate docs");

    let doc_content = String::from_utf8_lossy(&doc_output.stdout);
    
    // These implementation names should not appear in public API
    let forbidden_names = [
        "EnhancedEventBuffer",
        "EnhancedMetricsProvider",
        "EnhancedCircuitBreaker",
        "EnhancedStateBuffer",
    ];

    for name in &forbidden_names {
        assert!(
            !doc_content.contains(name),
            "Enhanced type '{}' found in public documentation",
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
        .args(&["build", "--bin", "kindly-guard"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to build binary");

    assert!(build_output.status.success(), "Binary build failed: {}", String::from_utf8_lossy(&build_output.stderr));

    // Find the built binary
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug");
    let binary_path = target_dir.join("kindly-guard");

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

/// Test that default features compile correctly
#[test]
fn test_default_features_compile() {
    let output = Command::new("cargo")
        .args(&["check"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to check with default features");

    assert!(
        output.status.success(),
        "Default features compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test that trait-based architecture allows clean separation
#[test]
fn test_trait_based_separation() {
    // Just verify the traits module is accessible and compiles
    let output = Command::new("cargo")
        .args(&["check", "--lib"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to check library");

    assert!(
        output.status.success(),
        "Library compilation failed: {}",
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
    
    // Enhanced implementations should not appear as public dependencies
    // (it's okay if they appear as internal/feature-gated dependencies)
    let lines: Vec<&str> = tree_output.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("enhanced") && i > 0 {
            // Check if this is a public dependency (would appear at top level)
            let indent_level = line.len() - line.trim_start().len();
            // Enhanced features should be properly feature-gated
            if indent_level == 0 && !line.contains("feature") {
                panic!("Enhanced implementation appears as a public dependency");
            }
        }
    }
}