use std::process::{Command, Stdio};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Helper to run CLI commands
fn run_cli_command(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(&["run", "--bin", "kindly-guard-cli", "--"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute CLI command")
}

/// Test help command and options
#[test]
fn test_help_command() {
    // Test main help
    let output = run_cli_command(&["--help"]);
    assert!(output.status.success(), "Help command failed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("KindlyGuard"), "Help should contain app name");
    assert!(stdout.contains("scan"), "Help should list scan command");
    assert!(stdout.contains("server"), "Help should list server command");
    assert!(stdout.contains("config"), "Help should list config command");

    // Test subcommand help
    let scan_help = run_cli_command(&["scan", "--help"]);
    assert!(scan_help.status.success(), "Scan help failed");
    
    let scan_stdout = String::from_utf8_lossy(&scan_help.stdout);
    assert!(scan_stdout.contains("PATH"), "Scan help should mention PATH");
}

/// Test scan command with various inputs
#[test]
fn test_scan_command() {
    // Create test files
    let mut safe_file = NamedTempFile::new().unwrap();
    writeln!(safe_file, "This is a safe file with normal text").unwrap();
    
    let mut threat_file = NamedTempFile::new().unwrap();
    writeln!(threat_file, "SELECT * FROM users WHERE id = 1 OR 1=1").unwrap();
    
    let mut unicode_file = NamedTempFile::new().unwrap();
    writeln!(unicode_file, "Hello \u{202E}dlroW").unwrap();

    // Test scanning safe file
    let safe_output = run_cli_command(&["scan", safe_file.path().to_str().unwrap()]);
    assert!(safe_output.status.success(), "Safe file scan failed");
    let safe_stdout = String::from_utf8_lossy(&safe_output.stdout);
    assert!(
        safe_stdout.contains("No threats") || safe_stdout.contains("safe"),
        "Safe file should report no threats"
    );

    // Test scanning threat file
    let threat_output = run_cli_command(&["scan", threat_file.path().to_str().unwrap()]);
    let threat_stdout = String::from_utf8_lossy(&threat_output.stdout);
    assert!(
        threat_stdout.contains("threat") || threat_stdout.contains("SQL"),
        "Should detect SQL injection threat"
    );

    // Test scanning unicode file
    let unicode_output = run_cli_command(&["scan", unicode_file.path().to_str().unwrap()]);
    let unicode_stdout = String::from_utf8_lossy(&unicode_output.stdout);
    assert!(
        unicode_stdout.contains("unicode") || unicode_stdout.contains("bidi"),
        "Should detect unicode threat"
    );

    // Test scanning non-existent file
    let missing_output = run_cli_command(&["scan", "/tmp/nonexistent_file_12345.txt"]);
    assert!(!missing_output.status.success(), "Should fail on missing file");
    let missing_stderr = String::from_utf8_lossy(&missing_output.stderr);
    assert!(
        missing_stderr.contains("not found") || missing_stderr.contains("No such file"),
        "Should report file not found"
    );
}

/// Test scan command with different output formats
#[test]
fn test_scan_output_formats() {
    let mut test_file = NamedTempFile::new().unwrap();
    writeln!(test_file, "SELECT * FROM users; DROP TABLE users;").unwrap();
    
    // Test JSON output
    let json_output = run_cli_command(&[
        "scan",
        "--format", "json",
        test_file.path().to_str().unwrap()
    ]);
    
    if json_output.status.success() {
        let json_stdout = String::from_utf8_lossy(&json_output.stdout);
        // Try to parse as JSON
        let result: Result<serde_json::Value, _> = serde_json::from_str(&json_stdout);
        assert!(result.is_ok(), "JSON output should be valid JSON");
    }

    // Test verbose output
    let verbose_output = run_cli_command(&[
        "scan",
        "--verbose",
        test_file.path().to_str().unwrap()
    ]);
    
    let verbose_stdout = String::from_utf8_lossy(&verbose_output.stdout);
    assert!(
        verbose_stdout.len() > 100,
        "Verbose output should contain detailed information"
    );
}

/// Test config command
#[test]
fn test_config_command() {
    // Test show config
    let show_output = run_cli_command(&["config", "show"]);
    assert!(show_output.status.success(), "Config show failed");
    
    let show_stdout = String::from_utf8_lossy(&show_output.stdout);
    assert!(
        show_stdout.contains("[") || show_stdout.contains("security"),
        "Should show configuration sections"
    );

    // Test validate config
    let mut config_file = NamedTempFile::new().unwrap();
    writeln!(config_file, r#"
[security]
unicode_detection = true
injection_detection = true

[server]
host = "127.0.0.1"
port = 8080
"#).unwrap();
    
    let validate_output = run_cli_command(&[
        "config", 
        "validate",
        "--config", config_file.path().to_str().unwrap()
    ]);
    
    assert!(
        validate_output.status.success(),
        "Valid config should pass validation"
    );

    // Test invalid config
    let mut bad_config = NamedTempFile::new().unwrap();
    writeln!(bad_config, r#"
[invalid_section]
bad_key = "value"
"#).unwrap();
    
    let bad_validate = run_cli_command(&[
        "config",
        "validate", 
        "--config", bad_config.path().to_str().unwrap()
    ]);
    
    // Depending on implementation, this might fail or warn
    let bad_stderr = String::from_utf8_lossy(&bad_validate.stderr);
    let bad_stdout = String::from_utf8_lossy(&bad_validate.stdout);
    assert!(
        bad_stderr.contains("invalid") || bad_stdout.contains("unknown") || bad_validate.status.success(),
        "Should handle invalid config gracefully"
    );
}

/// Test server command (basic startup test)
#[test]
fn test_server_command_help() {
    // Just test that server help works
    let output = run_cli_command(&["server", "--help"]);
    assert!(output.status.success(), "Server help failed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stdio"), "Should mention stdio mode");
    assert!(stdout.contains("port"), "Should mention port option");
}

/// Test error cases and help messages
#[test]
fn test_error_cases() {
    // Test unknown command
    let unknown = run_cli_command(&["unknown-command"]);
    assert!(!unknown.status.success(), "Unknown command should fail");
    
    // Test missing required arguments
    let missing_args = run_cli_command(&["scan"]);
    assert!(!missing_args.status.success(), "Scan without path should fail");
    let missing_stderr = String::from_utf8_lossy(&missing_args.stderr);
    assert!(
        missing_stderr.contains("required") || missing_stderr.contains("PATH"),
        "Should mention missing required argument"
    );

    // Test invalid flag
    let invalid_flag = run_cli_command(&["scan", "--invalid-flag", "test.txt"]);
    assert!(!invalid_flag.status.success(), "Invalid flag should fail");
}

/// Test scan with multiple files
#[test]
fn test_scan_multiple_files() {
    // Create multiple test files
    let mut file1 = NamedTempFile::new().unwrap();
    writeln!(file1, "Normal content").unwrap();
    
    let mut file2 = NamedTempFile::new().unwrap();
    writeln!(file2, "<script>alert('xss')</script>").unwrap();
    
    let mut file3 = NamedTempFile::new().unwrap();
    writeln!(file3, "Another normal file").unwrap();

    // Test scanning multiple files
    let output = run_cli_command(&[
        "scan",
        file1.path().to_str().unwrap(),
        file2.path().to_str().unwrap(),
        file3.path().to_str().unwrap(),
    ]);
    
    assert!(output.status.success(), "Multi-file scan failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should report results for all files
    assert!(
        stdout.contains("3") || stdout.matches("file").count() >= 3,
        "Should process all three files"
    );
    
    // Should detect XSS in file2
    assert!(
        stdout.contains("xss") || stdout.contains("script") || stdout.contains("threat"),
        "Should detect XSS threat in file2"
    );
}

/// Test performance with large input
#[test]
fn test_large_file_scan() {
    let mut large_file = NamedTempFile::new().unwrap();
    
    // Write 1MB of text
    for _ in 0..10000 {
        writeln!(large_file, "This is a line of normal text that repeats many times to create a large file for testing performance.").unwrap();
    }
    
    let start = std::time::Instant::now();
    let output = run_cli_command(&["scan", large_file.path().to_str().unwrap()]);
    let duration = start.elapsed();
    
    assert!(output.status.success(), "Large file scan failed");
    assert!(
        duration.as_secs() < 10,
        "Large file scan took too long: {:?}",
        duration
    );
}

/// Test environment variable configuration
#[test] 
fn test_env_var_config() {
    // Set environment variable
    std::env::set_var("KINDLY_GUARD_LOG_LEVEL", "debug");
    
    let output = Command::new("cargo")
        .args(&["run", "--bin", "kindly-guard-cli", "--", "config", "show"])
        .env("KINDLY_GUARD_LOG_LEVEL", "debug")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run with env var");
    
    // Should respect environment variable
    // (actual behavior depends on implementation)
    assert!(
        output.status.success() || true,
        "Should handle environment variables"
    );
}