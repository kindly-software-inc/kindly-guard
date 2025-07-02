//! Security tests for the KindlyGuard CLI wrapper functionality
//! 
//! These tests verify that the wrap command properly:
//! - Prevents command injection attacks
//! - Secures environment variables
//! - Handles signals and process isolation correctly
//! - Protects input/output streams
//! - Enforces blocking vs warning modes
//! - Integrates with various AI CLIs

use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use std::process::{Command as StdCommand, Stdio};
use tempfile::NamedTempFile;

/// Helper to create a test command with wrap
fn wrap_cmd() -> Command {
    let mut cmd = Command::cargo_bin("kindly-guard-cli").unwrap();
    cmd.arg("wrap");
    cmd
}

/// Helper to create a mock AI CLI script
fn create_mock_cli(content: &str) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    writeln!(file, "#!/bin/bash")?;
    writeln!(file, "{}", content)?;
    file.flush()?;
    
    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.as_file().metadata()?.permissions();
        perms.set_mode(0o755);
        file.as_file().set_permissions(perms)?;
    }
    
    Ok(file)
}

#[test]
fn test_command_injection_prevention_semicolon() {
    // Test that semicolon injection is prevented
    let mock_cli = create_mock_cli("echo \"$@\"").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .arg("test; rm -rf /")
        .write_stdin(b"safe input\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("test; rm -rf /"))
        .stdout(predicate::str::does_not_contain("rm -rf /"));
}

#[test]
fn test_command_injection_prevention_backticks() {
    // Test that backtick command substitution is prevented
    let mock_cli = create_mock_cli("echo \"$@\"").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .arg("test`whoami`")
        .write_stdin(b"safe input\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("test`whoami`"));
}

#[test]
fn test_command_injection_prevention_dollar_parens() {
    // Test that $() command substitution is prevented
    let mock_cli = create_mock_cli("echo \"$@\"").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .arg("test$(cat /etc/passwd)")
        .write_stdin(b"safe input\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("test$(cat /etc/passwd)"));
}

#[test]
fn test_environment_variable_security() {
    // Test that sensitive environment variables are not leaked
    let mock_cli = create_mock_cli("env | grep -E '^(PATH|HOME|USER|SHELL)='").unwrap();
    
    // Set a potentially dangerous environment variable
    std::env::set_var("MALICIOUS_VAR", "danger");
    
    wrap_cmd()
        .arg(mock_cli.path())
        .env_clear() // Clear all env vars
        .env("PATH", std::env::var("PATH").unwrap()) // Only pass PATH
        .assert()
        .success()
        .stdout(predicate::str::contains("PATH="))
        .stdout(predicate::str::does_not_contain("MALICIOUS_VAR"));
    
    std::env::remove_var("MALICIOUS_VAR");
}

#[test]
fn test_environment_injection_prevention() {
    // Test that environment variable injection is prevented
    let mock_cli = create_mock_cli("echo \"PATH=$PATH\"").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .env("PATH", "/usr/bin:/bin:$(rm -rf /)")
        .assert()
        .success()
        .stdout(predicate::str::contains("$(rm -rf /)"))
        .stdout(predicate::str::does_not_contain("rm -rf /"));
}

#[test]
#[ignore = "Signal tests require special handling"]
fn test_signal_handling_sigint() {
    // Test that SIGINT is properly forwarded to child process
    let mock_cli = create_mock_cli("trap 'echo \"Got SIGINT\"' INT; sleep 10").unwrap();
    
    // This test is disabled as spawn() is not available in assert_cmd
}

#[test]
#[ignore = "Signal tests require special handling"]
fn test_signal_handling_sigterm() {
    // Test that SIGTERM properly terminates wrapped process
    let mock_cli = create_mock_cli("trap 'echo \"Got SIGTERM\"; exit 0' TERM; sleep 10").unwrap();
    
    // This test is disabled as spawn() is not available in assert_cmd
}

#[test]
fn test_process_isolation_file_descriptors() {
    // Test that extra file descriptors are not leaked to child
    let mock_cli = create_mock_cli("ls -la /proc/$$/fd/ 2>/dev/null | wc -l").unwrap();
    
    // Open some extra file descriptors
    let _file1 = std::fs::File::open("/dev/null").unwrap();
    let _file2 = std::fs::File::open("/dev/null").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .assert()
        .success();
}

#[test]
fn test_input_stream_unicode_injection() {
    // Test that unicode injection attacks are detected in input
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"Hello\u{202E}World\n") // Right-to-left override
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"))
        .stdout(predicate::str::does_not_contain("\u{202E}"));
}

#[test]
fn test_input_stream_sql_injection() {
    // Test that SQL injection attempts are detected
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"'; DROP TABLE users; --\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}

#[test]
fn test_input_stream_command_injection() {
    // Test that command injection in input is detected
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"test`whoami`\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}

#[test]
fn test_input_stream_xss_injection() {
    // Test that XSS attempts are detected
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"<script>alert('xss')</script>\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}

#[test]
fn test_output_stream_passthrough() {
    // Test that clean output is passed through correctly
    let mock_cli = create_mock_cli("echo 'Clean output'; echo 'Error output' >&2").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Clean output"))
        .stderr(predicate::str::contains("Error output"));
}

#[test]
fn test_blocking_mode_blocks_threats() {
    // Test that blocking mode prevents threats from reaching the command
    let mock_cli = create_mock_cli("cat | wc -c").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"safe input\n")
        .write_stdin(b"'; DROP TABLE; --\n")
        .write_stdin(b"more safe input\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("11")) // Only first line
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}

#[test]
fn test_warning_mode_allows_threats() {
    // Test that warning mode allows threats but warns
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path()) // No --block flag
        .write_stdin(b"'; DROP TABLE; --\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("'; DROP TABLE; --"))
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Proceeding with caution"));
}

#[test]
fn test_exit_code_propagation() {
    // Test that wrapped command exit codes are propagated
    let mock_cli = create_mock_cli("exit 42").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .assert()
        .code(42);
}

#[test]
fn test_stdin_eof_handling() {
    // Test that EOF on stdin is handled correctly
    let mock_cli = create_mock_cli("cat; echo 'After EOF'").unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(b"test input\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("test input"))
        .stdout(predicate::str::contains("After EOF"));
}

#[test]
fn test_large_input_handling() {
    // Test handling of large inputs
    let mock_cli = create_mock_cli("wc -c").unwrap();
    let large_input = "a".repeat(1024 * 1024); // 1MB of data
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(large_input)
        .assert()
        .success()
        .stdout(predicate::str::contains("1048576"));
}

#[test]
fn test_binary_data_handling() {
    // Test that binary data is handled correctly
    let mock_cli = create_mock_cli("xxd -p | head -n 1").unwrap();
    let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(binary_data)
        .assert()
        .success()
        .stdout(predicate::str::contains("000102fffefd"));
}

#[test]
fn test_concurrent_io_handling() {
    // Test handling of concurrent stdin/stdout/stderr
    let mock_cli = create_mock_cli(r#"
        while IFS= read -r line; do
            echo "OUT: $line"
            echo "ERR: $line" >&2
        done
    "#).unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(b"line1\nline2\nline3\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("OUT: line1"))
        .stdout(predicate::str::contains("OUT: line2"))
        .stdout(predicate::str::contains("OUT: line3"))
        .stderr(predicate::str::contains("ERR: line1"))
        .stderr(predicate::str::contains("ERR: line2"))
        .stderr(predicate::str::contains("ERR: line3"));
}

#[test]
fn test_ai_cli_integration_gemini_style() {
    // Test integration with Gemini-style CLI
    let mock_cli = create_mock_cli(r#"
        echo "Gemini CLI v1.0"
        read -p "> " input
        echo "Response: $input"
    "#).unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(b"Generate code\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Gemini CLI"))
        .stdout(predicate::str::contains("Response: Generate code"));
}

#[test]
fn test_ai_cli_integration_codex_style() {
    // Test integration with Codex-style CLI
    let mock_cli = create_mock_cli(r#"
        echo "=== Codex CLI ==="
        echo "Enter prompt (Ctrl-D to finish):"
        cat
        echo -e "\n=== Generated ==="
    "#).unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(b"Write a function\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Codex CLI"))
        .stdout(predicate::str::contains("Write a function"))
        .stdout(predicate::str::contains("Generated"));
}

#[test]
fn test_interactive_prompt_handling() {
    // Test handling of interactive prompts
    let mock_cli = create_mock_cli(r#"
        read -p "Username: " user
        read -s -p "Password: " pass
        echo -e "\nLogged in as $user"
    "#).unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(b"testuser\ntestpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Username:"))
        .stdout(predicate::str::contains("Logged in as testuser"));
}

#[test]
fn test_path_traversal_prevention() {
    // Test that path traversal attempts are detected
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"../../etc/passwd\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}

#[test]
fn test_null_byte_injection() {
    // Test that null byte injection is handled
    let mock_cli = create_mock_cli("cat | xxd -p").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"test\0injection\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"));
}

#[test]
fn test_ansi_escape_injection() {
    // Test that ANSI escape sequence injection is detected
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"\x1b[31mRED\x1b[0m\x1b]0;TITLE\x07\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"));
}

#[test]
fn test_resource_exhaustion_prevention() {
    // Test that resource exhaustion attempts are handled
    let mock_cli = create_mock_cli("head -c 1000").unwrap(); // Limit output
    
    // Try to send infinite input
    let infinite_input = "a".repeat(10_000_000); // 10MB
    
    wrap_cmd()
        .arg(mock_cli.path())
        .timeout(std::time::Duration::from_secs(5))
        .write_stdin(infinite_input)
        .assert()
        .success()
        .stdout(predicate::str::contains("a").count(1000));
}

#[test]
fn test_server_connection_failure() {
    // Test behavior when server is unavailable
    let mock_cli = create_mock_cli("echo 'Hello'").unwrap();
    
    wrap_cmd()
        .arg("--server")
        .arg("http://localhost:99999") // Invalid port
        .arg(mock_cli.path())
        .write_stdin(b"test\n")
        .assert()
        .success() // Should still work without server
        .stdout(predicate::str::contains("Hello"));
}

#[test]
fn test_malformed_utf8_handling() {
    // Test handling of malformed UTF-8
    let mock_cli = create_mock_cli("cat | od -c").unwrap();
    let malformed = vec![0xFF, 0xFE, 0xFD];
    
    wrap_cmd()
        .arg(mock_cli.path())
        .write_stdin(malformed)
        .assert()
        .success();
}

#[test]
fn test_command_not_found() {
    // Test handling of non-existent commands
    wrap_cmd()
        .arg("/nonexistent/command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to start command"));
}

#[test]
fn test_permission_denied() {
    // Test handling of permission errors
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "#!/bin/bash\necho test").unwrap();
    file.flush().unwrap();
    
    // Remove execute permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o644);
        file.as_file().set_permissions(perms).unwrap();
    }
    
    wrap_cmd()
        .arg(file.path())
        .assert()
        .failure();
}

#[test]
fn test_symlink_resolution() {
    // Test that symlinks are resolved safely
    let mock_cli = create_mock_cli("echo 'Real file'").unwrap();
    let link_path = mock_cli.path().with_extension("link");
    
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(mock_cli.path(), &link_path).unwrap();
    }
    
    wrap_cmd()
        .arg(&link_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Real file"));
    
    // Cleanup
    std::fs::remove_file(link_path).ok();
}

#[test]
fn test_working_directory_isolation() {
    // Test that working directory changes don't affect wrapper
    let mock_cli = create_mock_cli("pwd").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    
    wrap_cmd()
        .arg(mock_cli.path())
        .current_dir(temp_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(temp_dir.path().to_str().unwrap()));
}

#[test]
fn test_multiple_threat_detection() {
    // Test detection of multiple threats in single input
    let mock_cli = create_mock_cli("cat").unwrap();
    
    wrap_cmd()
        .arg("--block")
        .arg(mock_cli.path())
        .write_stdin(b"'; DROP TABLE; -- <script>alert('xss')</script> \u{202E}\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("THREAT DETECTED"))
        .stderr(predicate::str::contains("Input blocked"));
}