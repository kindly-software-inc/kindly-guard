# KindlyGuard v0.15.0 Release Verification Report

**Generated**: 2025-07-07 01:36:29  
**Version**: 0.15.0  
**Commit**: b5f676b9deb3bc0a8462025eee0c394208fd4506  
**Branch**: main  

## Executive Summary

This report contains the results of automated verification checks for the KindlyGuard v0.15.0 release.

## 1. Version Consistency Checks

✗ **kindly-guard-server version**: FAILED
  - Version  does not match expected 0.15.0
⚠ **kindly-guard-cli Cargo.toml**: WARNING
  - File not found
✓ **kindly-guard-shield version**: PASSED
  - Version 0.15.0 matches expected 0.15.0
✓ **CHANGELOG.md entry**: PASSED
  - Version 0.15.0 entry found
✓ **package.json version**: PASSED
  - Version matches

## 2. Security Audits

✗ **Cargo audit**: FAILED
  -  vulnerabilities found
✗ **Cargo deny**: FAILED
  - Some checks failed
⚠ **Unsafe code check**: WARNING
  - cargo-geiger not installed

## 3. Test Suite Execution

✗ **All tests**: FAILED
  - Test execution failed
✗ **Quarantine tests**: FAILED
  - Quarantine tests failed
✗ **Message neutralization tests**: FAILED
  - Message neutralization tests failed
⚠ **Property tests**: WARNING
  - Property tests not found or failed

## 4. Performance Benchmarks

