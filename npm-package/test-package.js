#!/usr/bin/env node

/**
 * Test script for KindlyGuard npm package
 * Verifies that the binary is correctly installed and executable
 */

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function log(message, color = RESET) {
  console.log(`${color}${message}${RESET}`);
}

function checkBinary() {
  const binPath = path.join(__dirname, 'bin', 'kindlyguard');
  const binPathExe = path.join(__dirname, 'bin', 'kindlyguard.exe');
  
  // Check if binary exists
  const actualPath = process.platform === 'win32' ? binPathExe : binPath;
  
  if (!fs.existsSync(actualPath)) {
    log('✗ Binary not found at: ' + actualPath, RED);
    return false;
  }
  
  log('✓ Binary found at: ' + actualPath, GREEN);
  
  // Check if it's executable (Unix only)
  if (process.platform !== 'win32') {
    const stats = fs.statSync(actualPath);
    if ((stats.mode & 0o111) === 0) {
      log('✗ Binary is not executable', RED);
      return false;
    }
    log('✓ Binary is executable', GREEN);
  }
  
  // Try to run --version
  const result = spawnSync(actualPath, ['--version'], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  
  if (result.error) {
    log('✗ Failed to execute binary: ' + result.error.message, RED);
    return false;
  }
  
  if (result.status !== 0) {
    log('✗ Binary exited with code: ' + result.status, RED);
    if (result.stderr) {
      log('  Error: ' + result.stderr.trim(), RED);
    }
    return false;
  }
  
  log('✓ Binary executed successfully', GREEN);
  log('  Version: ' + result.stdout.trim(), YELLOW);
  
  return true;
}

function main() {
  log('Testing KindlyGuard npm package...', YELLOW);
  log('Platform: ' + process.platform + ' ' + process.arch, YELLOW);
  
  if (checkBinary()) {
    log('\n✅ All tests passed!', GREEN);
    process.exit(0);
  } else {
    log('\n❌ Tests failed!', RED);
    process.exit(1);
  }
}

main();