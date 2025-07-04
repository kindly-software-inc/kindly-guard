/**
 * Platform detection utilities for KindlyGuard binary distribution
 * Following best practices from esbuild and swc
 */

const os = require('os');
const path = require('path');

// Platform mapping
const PLATFORM_MAPPING = {
  darwin: 'darwin',
  linux: 'linux',
  win32: 'win32'
};

// Architecture mapping
const ARCH_MAPPING = {
  x64: 'x64',
  x86_64: 'x64',
  arm64: 'arm64',
  aarch64: 'arm64'
};

// Known platform-architecture combinations
const SUPPORTED_PLATFORMS = [
  'darwin-x64',
  'darwin-arm64',
  'linux-x64',
  'win32-x64'
];

function getPlatform() {
  const platform = PLATFORM_MAPPING[process.platform];
  if (!platform) {
    throw new Error(`Unsupported platform: ${process.platform}`);
  }
  return platform;
}

function getArchitecture() {
  const arch = ARCH_MAPPING[process.arch] || process.arch;
  if (!ARCH_MAPPING[process.arch]) {
    throw new Error(`Unsupported architecture: ${process.arch}`);
  }
  return arch;
}

function getPlatformKey() {
  const platform = getPlatform();
  const arch = getArchitecture();
  const key = `${platform}-${arch}`;
  
  if (!SUPPORTED_PLATFORMS.includes(key)) {
    throw new Error(
      `Unsupported platform: ${key}\n` +
      `Supported platforms are: ${SUPPORTED_PLATFORMS.join(', ')}`
    );
  }
  
  return key;
}

function getPackageName() {
  return `@kindlyguard/${getPlatformKey()}`;
}

function getBinaryName(name) {
  const platform = getPlatform();
  return platform === 'win32' ? `${name}.exe` : name;
}

function getBinaryPath(name, baseDir = __dirname) {
  const binDir = path.join(baseDir, '..', 'bin');
  return path.join(binDir, getBinaryName(name));
}

function isMusl() {
  // Detect musl libc (Alpine Linux)
  if (process.platform !== 'linux') {
    return false;
  }
  
  try {
    const { execSync } = require('child_process');
    const output = execSync('ldd --version 2>&1', { encoding: 'utf8' });
    return output.includes('musl');
  } catch (e) {
    // Check if /lib/ld-musl-x86_64.so.1 exists
    const fs = require('fs');
    return fs.existsSync('/lib/ld-musl-x86_64.so.1');
  }
}

function validateBinary(binaryPath) {
  const fs = require('fs');
  
  if (!fs.existsSync(binaryPath)) {
    return { valid: false, error: 'Binary not found' };
  }
  
  const stats = fs.statSync(binaryPath);
  if (!stats.isFile()) {
    return { valid: false, error: 'Path is not a file' };
  }
  
  // Check if executable on Unix-like systems
  if (process.platform !== 'win32') {
    const mode = stats.mode;
    const isExecutable = (mode & 0o111) !== 0;
    if (!isExecutable) {
      return { valid: false, error: 'Binary is not executable' };
    }
  }
  
  return { valid: true };
}

function downloadUrl(version = process.env.npm_package_version || 'latest') {
  const platformKey = getPlatformKey();
  const baseUrl = process.env.KINDLYGUARD_DOWNLOAD_BASE || 
    'https://github.com/kindly-software-inc/kindly-guard/releases/download';
  
  // Handle Windows differently (uses .zip instead of .tar.gz)
  const extension = platformKey.startsWith('win') ? 'zip' : 'tar.gz';
  // Note: Current release assets don't include version in filename
  const assetName = `kindlyguard-${platformKey}.${extension}`;
  return `${baseUrl}/v${version}/${assetName}`;
}

module.exports = {
  getPlatform,
  getArchitecture,
  getPlatformKey,
  getPackageName,
  getBinaryName,
  getBinaryPath,
  isMusl,
  validateBinary,
  downloadUrl,
  SUPPORTED_PLATFORMS
};