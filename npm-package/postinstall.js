#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// Detect platform and architecture
const platform = process.platform;
const arch = process.arch;

// Map Node.js platform/arch to our package naming
const platformMap = {
  'darwin': 'darwin',
  'linux': 'linux',
  'win32': 'win32'
};

const archMap = {
  'x64': 'x64',
  'arm64': 'arm64'
};

const supportedPlatform = platformMap[platform];
const supportedArch = archMap[arch];

if (!supportedPlatform || !supportedArch) {
  console.error(`Unsupported platform: ${platform}-${arch}`);
  console.error('KindlyGuard currently supports:');
  console.error('  - Linux x64');
  console.error('  - macOS x64 (Intel)');
  console.error('  - macOS arm64 (Apple Silicon)');
  console.error('  - Windows x64');
  process.exit(1);
}

const packageName = `@kindlyguard/${supportedPlatform}-${supportedArch}`;
const binDir = path.join(__dirname, 'bin');

console.log(`Installing KindlyGuard for ${supportedPlatform}-${supportedArch}...`);

// Check if the platform-specific package is installed
try {
  const platformPackagePath = require.resolve(`${packageName}/package.json`);
  const platformPackageDir = path.dirname(platformPackagePath);
  
  // Create bin directory if it doesn't exist
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }
  
  // Copy binaries from platform package
  const binaries = ['kindlyguard', 'kindlyguard-cli'];
  
  for (const binary of binaries) {
    const srcBinary = platform === 'win32' ? `${binary}.exe` : binary;
    const dstBinary = srcBinary;
    
    const srcPath = path.join(platformPackageDir, srcBinary);
    const dstPath = path.join(binDir, dstBinary);
    
    if (fs.existsSync(srcPath)) {
      console.log(`Copying ${binary}...`);
      fs.copyFileSync(srcPath, dstPath);
      
      // Make executable on Unix-like systems
      if (platform !== 'win32') {
        fs.chmodSync(dstPath, 0o755);
      }
    } else {
      console.warn(`Warning: ${binary} not found in platform package`);
    }
  }
  
  // Create wrapper scripts for Unix-like systems
  if (platform !== 'win32') {
    for (const binary of binaries) {
      const wrapperPath = path.join(binDir, binary);
      const wrapperContent = `#!/bin/sh
exec "$(dirname "$0")/${binary}.bin" "$@"
`;
      
      // Rename actual binary
      const actualBinaryPath = path.join(binDir, binary);
      const renamedBinaryPath = path.join(binDir, `${binary}.bin`);
      
      if (fs.existsSync(actualBinaryPath)) {
        fs.renameSync(actualBinaryPath, renamedBinaryPath);
        fs.writeFileSync(wrapperPath, wrapperContent);
        fs.chmodSync(wrapperPath, 0o755);
      }
    }
  }
  
  console.log('KindlyGuard installation complete!');
  console.log('');
  console.log('You can now use:');
  console.log('  kindlyguard --help        # Run the MCP server');
  console.log('  kindlyguard-cli --help    # Use the CLI tool');
  console.log('');
  console.log('For Claude Desktop integration, add to your config:');
  console.log(JSON.stringify({
    mcpServers: {
      "kindly-guard": {
        command: "npx",
        args: ["kindlyguard", "--stdio"]
      }
    }
  }, null, 2));
  
} catch (error) {
  console.error(`Failed to install platform-specific package: ${packageName}`);
  console.error('This might happen if:');
  console.error('1. The platform package is not yet published');
  console.error('2. Network issues prevented installation');
  console.error('');
  console.error('As a fallback, you can build from source:');
  console.error('  git clone https://github.com/samduchaine/kindly-guard');
  console.error('  cd kindly-guard');
  console.error('  cargo build --release');
  process.exit(1);
}