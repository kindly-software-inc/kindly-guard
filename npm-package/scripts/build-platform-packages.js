#!/usr/bin/env node

/**
 * Build script for creating platform-specific npm packages
 * This prepares the binaries for distribution
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PLATFORMS = [
  { os: 'linux', arch: 'x64', rustTarget: 'x86_64-unknown-linux-gnu', ext: '' },
  { os: 'darwin', arch: 'x64', rustTarget: 'x86_64-apple-darwin', ext: '' },
  { os: 'darwin', arch: 'arm64', rustTarget: 'aarch64-apple-darwin', ext: '' },
  { os: 'win32', arch: 'x64', rustTarget: 'x86_64-pc-windows-msvc', ext: '.exe' }
];

const ROOT_DIR = path.join(__dirname, '..', '..');
const NPM_DIR = path.join(__dirname, '..', 'npm');
const CARGO_TOML = path.join(ROOT_DIR, 'Cargo.toml');

// Ensure we're in the right directory
if (!fs.existsSync(CARGO_TOML)) {
  console.error('Error: Cargo.toml not found. Run this script from the npm-package directory.');
  process.exit(1);
}

// Get version from package.json
const packageJson = require('../package.json');
const version = packageJson.version;

console.log(`Building KindlyGuard ${version} platform packages...`);

// Build for each platform
for (const platform of PLATFORMS) {
  const platformKey = `${platform.os}-${platform.arch}`;
  const packageName = `kindlyguard-${platformKey}`;
  const packageDir = path.join(NPM_DIR, packageName);
  
  console.log(`\n=== Building ${platformKey} ===`);
  
  // Check if we can build for this target
  if (process.platform !== platform.os && platform.os !== 'linux') {
    console.log(`Skipping ${platformKey} (cross-compilation required)`);
    continue;
  }
  
  try {
    // Build the binaries
    console.log(`Building for ${platform.rustTarget}...`);
    execSync(`cargo build --release --target ${platform.rustTarget}`, {
      cwd: ROOT_DIR,
      stdio: 'inherit'
    });
    
    // Copy binaries to platform package
    const targetDir = path.join(ROOT_DIR, 'target', platform.rustTarget, 'release');
    const binaries = [
      { src: `kindlyguard${platform.ext}`, dst: `kindlyguard${platform.ext}` },
      { src: `kindlyguard-cli${platform.ext}`, dst: `kindlyguard-cli${platform.ext}` }
    ];
    
    for (const binary of binaries) {
      const srcPath = path.join(targetDir, binary.src);
      const dstPath = path.join(packageDir, binary.dst);
      
      if (fs.existsSync(srcPath)) {
        console.log(`Copying ${binary.src}...`);
        fs.copyFileSync(srcPath, dstPath);
        
        // Make executable on Unix-like systems
        if (platform.os !== 'win32') {
          fs.chmodSync(dstPath, 0o755);
        }
      } else {
        console.warn(`Warning: ${binary.src} not found at ${srcPath}`);
      }
    }
    
    // Update package version
    const platformPackageJson = path.join(packageDir, 'package.json');
    const platformPackage = JSON.parse(fs.readFileSync(platformPackageJson, 'utf8'));
    platformPackage.version = version;
    fs.writeFileSync(platformPackageJson, JSON.stringify(platformPackage, null, 2) + '\n');
    
    console.log(`✓ ${platformKey} package prepared`);
    
  } catch (error) {
    console.error(`Failed to build ${platformKey}:`, error.message);
  }
}

console.log('\n=== Build Summary ===');
console.log('Platform packages are ready for publishing.');
console.log('To publish all packages, run: npm run publish-all');

// Generate publish script
const publishScript = `#!/bin/bash
# Auto-generated publish script

set -e

echo "Publishing KindlyGuard ${version} packages..."

# Publish platform packages first
${PLATFORMS.map(p => {
  const pkg = `kindlyguard-${p.os}-${p.arch}`;
  return `echo "Publishing @kindlyguard/${p.os}-${p.arch}..."
cd npm/${pkg} && npm publish --access public
cd ../..`;
}).join('\n\n')}

# Wait a moment for packages to be available
echo "Waiting for platform packages to be available..."
sleep 10

# Publish main package
echo "Publishing main kindlyguard package..."
npm publish

echo "All packages published successfully!"
`;

fs.writeFileSync(path.join(__dirname, '..', 'publish-all.sh'), publishScript);
fs.chmodSync(path.join(__dirname, '..', 'publish-all.sh'), 0o755);

console.log('Generated publish-all.sh script');