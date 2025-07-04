#!/usr/bin/env node

/**
 * Post-install script for KindlyGuard
 * Downloads or copies platform-specific binaries
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const https = require('https');
const tar = require('tar');
const { pipeline } = require('stream');
const { promisify } = require('util');

const platform = require('./platform');

const pipelineAsync = promisify(pipeline);

// Skip in CI or when explicitly requested
if (process.env.CI || process.env.KINDLYGUARD_SKIP_DOWNLOAD) {
  console.log('Skipping KindlyGuard binary installation');
  process.exit(0);
}

async function downloadBinary(url, destPath) {
  console.log(`Downloading from ${url}...`);
  
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Follow redirect
        return downloadBinary(response.headers.location, destPath)
          .then(resolve)
          .catch(reject);
      }
      
      if (response.statusCode !== 200) {
        reject(new Error(`Download failed: ${response.statusCode}`));
        return;
      }
      
      const totalSize = parseInt(response.headers['content-length'], 10);
      let downloadedSize = 0;
      
      response.on('data', (chunk) => {
        downloadedSize += chunk.length;
        const percent = Math.round((downloadedSize / totalSize) * 100);
        process.stdout.write(`\rDownloading... ${percent}%`);
      });
      
      response.pipe(tar.x({
        C: path.dirname(destPath),
        strip: 1
      }))
      .on('finish', () => {
        console.log('\nDownload complete!');
        resolve();
      })
      .on('error', reject);
    }).on('error', reject);
  });
}

async function tryNativeDependency() {
  try {
    const packageName = platform.getPackageName();
    const platformPackagePath = require.resolve(`${packageName}/package.json`);
    const platformPackageDir = path.dirname(platformPackagePath);
    
    console.log(`Found native dependency: ${packageName}`);
    
    const binDir = path.join(__dirname, '..', 'bin');
    
    // Ensure bin directory exists
    await fs.promises.mkdir(binDir, { recursive: true });
    
    // Copy binaries
    const binaries = ['kindlyguard', 'kindlyguard-cli'];
    
    for (const binary of binaries) {
      const srcName = platform.getBinaryName(binary);
      const srcPath = path.join(platformPackageDir, srcName);
      const dstPath = path.join(binDir, srcName);
      
      if (fs.existsSync(srcPath)) {
        console.log(`Copying ${binary}...`);
        await fs.promises.copyFile(srcPath, dstPath);
        
        // Make executable on Unix-like systems
        if (process.platform !== 'win32') {
          await fs.promises.chmod(dstPath, 0o755);
        }
      }
    }
    
    return true;
  } catch (error) {
    return false;
  }
}

async function tryDirectDownload() {
  const version = process.env.npm_package_version || 'latest';
  const url = platform.downloadUrl(version);
  const binDir = path.join(__dirname, '..', 'bin');
  
  try {
    await fs.promises.mkdir(binDir, { recursive: true });
    await downloadBinary(url, binDir);
    
    // Make binaries executable
    const binaries = ['kindlyguard', 'kindlyguard-cli'];
    for (const binary of binaries) {
      const binaryPath = path.join(binDir, platform.getBinaryName(binary));
      if (fs.existsSync(binaryPath) && process.platform !== 'win32') {
        await fs.promises.chmod(binaryPath, 0o755);
      }
    }
    
    return true;
  } catch (error) {
    console.error('Download failed:', error.message);
    return false;
  }
}

async function verifyInstallation() {
  const binPath = platform.getBinaryPath('kindlyguard');
  const validation = platform.validateBinary(binPath);
  
  if (!validation.valid) {
    throw new Error(`Binary validation failed: ${validation.error}`);
  }
  
  // Try to run --version to verify it works
  const result = spawnSync(binPath, ['--version'], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  
  if (result.error) {
    throw new Error(`Failed to execute binary: ${result.error.message}`);
  }
  
  if (result.status !== 0) {
    throw new Error(`Binary exited with code ${result.status}`);
  }
  
  console.log(`KindlyGuard ${result.stdout.trim()} installed successfully!`);
  return true;
}

async function main() {
  try {
    console.log(`Installing KindlyGuard for ${platform.getPlatformKey()}...`);
    
    // Try native dependency first
    let installed = await tryNativeDependency();
    
    // Fall back to direct download
    if (!installed && !process.env.KINDLYGUARD_SKIP_DOWNLOAD) {
      installed = await tryDirectDownload();
    }
    
    if (!installed) {
      throw new Error('Failed to install KindlyGuard binary');
    }
    
    // Verify installation
    await verifyInstallation();
    
    console.log('\nInstallation complete!');
    console.log('');
    console.log('Usage:');
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
    console.error('\nERROR:', error.message);
    console.error('');
    console.error('To skip binary download, set KINDLYGUARD_SKIP_DOWNLOAD=1');
    console.error('');
    console.error('For manual installation:');
    console.error('  1. Download the binary from:');
    console.error(`     ${platform.downloadUrl()}`);
    console.error('  2. Extract to:', path.join(__dirname, '..', 'bin'));
    console.error('  3. Make executable: chmod +x bin/kindlyguard*');
    
    process.exit(1);
  }
}

// Only run if called directly
if (require.main === module) {
  main();
}