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
const unzipper = require('unzipper');
const { pipeline } = require('stream');
const { promisify } = require('util');

const platform = require('./platform');

const pipelineAsync = promisify(pipeline);

// Skip in CI or when explicitly requested
if (process.env.CI || process.env.KINDLYGUARD_SKIP_DOWNLOAD) {
  console.log('ℹ️  Skipping KindlyGuard binary installation');
  if (process.env.CI) {
    console.log('   (Running in CI environment)');
  }
  if (process.env.KINDLYGUARD_SKIP_DOWNLOAD) {
    console.log('   (KINDLYGUARD_SKIP_DOWNLOAD is set)');
  }
  process.exit(0);
}

async function downloadBinary(url, destPath) {
  console.log(`📦 Downloading from ${url}...`);
  
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Follow redirect
        return downloadBinary(response.headers.location, destPath)
          .then(resolve)
          .catch(reject);
      }
      
      if (response.statusCode === 404) {
        const error = new Error('DOWNLOAD_NOT_FOUND');
        error.statusCode = 404;
        reject(error);
        return;
      }
      
      if (response.statusCode !== 200) {
        const error = new Error(`Download failed with status: ${response.statusCode}`);
        error.statusCode = response.statusCode;
        reject(error);
        return;
      }
      
      const totalSize = parseInt(response.headers['content-length'], 10);
      let downloadedSize = 0;
      
      response.on('data', (chunk) => {
        downloadedSize += chunk.length;
        const percent = Math.round((downloadedSize / totalSize) * 100);
        const progressBar = '█'.repeat(Math.floor(percent / 2)) + '░'.repeat(50 - Math.floor(percent / 2));
        process.stdout.write(`\r📥 Downloading: [${progressBar}] ${percent}%`);
      });
      
      // Handle different archive types
      const isZip = url.endsWith('.zip');
      const extractStream = isZip 
        ? unzipper.Extract({ path: path.dirname(destPath) })
        : tar.x({ C: path.dirname(destPath), strip: 1 });
      
      response.pipe(extractStream)
      .on('finish', () => {
        console.log('\n✅ Download complete!');
        resolve();
      })
      .on('error', (err) => {
        if (err.code === 'ENOSPC') {
          const error = new Error('DISK_SPACE');
          error.originalError = err;
          reject(error);
        } else {
          reject(err);
        }
      });
    }).on('error', (err) => {
      if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
        const error = new Error('NETWORK_ERROR');
        error.originalError = err;
        reject(error);
      } else {
        reject(err);
      }
    });
  });
}

async function tryNativeDependency() {
  try {
    const packageName = platform.getPackageName();
    const platformPackagePath = require.resolve(`${packageName}/package.json`);
    const platformPackageDir = path.dirname(platformPackagePath);
    
    console.log(`📌 Found native dependency: ${packageName}`);
    
    const binDir = path.join(__dirname, '..', 'bin');
    
    // Ensure bin directory exists
    await fs.promises.mkdir(binDir, { recursive: true });
    
    // Copy the unified binary
    const binary = 'kindlyguard';
    const srcName = platform.getBinaryName(binary);
    const srcPath = path.join(platformPackageDir, srcName);
    const dstPath = path.join(binDir, srcName);
    
    if (fs.existsSync(srcPath)) {
      console.log(`   📄 Copying ${binary}...`);
      await fs.promises.copyFile(srcPath, dstPath);
      
      // Make executable on Unix-like systems
      if (process.platform !== 'win32') {
        await fs.promises.chmod(dstPath, 0o755);
      }
      console.log(`   ✓ ${binary} copied successfully`);
    } else {
      throw new Error(`Binary not found: ${srcPath}`);
    }
    
    console.log('✅ Native binaries installed');
    return true;
  } catch (error) {
    // Only log if it's not a module not found error (which is expected)
    if (error.code !== 'MODULE_NOT_FOUND') {
      console.log(`⚠️  Native dependency error: ${error.message}`);
    }
    return false;
  }
}

async function tryDirectDownload() {
  const version = process.env.npm_package_version || 'latest';
  const url = platform.downloadUrl(version);
  const binDir = path.join(__dirname, '..', 'bin');
  
  try {
    console.log('📡 Attempting direct download...');
    await fs.promises.mkdir(binDir, { recursive: true });
    await downloadBinary(url, binDir);
    
    // Make binary executable
    const binary = 'kindlyguard';
    const binaryPath = path.join(binDir, platform.getBinaryName(binary));
    if (fs.existsSync(binaryPath)) {
      if (process.platform !== 'win32') {
        await fs.promises.chmod(binaryPath, 0o755);
      }
      console.log(`   ✓ ${binary} ready`);
    } else {
      throw new Error(`Binary not found after download: ${binaryPath}`);
    }
    
    console.log('✅ Direct download successful');
    return true;
  } catch (error) {
    // For known error types, let them bubble up for proper handling
    if (['NETWORK_ERROR', 'DISK_SPACE', 'DOWNLOAD_NOT_FOUND'].includes(error.message) || 
        error.code === 'ENOSPC' || 
        error.statusCode === 404) {
      throw error;
    }
    
    console.error(`⚠️  Download failed: ${error.message}`);
    return false;
  }
}

async function verifyInstallation() {
  const binPath = platform.getBinaryPath('kindlyguard');
  const validation = platform.validateBinary(binPath);
  
  if (!validation.valid) {
    const error = new Error(validation.error);
    if (validation.error.includes('not found')) {
      error.code = 'ENOENT';
    } else if (validation.error.includes('architecture')) {
      error.code = 'ARCH_MISMATCH';
    }
    throw error;
  }
  
  // Try to run --version to verify it works
  const result = spawnSync(binPath, ['--version'], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  
  if (result.error) {
    const error = new Error(result.error.message);
    error.code = result.error.code;
    error.originalError = result.error;
    
    // Check for common error codes
    if (result.error.code === 'ENOENT') {
      error.message = 'Binary not found';
    } else if (result.error.code === 'EACCES') {
      error.message = 'Permission denied';
    } else if (result.error.code === 'EISDIR') {
      error.message = 'Expected a file but found a directory';
    }
    
    throw error;
  }
  
  if (result.status === 2) {
    const error = new Error('Missing dependencies');
    error.code = 'MISSING_DEPS';
    error.status = result.status;
    error.stderr = result.stderr;
    throw error;
  }
  
  if (result.status !== 0) {
    const error = new Error(`Binary exited with code ${result.status}`);
    error.status = result.status;
    error.stderr = result.stderr;
    throw error;
  }
  
  console.log(`✨ KindlyGuard ${result.stdout.trim()} installed successfully!`);
  return true;
}

function displayErrorHelp(error) {
  console.error('\n❌ Installation failed!\n');
  
  // Handle specific error types with friendly messages
  if (error.code === 'EACCES' || error.message?.includes('Permission denied')) {
    console.error('🔒 Permission Denied');
    console.error('');
    console.error('   KindlyGuard needs permission to install binaries.');
    console.error('');
    console.error('   Try one of these solutions:');
    console.error('   • Run with elevated permissions: sudo npm install -g kindlyguard');
    console.error('   • Install locally instead: npm install kindlyguard');
    console.error('   • Fix npm permissions: https://docs.npmjs.com/resolving-eacces-permissions-errors');
    console.error('');
    console.error('   For more help: https://github.com/kindlyguard/kindlyguard/wiki/Permission-Issues');
    
  } else if (error.code === 'ENOENT' || error.message?.includes('not found')) {
    console.error('🔍 Binary Not Found');
    console.error('');
    console.error('   The KindlyGuard binary could not be found or executed.');
    console.error('');
    console.error('   Possible causes:');
    console.error('   • Download was incomplete or corrupted');
    console.error('   • Antivirus software may have quarantined the file');
    console.error('   • File system permissions issue');
    console.error('');
    console.error('   Try:');
    console.error('   • Clear npm cache: npm cache clean --force');
    console.error('   • Reinstall: npm install kindlyguard --force');
    console.error('   • Manual installation (see below)');
    
  } else if (error.code === 'ARCH_MISMATCH' || error.message?.includes('architecture')) {
    console.error('🖥️  Architecture Mismatch');
    console.error('');
    console.error(`   Your system: ${process.platform} ${process.arch}`);
    console.error('');
    console.error('   KindlyGuard supports:');
    console.error('   • macOS: x64, arm64 (Apple Silicon)');
    console.error('   • Linux: x64, arm64');
    console.error('   • Windows: x64');
    console.error('');
    console.error('   If your platform should be supported, please report:');
    console.error('   https://github.com/kindlyguard/kindlyguard/issues');
    
  } else if (error.code === 'MISSING_DEPS' || error.status === 2) {
    console.error('📦 Missing Dependencies');
    console.error('');
    console.error('   KindlyGuard requires some system libraries to run.');
    console.error('');
    if (error.stderr) {
      console.error('   Error details:', error.stderr.trim());
    }
    console.error('');
    console.error('   On Ubuntu/Debian:');
    console.error('   • sudo apt-get update && sudo apt-get install -y libssl-dev');
    console.error('');
    console.error('   On RHEL/CentOS/Fedora:');
    console.error('   • sudo yum install openssl-devel');
    console.error('');
    console.error('   On macOS:');
    console.error('   • Should work out of the box. Try: xcode-select --install');
    
  } else if (error.code === 'NETWORK_ERROR' || error.message === 'NETWORK_ERROR') {
    console.error('🌐 Network Error');
    console.error('');
    console.error('   Failed to download KindlyGuard binary.');
    console.error('');
    console.error('   Possible causes:');
    console.error('   • No internet connection');
    console.error('   • Firewall blocking GitHub releases');
    console.error('   • Corporate proxy settings');
    console.error('');
    console.error('   Try:');
    console.error('   • Check your internet connection');
    console.error('   • Configure proxy: npm config set proxy http://proxy.company.com:8080');
    console.error('   • Use manual installation (see below)');
    
  } else if (error.code === 'DISK_SPACE' || error.message === 'DISK_SPACE') {
    console.error('💾 Insufficient Disk Space');
    console.error('');
    console.error('   Not enough disk space to install KindlyGuard.');
    console.error('');
    console.error('   KindlyGuard requires approximately 50MB of free space.');
    console.error('');
    console.error('   Try:');
    console.error('   • Free up disk space');
    console.error('   • Clear npm cache: npm cache clean --force');
    console.error('   • Install to a different location');
    
  } else if (error.message === 'DOWNLOAD_NOT_FOUND' || error.statusCode === 404) {
    console.error('⚠️  Download Not Found');
    console.error('');
    console.error('   The requested KindlyGuard version could not be found.');
    console.error('');
    console.error('   This might happen if:');
    console.error('   • The version is too new and binaries aren\'t released yet');
    console.error('   • The version number is incorrect');
    console.error('');
    console.error('   Try:');
    console.error('   • Install the latest stable version: npm install kindlyguard@latest');
    console.error('   • Check available versions: npm view kindlyguard versions');
    
  } else {
    console.error('⚠️  Unexpected Error');
    console.error('');
    console.error('   Error:', error.message || error);
    if (error.stderr) {
      console.error('   Details:', error.stderr.trim());
    }
    console.error('');
    console.error('   Please report this issue:');
    console.error('   https://github.com/kindlyguard/kindlyguard/issues');
  }
  
  console.error('');
  console.error('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.error('');
  console.error('📋 Alternative Solutions:');
  console.error('');
  console.error('1. Skip automatic download:');
  console.error('   KINDLYGUARD_SKIP_DOWNLOAD=1 npm install kindlyguard');
  console.error('');
  console.error('2. Manual installation:');
  console.error(`   • Download from: ${platform.downloadUrl()}`);
  console.error(`   • Extract to: ${path.join(__dirname, '..', 'bin')}`);
  console.error('   • Make executable: chmod +x bin/kindlyguard*');
  console.error('');
  console.error('3. Build from source:');
  console.error('   • git clone https://github.com/kindlyguard/kindlyguard');
  console.error('   • cd kindlyguard && cargo build --release');
  console.error('');
  console.error('📚 Documentation: https://kindlyguard.dev/docs/installation');
  console.error('💬 Discord: https://discord.gg/kindlyguard');
  console.error('🐛 Issues: https://github.com/kindlyguard/kindlyguard/issues');
  console.error('');
}

async function main() {
  try {
    console.log(`🚀 Installing KindlyGuard for ${platform.getPlatformKey()}...\n`);
    
    // Try native dependency first
    let installed = await tryNativeDependency();
    
    // Fall back to direct download
    if (!installed && !process.env.KINDLYGUARD_SKIP_DOWNLOAD) {
      try {
        installed = await tryDirectDownload();
      } catch (downloadError) {
        // Re-throw known errors for proper handling
        throw downloadError;
      }
    }
    
    if (!installed) {
      throw new Error('Failed to install KindlyGuard binary');
    }
    
    // Verify installation
    await verifyInstallation();
    
    console.log('\n🎉 Installation complete!\n');
    console.log('📖 Quick Start:');
    console.log('   kindlyguard --help              # Show all available commands');
    console.log('   kindlyguard server --stdio      # Run as MCP server');
    console.log('   kindlyguard scan <file>         # Scan a file for threats');
    console.log('   kindlyguard install claude      # Set up Claude Desktop integration\n');
    console.log('🔧 Claude Desktop Integration:');
    console.log('   Add this to your Claude Desktop config:\n');
    console.log(JSON.stringify({
      mcpServers: {
        "kindlyguard": {
          command: "npx",
          args: ["kindlyguard", "server", "--stdio"]
        }
      }
    }, null, 2));
    console.log('\n✨ Happy coding with KindlyGuard!\n');
    
  } catch (error) {
    displayErrorHelp(error);
    process.exit(1);
  }
}

// Only run if called directly
if (require.main === module) {
  main();
}