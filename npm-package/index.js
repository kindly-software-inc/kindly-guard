/**
 * KindlyGuard - Security-focused MCP server for AI protection
 * 
 * Protects against unicode attacks, injection threats, and other AI vulnerabilities
 * Visit https://github.com/samduchaine/kindly-guard for more information.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class KindlyGuard {
  constructor(options = {}) {
    this.options = {
      stdio: true,
      config: null,
      shield: false,
      logLevel: 'info',
      ...options
    };
    
    this.serverProcess = null;
    this.binPath = this._findBinary('kindlyguard');
  }
  
  _findBinary(name) {
    const binDir = path.join(__dirname, 'bin');
    const candidates = [
      path.join(binDir, name),
      path.join(binDir, `${name}.exe`),
      path.join(binDir, `${name}.bin`)
    ];
    
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    
    throw new Error(`KindlyGuard binary not found. Run 'npm install' to complete installation.`);
  }
  
  /**
   * Start the KindlyGuard MCP server
   */
  start() {
    if (this.serverProcess) {
      throw new Error('Server is already running');
    }
    
    const args = [];
    
    if (this.options.stdio) {
      args.push('--stdio');
    }
    
    if (this.options.config) {
      args.push('--config', this.options.config);
    }
    
    if (this.options.shield) {
      args.push('--shield');
    }
    
    const env = {
      ...process.env,
      RUST_LOG: this.options.logLevel
    };
    
    this.serverProcess = spawn(this.binPath, args, {
      stdio: this.options.stdio ? 'pipe' : 'inherit',
      env
    });
    
    this.serverProcess.on('error', (error) => {
      console.error('Failed to start KindlyGuard server:', error);
    });
    
    this.serverProcess.on('exit', (code, signal) => {
      this.serverProcess = null;
      if (code !== 0) {
        console.error(`KindlyGuard server exited with code ${code}`);
      }
    });
    
    return this.serverProcess;
  }
  
  /**
   * Stop the KindlyGuard server
   */
  stop() {
    if (this.serverProcess) {
      this.serverProcess.kill();
      this.serverProcess = null;
    }
  }
  
  /**
   * Get server status
   */
  async status() {
    const { spawnSync } = require('child_process');
    const result = spawnSync(this.binPath, ['status'], {
      encoding: 'utf8'
    });
    
    if (result.error) {
      throw result.error;
    }
    
    return {
      exitCode: result.status,
      stdout: result.stdout,
      stderr: result.stderr
    };
  }
  
  /**
   * Scan text or file for threats
   */
  async scan(input, options = {}) {
    const { spawnSync } = require('child_process');
    const args = ['scan'];
    
    if (options.file) {
      args.push('--file', input);
    } else {
      args.push('--text', input);
    }
    
    if (options.format) {
      args.push('--format', options.format);
    }
    
    const result = spawnSync(this.binPath, args, {
      encoding: 'utf8'
    });
    
    if (result.error) {
      throw result.error;
    }
    
    if (options.format === 'json' && result.stdout) {
      try {
        return JSON.parse(result.stdout);
      } catch (e) {
        return result.stdout;
      }
    }
    
    return {
      exitCode: result.status,
      stdout: result.stdout,
      stderr: result.stderr
    };
  }
}

// Convenience methods
const kindlyguard = {
  // Create a new instance
  create: (options) => new KindlyGuard(options),
  
  // Quick scan
  scan: async (input, options) => {
    const instance = new KindlyGuard();
    return instance.scan(input, options);
  },
  
  // Start server with default options
  startServer: (options) => {
    const instance = new KindlyGuard(options);
    return instance.start();
  },
  
  // Export the class for advanced usage
  KindlyGuard
};

module.exports = kindlyguard;