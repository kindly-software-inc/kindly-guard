/**
 * KindlyGuard - Security-focused MCP server for AI protection
 * 
 * Protects against unicode attacks, injection threats, and other AI vulnerabilities
 * Visit https://github.com/samduchaine/kindly-guard for more information.
 */

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const platform = require('./platform');

class KindlyGuard {
  constructor(options = {}) {
    this.options = {
      stdio: true,
      config: null,
      shield: false,
      logLevel: 'info',
      timeout: 30000,
      ...options
    };
    
    this.serverProcess = null;
    this.binPath = this._findBinary();
  }
  
  _findBinary() {
    const binaryName = 'kindlyguard';
    const binaryPath = platform.getBinaryPath(binaryName);
    
    const validation = platform.validateBinary(binaryPath);
    if (!validation.valid) {
      throw new Error(
        `KindlyGuard binary not found at ${binaryPath}. ` +
        `${validation.error}. ` +
        `Run 'npm install' to complete installation.`
      );
    }
    
    return binaryPath;
  }
  
  /**
   * Start the KindlyGuard MCP server
   * @returns {ChildProcess} The spawned server process
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
      RUST_LOG: this.options.logLevel === 'debug' ? 'kindly_guard=debug' : 'kindly_guard=info'
    };
    
    this.serverProcess = spawn(this.binPath, args, {
      stdio: this.options.stdio ? 'pipe' : 'inherit',
      env
    });
    
    this.serverProcess.on('error', (error) => {
      console.error('Failed to start KindlyGuard server:', error);
      this.serverProcess = null;
    });
    
    this.serverProcess.on('exit', (code, signal) => {
      this.serverProcess = null;
      if (code !== 0 && code !== null) {
        console.error(`KindlyGuard server exited with code ${code}`);
      }
    });
    
    // Handle stdio if enabled
    if (this.options.stdio && this.serverProcess.stdin && this.serverProcess.stdout) {
      process.stdin.pipe(this.serverProcess.stdin);
      this.serverProcess.stdout.pipe(process.stdout);
      this.serverProcess.stderr.pipe(process.stderr);
    }
    
    return this.serverProcess;
  }
  
  /**
   * Stop the KindlyGuard server gracefully
   * @param {number} timeout - Milliseconds to wait before force killing
   */
  async stop(timeout = 5000) {
    if (!this.serverProcess) {
      return;
    }
    
    return new Promise((resolve) => {
      let timeoutId = null;
      
      this.serverProcess.once('exit', () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        this.serverProcess = null;
        resolve();
      });
      
      // Try graceful shutdown first
      this.serverProcess.kill('SIGTERM');
      
      // Force kill after timeout
      timeoutId = setTimeout(() => {
        if (this.serverProcess) {
          this.serverProcess.kill('SIGKILL');
        }
      }, timeout);
    });
  }
  
  /**
   * Get server status and statistics
   * @returns {Promise<Object>} Status information
   */
  async status() {
    const result = spawnSync(this.binPath, ['status', '--json'], {
      encoding: 'utf8',
      timeout: this.options.timeout
    });
    
    if (result.error) {
      throw result.error;
    }
    
    if (result.status !== 0) {
      throw new Error(`Status command failed: ${result.stderr || result.stdout}`);
    }
    
    try {
      return JSON.parse(result.stdout);
    } catch (e) {
      return {
        exitCode: result.status,
        stdout: result.stdout,
        stderr: result.stderr
      };
    }
  }
  
  /**
   * Scan text or file for threats
   * @param {string} input - Text to scan or file path
   * @param {Object} options - Scan options
   * @returns {Promise<Object>} Scan results
   */
  async scan(input, options = {}) {
    const args = ['scan'];
    
    if (options.file) {
      args.push('--file', input);
    } else {
      args.push('--text', input);
    }
    
    if (options.format) {
      args.push('--format', options.format);
    }
    
    if (options.detailed) {
      args.push('--detailed');
    }
    
    const result = spawnSync(this.binPath, args, {
      encoding: 'utf8',
      timeout: this.options.timeout,
      maxBuffer: 10 * 1024 * 1024 // 10MB
    });
    
    if (result.error) {
      throw result.error;
    }
    
    if (result.status !== 0 && result.status !== 1) { // Exit code 1 means threats found
      throw new Error(`Scan failed: ${result.stderr || result.stdout}`);
    }
    
    if (options.format === 'json' && result.stdout) {
      try {
        // Extract just the JSON part - look for complete JSON object
        // The JSON ends at the first } that closes the root object
        let braceCount = 0;
        let inString = false;
        let escapeNext = false;
        let jsonEnd = -1;
        
        for (let i = 0; i < result.stdout.length; i++) {
          const char = result.stdout[i];
          
          if (escapeNext) {
            escapeNext = false;
            continue;
          }
          
          if (char === '\\') {
            escapeNext = true;
            continue;
          }
          
          if (char === '"' && !escapeNext) {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') braceCount++;
            else if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                jsonEnd = i + 1;
                break;
              }
            }
          }
        }
        
        if (jsonEnd > 0) {
          const jsonStr = result.stdout.substring(0, jsonEnd);
          return JSON.parse(jsonStr);
        }
        
        // Fallback to parsing the whole output
        return JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(`Failed to parse scan results: ${e.message}`);
      }
    }
    
    return {
      exitCode: result.status,
      threatsFound: result.status === 1,
      stdout: result.stdout,
      stderr: result.stderr
    };
  }
  
  /**
   * Get binary version information
   * @returns {Promise<string>} Version string
   */
  async version() {
    const result = spawnSync(this.binPath, ['--version'], {
      encoding: 'utf8',
      timeout: 5000
    });
    
    if (result.error) {
      throw result.error;
    }
    
    return result.stdout.trim();
  }
}

// Factory function for creating instances
function createKindlyGuard(options) {
  return new KindlyGuard(options);
}

// Quick scan helper
async function scan(input, options) {
  const instance = new KindlyGuard();
  return instance.scan(input, options);
}

// Start server helper
function startServer(options) {
  const instance = new KindlyGuard(options);
  return instance.start();
}

// Export both CommonJS and ES module compatible interface
module.exports = createKindlyGuard;
module.exports.KindlyGuard = KindlyGuard;
module.exports.createKindlyGuard = createKindlyGuard;
module.exports.scan = scan;
module.exports.startServer = startServer;
module.exports.default = createKindlyGuard;

// Platform utilities for advanced usage
module.exports.platform = platform;