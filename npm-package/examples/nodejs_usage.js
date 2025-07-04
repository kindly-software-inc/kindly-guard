/**
 * Example: Using KindlyGuard as an MCP server in Node.js
 */

const kindlyguard = require('@kindlyguard/kindlyguard');

// Example 1: Start MCP server programmatically
async function startMCPServer() {
  const server = kindlyguard.create({
    stdio: true,
    logLevel: 'debug'
  });
  
  const mcp = server.start();
  
  // Send a message to the server
  mcp.send({
    jsonrpc: "2.0",
    method: "initialize",
    params: {
      protocolVersion: "0.1.0",
      capabilities: {}
    },
    id: 1
  });
  
  // Listen for responses
  mcp.onMessage((message) => {
    console.log('Received:', message);
  });
  
  // Graceful shutdown
  process.on('SIGINT', () => {
    server.stop();
    process.exit(0);
  });
}

// Example 2: Quick threat scanning
async function scanExample() {
  // Scan text for threats
  const textResult = await kindlyguard.scan(
    "Check this text\u202Efor hidden threats",
    { format: 'json' }
  );
  
  console.log('Text scan result:', textResult);
  
  // Scan a file
  const fileResult = await kindlyguard.scan(
    './suspicious.json',
    { file: true, format: 'json' }
  );
  
  console.log('File scan result:', fileResult);
}

// Example 3: Custom server with event handling
async function customServer() {
  const server = kindlyguard.create({
    stdio: false,
    shield: true,
    config: './custom-config.toml',
    onError: (error) => {
      console.error('Server error:', error);
    },
    onExit: (code, signal) => {
      console.log(`Server exited with code ${code}, signal ${signal}`);
    }
  });
  
  const process = server.start();
  
  // Check server status
  setTimeout(async () => {
    const status = await server.status();
    console.log('Server status:', status);
  }, 1000);
  
  // Stop after 10 seconds
  setTimeout(() => {
    console.log('Stopping server...');
    server.stop();
  }, 10000);
}

// Run examples based on command line argument
const example = process.argv[2];

switch (example) {
  case 'mcp':
    startMCPServer();
    break;
  case 'scan':
    scanExample();
    break;
  case 'custom':
    customServer();
    break;
  default:
    console.log(`
Usage: node nodejs_usage.js <example>

Examples:
  mcp     - Start MCP server with stdio
  scan    - Demonstrate threat scanning
  custom  - Custom server with events

Example:
  node nodejs_usage.js mcp
`);
}