# KindlyGuard NPM Package Structure

This document provides a quick reference for the npm package structure that has been set up for binary distribution, following best practices from packages like esbuild and swc.

## Package Structure

```
npm-package/
├── package.json              # Main package configuration
├── lib/
│   ├── main.js              # Main Node.js API wrapper
│   ├── main.d.ts            # TypeScript definitions
│   ├── platform.js          # Platform detection utilities
│   └── postinstall.js       # Binary download/installation script
├── bin/
│   ├── kindlyguard          # CLI wrapper script
│   └── kindlyguard-cli      # CLI tool wrapper script
├── scripts/
│   └── build-platform-packages.js  # Build script for platform packages
├── npm/                     # Platform-specific packages
│   ├── kindlyguard-linux-x64/
│   ├── kindlyguard-darwin-x64/
│   ├── kindlyguard-darwin-arm64/
│   └── kindlyguard-win32-x64/
└── test-package.js          # Package test suite
```

## Key Features

### 1. Binary Distribution
- Separate npm packages for each platform (@kindlyguard/linux-x64, etc.)
- Optional dependencies in main package
- Automatic fallback to GitHub releases if platform package unavailable

### 2. Platform Detection
- Automatic detection of OS and architecture
- Support for Linux, macOS (Intel & ARM), and Windows
- Musl libc detection for Alpine Linux compatibility

### 3. Installation Flow
1. User installs `kindlyguard` package
2. npm tries to install optional platform-specific dependency
3. `postinstall.js` runs to:
   - Copy binaries from platform package (if available)
   - OR download from GitHub releases
   - Validate binary is executable

### 4. API Design
- CommonJS and ES module compatible
- TypeScript definitions included
- Both programmatic API and CLI usage supported

## Usage Examples

### Programmatic API
```javascript
const kindlyguard = require('kindlyguard');

// Start MCP server
const server = kindlyguard.startServer({ stdio: true });

// Scan text
const results = await kindlyguard.scan('suspicious text', { format: 'json' });

// Create instance with options
const kg = kindlyguard({ logLevel: 'debug' });
await kg.start();
```

### CLI Usage
```bash
# Start as MCP server
kindlyguard --stdio

# Scan a file
kindlyguard-cli scan file.txt --format json

# Check status
kindlyguard-cli status
```

## Building and Publishing

### Build Platform Packages
```bash
npm run build-platform-packages
```

### Publish All Packages
```bash
npm run publish-all
```

## Environment Variables

- `KINDLYGUARD_SKIP_DOWNLOAD` - Skip binary download
- `KINDLYGUARD_DOWNLOAD_BASE` - Custom download URL
- `CI` - Skip install in CI environments

## Testing

Run the test suite:
```bash
npm test
```

This validates:
- Platform detection
- Binary validation
- API interface
- TypeScript definitions
- Basic functionality (if binary available)