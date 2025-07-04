# KindlyGuard Shield

A secure Tauri-based system tray application that displays real-time security threats detected by KindlyGuard.

## Architecture

### Security-First Design

1. **Minimal Attack Surface**
   - No unsafe code (`#![forbid(unsafe_code)]`)
   - Strict CSP headers
   - IPC allowlist
   - All inputs validated

2. **Defense in Depth**
   - Message validation layer
   - Rate limiting
   - Replay attack protection
   - Pattern detection

3. **Secure Communication**
   - WebSocket for Claude Code integration
   - All messages validated and sanitized
   - Constant-time security comparisons

## Project Structure

```
kindly-guard-shield/
├── src-tauri/          # Rust backend
│   ├── src/
│   │   ├── main.rs     # Application entry point
│   │   ├── tray.rs     # System tray management
│   │   ├── ipc/        # Secure IPC handlers
│   │   ├── core/       # Core threat management
│   │   ├── websocket/  # Claude Code server
│   │   └── security/   # Security validation
│   └── Cargo.toml
├── src/                # Minimal frontend
│   ├── index.html      # Main UI
│   ├── shield.ts       # TypeScript logic
│   └── styles/         # CSS styling
└── tauri.conf.json     # Tauri configuration
```

## Building

### Prerequisites

1. Install Rust: https://rustup.rs/
2. Install Node.js: https://nodejs.org/
3. Install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install libwebkit2gtk-4.1-dev \
     build-essential \
     curl \
     wget \
     file \
     libxdo-dev \
     libssl-dev \
     libayatana-appindicator3-dev \
     librsvg2-dev

   # macOS
   xcode-select --install

   # Windows
   # Install Visual Studio Build Tools
   ```

### Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev
```

### Production Build

```bash
# Build with security profile
cd src-tauri
cargo build --profile=secure

# Build Tauri app
cd ..
npm run build
```

## Security Features

### Input Validation
- All IPC messages validated
- JSON schema validation
- Size limits enforced
- Pattern detection for malicious content

### Rate Limiting
- Configurable per-minute limits
- Per-connection tracking
- Automatic throttling

### Threat Detection
- Unicode attack detection
- Injection pattern matching
- Path traversal prevention
- Replay attack protection

## Configuration

The application can be configured through environment variables:

- `RUST_LOG`: Set logging level (default: `kindly_guard_shield=debug`)
- `SHIELD_WS_PORT`: WebSocket server port (default: 9955)
- `SHIELD_RATE_LIMIT`: Requests per minute (default: 60)

## WebSocket API

The shield exposes a WebSocket server for Claude Code integration:

### Commands

```json
// Subscribe to threat updates
{ "type": "subscribe" }

// Get current status
{ "type": "get_status" }

// Toggle protection
{ "type": "toggle_protection" }
```

### Messages

```json
// Threat notification
{
  "type": "threat",
  "threats": [{
    "id": "threat_123",
    "threat_type": "UnicodeInvisible",
    "severity": "High",
    "source": "claude-code",
    "details": "Invisible character detected",
    "timestamp": "2024-01-01T00:00:00Z",
    "blocked": true
  }]
}

// Status update
{
  "type": "status",
  "protection_enabled": true,
  "threats_blocked": 42
}
```

## System Tray Menu

- **Show Shield**: Display the main window
- **Toggle Protection**: Enable/disable protection
- **View Statistics**: Show threat statistics
- **About**: Application information
- **Quit**: Exit the application

## License

Private and confidential. Part of the KindlyGuard security suite.