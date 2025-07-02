# KindlyGuard Extension for Claude Code

Real-time security monitoring integration for Claude Code, connecting to the KindlyGuard shield app.

## Features

- **Auto-discovery**: Automatically connects to shield app on port 9955
- **Real-time monitoring**: Live threat notifications and statistics
- **Floating widget**: Unobtrusive security status display
- **Keyboard shortcuts**: Quick toggle with Ctrl+Shift+S (Cmd+Shift+S on Mac)
- **Threat notifications**: Configurable alert levels (all/threats/critical)

## Installation

1. Ensure the KindlyGuard shield app is running
2. Install this extension in Claude Code
3. The extension will auto-connect on startup

## Usage

### Commands

- **Toggle Security Shield** (`Ctrl+Shift+S`): Show/hide the security widget
- **Show Security Details**: Open detailed security panel

### Widget

The floating widget displays:
- Connection status
- Current security mode (active/passive/learning)
- Threat statistics
- Quick access to details

### Notifications

When threats are detected, you'll see toast notifications with:
- Threat type and severity
- Brief description
- Option to view details

## Configuration

Configure in Claude Code settings:

```json
{
  "kindlyguard.autoConnect": true,
  "kindlyguard.notificationLevel": "threats",
  "kindlyguard.shieldPort": 9955
}
```

## Architecture

```
Extension (TypeScript)
    ↓
WebSocket Client
    ↓
Shield App (localhost:9955)
    ↓
KindlyGuard MCP Server
```

## Development

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch mode
npm run watch
```

## Security

- All communication is local (localhost only)
- No external network requests
- Threats are handled in real-time
- No data persistence in extension