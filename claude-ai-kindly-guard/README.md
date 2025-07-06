# KindlyGuard for Claude.ai

A browser extension that integrates KindlyGuard's real-time security shield directly into the Claude.ai interface, providing protection against unicode attacks, injection attempts, and other security threats.

## Features

- **Real-time Protection**: Monitors all text input and API calls to Claude.ai
- **Non-intrusive UI**: Floating shield widget that matches Claude's design language
- **Live Statistics**: Track scanned messages and blocked threats
- **WebSocket Integration**: Connects to local KindlyGuard shield app for enhanced protection
- **Visual Indicators**: Highlights potential threats directly in the interface
- **Enhanced Mode**: Purple glow indicates when advanced protection is active

## Installation

### From Source

1. Clone this repository or download the extension files
2. Open Chrome/Edge and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the `claude-ai-kindlyguard` directory
5. The extension icon should appear in your toolbar

### Prerequisites

- KindlyGuard shield app running locally on `ws://localhost:7890`
- Chrome, Edge, or any Chromium-based browser (Firefox support coming soon)

## Usage

1. **Automatic Protection**: Once installed, the extension automatically activates on claude.ai
2. **Shield Widget**: Look for the purple shield icon in the bottom-right corner
3. **Click to Expand**: Click the shield to view detailed statistics and recent threats
4. **Connection Status**: Green indicator shows active protection, red means disconnected

## Extension Architecture

```
claude-ai-kindlyguard/
├── manifest.json          # Extension manifest (v3)
├── src/
│   ├── background.js      # Service worker for WebSocket management
│   ├── content.js         # Main content script for UI injection
│   ├── inject.js          # Page context script for API interception
│   └── ui/
│       ├── shield.css     # Shield widget styles
│       ├── popup.html     # Extension popup
│       ├── popup.css      # Popup styles
│       └── popup.js       # Popup functionality
└── assets/               # Extension icons
```

## Security & Privacy

- **Local Only**: Connects only to localhost WebSocket (no external servers)
- **No Data Collection**: The extension doesn't collect or transmit any user data
- **Minimal Permissions**: Only requests access to claude.ai
- **Open Source**: Full source code available for security audit

## Configuration

The extension respects your KindlyGuard shield app configuration:
- Standard vs Enhanced mode
- Threat detection sensitivity
- Custom threat patterns

## Browser Compatibility

- ✅ Chrome/Chromium (v88+)
- ✅ Microsoft Edge
- ✅ Brave Browser
- ✅ Opera
- 🚧 Firefox (in development)
- 🚧 Safari (planned)

## Development

### Building from Source

```bash
# No build step required for basic version
# For production, consider minifying:
npm install -g terser clean-css-cli
terser src/background.js -o dist/background.js
terser src/content.js -o dist/content.js
terser src/inject.js -o dist/inject.js
cleancss src/ui/shield.css -o dist/ui/shield.css
```

### Testing

1. Load the extension in developer mode
2. Navigate to claude.ai
3. Open DevTools and check for any console errors
4. Verify the shield widget appears and connects

## Troubleshooting

### Shield Not Appearing
- Ensure you're on claude.ai (not a different domain)
- Check if the extension is enabled in chrome://extensions/
- Reload the claude.ai page

### Connection Failed
- Verify KindlyGuard shield app is running on port 7890
- Check browser console for WebSocket errors
- Try clicking "Reconnect" in the shield widget

### Performance Issues
- The extension is designed to be lightweight
- If you experience slowdowns, check if enhanced mode is causing it
- Report issues with specific reproduction steps

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Follow the existing code style
4. Test thoroughly on claude.ai
5. Submit a pull request

## License

This extension is part of the KindlyGuard project and follows the same license terms.

## Support

- GitHub Issues: [Report bugs or request features]
- Documentation: [Full KindlyGuard documentation]
- Community: [Join our Discord server]