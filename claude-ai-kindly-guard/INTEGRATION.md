# KindlyGuard Extension Integration Guide

## WebSocket Protocol

The extension connects to the KindlyGuard shield app via WebSocket at `ws://localhost:7890/shield`.

### Message Format

#### From Extension to Shield App

```json
{
  "type": "scan",
  "text": "Text content to scan",
  "tabId": 123
}
```

#### From Shield App to Extension

```json
{
  "status": "active|idle|scanning",
  "mode": "standard|enhanced",
  "stats": {
    "scanned": 1234,
    "blocked": 56,
    "threats": [
      {
        "type": "unicode|injection|xss|prompt|encoding",
        "timestamp": "2024-01-01T12:00:00Z",
        "severity": "low|medium|high|critical",
        "details": "Optional threat details"
      }
    ]
  }
}
```

## Shield App WebSocket Endpoint

To integrate with the extension, the shield app needs to implement:

```rust
// In shield app's main.rs or server module
use warp::{ws::WebSocket, Filter};

pub fn shield_websocket() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("shield")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| {
            ws.on_upgrade(|websocket| handle_shield_connection(websocket))
        })
}

async fn handle_shield_connection(ws: WebSocket) {
    // Handle incoming messages from extension
    // Send periodic updates about shield status
}
```

## Testing the Extension

### Manual Testing

1. Load extension in Chrome developer mode
2. Start the shield app with WebSocket server
3. Navigate to claude.ai
4. Verify shield widget appears
5. Type text and check for real-time scanning

### Automated Testing

```javascript
// Example test for shield visibility
describe('KindlyGuard Extension', () => {
  it('should show shield on claude.ai', async () => {
    await browser.url('https://claude.ai');
    await browser.pause(1000); // Wait for injection
    
    const shield = await browser.$('#kindlyguard-shield');
    expect(await shield.isDisplayed()).toBe(true);
  });
});
```

## Design Decisions

### Why Manifest V3?
- Future-proof (V2 being phased out)
- Better security model
- Service workers instead of background pages

### Why WebSocket?
- Real-time bidirectional communication
- Low latency for threat detection
- Persistent connection for continuous monitoring

### Why Inject Script?
- Intercept fetch/XHR calls at page level
- Access to page's JavaScript context
- Monitor all API communications

## Performance Considerations

- Content script is lightweight (~10KB)
- CSS animations use GPU acceleration
- WebSocket reconnection uses exponential backoff
- No blocking operations in content script

## Security Considerations

- WebSocket restricted to localhost only
- No external server communication
- Content Security Policy compliant
- No eval() or dynamic code execution
- Minimal permissions requested

## Future Enhancements

1. **Firefox Support**: Adapt for Firefox's WebExtension APIs
2. **Threat Visualization**: D3.js-based threat timeline
3. **Keyboard Shortcuts**: Quick toggle protection modes
4. **Multi-tab Support**: Separate stats per tab
5. **Export Functionality**: Save threat reports