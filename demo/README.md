# KindlyGuard Demo Showcase

This directory contains everything needed to demonstrate KindlyGuard's powerful security features.

## Quick Start

Run the main showcase script:

```bash
./showcase.sh
```

This interactive demo will guide you through all of KindlyGuard's features.

## Demo Contents

### 1. Main Showcase Script
- `showcase.sh` - Interactive demo that shows all features

### 2. Configuration Files
- `standard-demo.toml` - Standard mode configuration (blue shield)
- `enhanced-demo.toml` - Enhanced mode configuration (purple shield)

### 3. Threat Samples
- `threats/unicode-attacks.json` - Unicode-based security threats
- `threats/injection-attacks.json` - SQL, XSS, and command injection samples  
- `threats/mixed-threats.json` - Complex multi-vector attacks

### 4. Test Scripts
- `test_unicode_threat.py` - Demonstrates unicode attack detection
- `test_injection_threat.py` - Shows SQL injection blocking
- `test_xss_threat.py` - Tests XSS prevention
- `simulate_threats.py` - Generates threat stream for UI demo

### 5. Test Data
- `test-small.json` - 1KB file for performance testing
- `test-medium.json` - 10KB file with mixed content
- `test-large.json` - 100KB file for stress testing

### 6. Documentation
- `video-script.md` - Script for creating demo video
- `screenshots-guide.md` - Guide for capturing screenshots

## Running Individual Demos

### Unicode Attack Detection
```bash
# Start server
../target/release/kindly-guard serve --config standard-demo.toml &

# Test unicode threats
python3 test_unicode_threat.py
```

### Enhanced Mode Performance
```bash
# Start in enhanced mode
../target/release/kindly-guard serve --config enhanced-demo.toml &

# Run performance test
../target/release/kindly-guard scan test-medium.json
```

### Shield UI Demo
```bash
# Build and run shield
cd ../kindly-guard-shield
cargo build --release
./target/release/kindly-guard-shield &

# Simulate threats
cd ../demo
python3 simulate_threats.py
```

## Creating Demo Content

### Recording Video
1. Follow the script in `video-script.md`
2. Use OBS or similar for recording
3. Keep demos under 4 minutes
4. Focus on visual impact

### Taking Screenshots
1. Follow `screenshots-guide.md`
2. Use consistent styling
3. Highlight important features
4. Organize in `screenshots/` directory

### Live Presentations
1. Run `showcase.sh` for guided demo
2. Have terminal and shield UI ready
3. Prepare threat examples
4. Show performance differences

## Key Talking Points

### Security Features
- Real-time threat detection
- Zero false positives
- Automatic neutralization
- Comprehensive threat coverage

### Performance
- Standard mode: Good performance for most use cases
- Enhanced mode: 10x faster with advanced algorithms
- Minimal resource usage
- Scales to high-volume applications

### Integration
- Easy Claude AI integration
- Works with any MCP client
- Simple configuration
- No code changes required

### User Experience
- Beautiful shield UI
- Real-time notifications  
- Detailed analytics
- System tray integration

## Troubleshooting

### Server won't start
```bash
# Check if already running
ps aux | grep kindly-guard
# Kill if needed
pkill kindly-guard
```

### Shield UI not showing
```bash
# Ensure built first
cd ../kindly-guard-shield
cargo build --release
```

### Tests failing
```bash
# Ensure server is running
../target/release/kindly-guard serve &
# Check logs
RUST_LOG=debug ../target/release/kindly-guard serve
```

## Customization

Feel free to modify the demo for your audience:
- Add specific threat examples relevant to your use case
- Adjust timing in scripts
- Create custom configurations
- Add your own test data

## Support

For questions or issues with the demo:
1. Check the main documentation
2. Review error messages carefully
3. Enable debug logging
4. Open an issue on GitHub

Happy demonstrating! 🛡️