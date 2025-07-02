# KindlyGuard Startup Scripts

This directory contains convenient startup scripts for managing the KindlyGuard ecosystem.

## Available Scripts

### 🚀 `start-all.sh`
Starts all KindlyGuard components in production mode:
- Builds components if needed
- Starts the server with stdio transport
- Starts the Shield app
- Runs basic connectivity tests
- Shows status of all components

**Usage:**
```bash
./start-all.sh
```

### 🛠️ `start-dev.sh`
Starts all components in development mode with enhanced debugging:
- Opens separate terminals for each component (if supported)
- Enables debug logging
- Starts Shield with hot-reload
- Opens a monitor terminal for real-time statistics

**Usage:**
```bash
./start-dev.sh
```

**Note:** This script attempts to detect your terminal emulator and open new windows/tabs. Supported terminals:
- macOS: Terminal.app
- Linux: gnome-terminal, konsole, xterm, kitty, alacritty

### 🛑 `stop-all.sh`
Cleanly shuts down all running KindlyGuard components:
- Gracefully stops the Shield app
- Stops the server
- Cleans up any monitoring processes
- Rotates large log files

**Usage:**
```bash
./stop-all.sh
```

### 📊 `status.sh`
Shows the current status of all components:
- Process status and PIDs
- Port availability
- Log file sizes
- System resource usage
- Health checks

**Usage:**
```bash
./status.sh
```

## Quick Start

1. **First Time Setup:**
   ```bash
   # Make scripts executable (only needed once)
   chmod +x *.sh
   
   # Start in production mode
   ./start-all.sh
   ```

2. **Development:**
   ```bash
   # Start with debug output in separate terminals
   ./start-dev.sh
   ```

3. **Check Status:**
   ```bash
   # See what's running
   ./status.sh
   ```

4. **Stop Everything:**
   ```bash
   # Clean shutdown
   ./stop-all.sh
   ```

## Log Files

The scripts create the following log files in the root directory:
- `kindly-guard.log` - Server logs (production)
- `kindly-guard-shield.log` - Shield app logs (production)
- `kindly-guard-dev.log` - Server logs (development)
- `kindly-guard-shield-dev.log` - Shield app logs (development)

View logs in real-time:
```bash
# Server logs
tail -f kindly-guard.log

# Shield logs
tail -f kindly-guard-shield.log

# All logs
tail -f kindly-guard*.log
```

## Troubleshooting

### Components won't start
1. Check if binaries are built: `./status.sh`
2. Build if needed:
   ```bash
   cargo build --release
   cd kindly-guard-shield && npm install && npm run tauri build
   ```

### Port already in use
The Shield app uses port 9100. Check what's using it:
```bash
lsof -i:9100
```

### Development mode doesn't open terminals
The script will fall back to background processes if it can't detect your terminal.
Check the log files instead:
```bash
tail -f kindly-guard-dev.log
tail -f kindly-guard-shield-dev.log
```

### Scripts don't have permission
Make them executable:
```bash
chmod +x *.sh
```

## Configuration

The scripts use default configuration. To customize:

1. Copy the example config:
   ```bash
   cp kindly-guard.toml.example kindly-guard.toml
   ```

2. Edit `kindly-guard.toml` with your settings

3. The scripts will automatically use your custom configuration

## Process Management

The scripts create PID files for tracking:
- `.kindly-guard-server.pid` - Server process ID
- `.kindly-guard-shield.pid` - Shield process ID

These are automatically cleaned up by `stop-all.sh`.

## Integration with System Services

For production deployments, consider using the systemd service instead:
```bash
cd systemd
sudo ./install.sh
sudo systemctl start kindly-guard
```

The startup scripts are best for development and testing.