# KindlyGuard Systemd Service

This directory contains systemd service files and installation scripts for running KindlyGuard as a system service.

## Quick Start

### System-wide Installation (requires root)

```bash
sudo ./install.sh
sudo systemctl start kindly-guard
sudo systemctl enable kindly-guard  # To start at boot
```

### User Installation (no root required)

```bash
./install.sh
systemctl --user start kindly-guard
systemctl --user enable kindly-guard  # To start at login
```

## Files

- `kindly-guard.service` - System service unit file
- `kindly-guard.socket` - Socket activation unit (for on-demand startup)
- `kindly-guard-user.service` - User service unit file
- `install.sh` - Installation script (detects root/user mode)
- `uninstall.sh` - Uninstallation script

## Service Management

### System Service Commands

```bash
# Start/stop/restart
sudo systemctl start kindly-guard
sudo systemctl stop kindly-guard
sudo systemctl restart kindly-guard

# Enable/disable autostart
sudo systemctl enable kindly-guard
sudo systemctl disable kindly-guard

# Check status
sudo systemctl status kindly-guard

# View logs
sudo journalctl -u kindly-guard -f
```

### User Service Commands

```bash
# Start/stop/restart
systemctl --user start kindly-guard
systemctl --user stop kindly-guard
systemctl --user restart kindly-guard

# Enable/disable autostart
systemctl --user enable kindly-guard
systemctl --user disable kindly-guard

# Check status
systemctl --user status kindly-guard

# View logs
journalctl --user -u kindly-guard -f
```

## Configuration

The service looks for configuration in:
- System: `/etc/kindly-guard/config.yaml`
- User: `~/.config/kindly-guard/config.yaml`

Example configuration is created during installation if it doesn't exist.

## Security Features

The system service includes security hardening:
- Runs as dedicated `kindlyguard` user
- Private `/tmp` directory
- Read-only system directories
- No new privileges
- Resource limits (512MB RAM, 200% CPU)

## Socket Activation

The socket unit enables on-demand activation. To use it:

```bash
sudo systemctl enable kindly-guard.socket
sudo systemctl start kindly-guard.socket
```

KindlyGuard will then start automatically when connections arrive at:
`/var/run/kindly-guard/kindly-guard.sock`

## Environment Variables

You can override settings with environment variables:

```bash
# In /etc/systemd/system/kindly-guard.service.d/override.conf
[Service]
Environment="RUST_LOG=debug"
Environment="KINDLY_GUARD_CONFIG=/custom/path/config.yaml"
```

## Troubleshooting

### Service won't start

1. Check logs: `journalctl -u kindly-guard -e`
2. Verify binary exists: `ls -la /usr/local/bin/kindly-guard`
3. Check config syntax: `kindly-guard validate-config`
4. Ensure ports are available (if using network mode)

### Permission errors

1. Ensure kindlyguard user exists: `id kindlyguard`
2. Check directory permissions:
   ```bash
   ls -la /var/log/kindly-guard
   ls -la /var/lib/kindly-guard
   ls -la /etc/kindly-guard
   ```

### High CPU/Memory usage

1. Check resource limits in service file
2. Enable rate limiting in config
3. Monitor with: `systemctl status kindly-guard`

## Uninstalling

To remove KindlyGuard:

```bash
# System-wide
sudo ./uninstall.sh

# User
./uninstall.sh
```

The uninstall script will ask whether to preserve configuration files.