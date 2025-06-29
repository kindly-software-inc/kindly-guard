#!/bin/bash
#
# KindlyGuard systemd installation script
# This script installs KindlyGuard as a system service
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${GREEN}Running as root, installing system-wide service${NC}"
   SYSTEM_INSTALL=true
else
   echo -e "${YELLOW}Not running as root, installing user service${NC}"
   SYSTEM_INSTALL=false
fi

# Paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if $SYSTEM_INSTALL; then
    # System installation paths
    BINARY_PATH="/usr/local/bin/kindly-guard"
    CONFIG_DIR="/etc/kindly-guard"
    LOG_DIR="/var/log/kindly-guard"
    DATA_DIR="/var/lib/kindly-guard"
    SERVICE_FILE="/etc/systemd/system/kindly-guard.service"
    SOCKET_FILE="/etc/systemd/system/kindly-guard.socket"
else
    # User installation paths
    BINARY_PATH="$HOME/.local/bin/kindly-guard"
    CONFIG_DIR="$HOME/.config/kindly-guard"
    SERVICE_FILE="$HOME/.config/systemd/user/kindly-guard.service"
    mkdir -p "$HOME/.config/systemd/user"
    mkdir -p "$HOME/.local/bin"
fi

echo "Installing KindlyGuard..."

# Build the project
echo -e "${GREEN}Building KindlyGuard...${NC}"
cd "$PROJECT_ROOT"
cargo build --release

# Copy binary
echo -e "${GREEN}Installing binary to $BINARY_PATH${NC}"
if $SYSTEM_INSTALL; then
    cp target/release/kindly-guard "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
else
    cp target/release/kindly-guard "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
fi

# Create directories
echo -e "${GREEN}Creating directories...${NC}"
mkdir -p "$CONFIG_DIR"

if $SYSTEM_INSTALL; then
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    
    # Create kindlyguard user and group
    if ! id -u kindlyguard &>/dev/null; then
        echo -e "${GREEN}Creating kindlyguard user...${NC}"
        useradd --system --shell /bin/false --home-dir /var/lib/kindly-guard kindlyguard
    fi
    
    # Set permissions
    chown kindlyguard:kindlyguard "$LOG_DIR" "$DATA_DIR"
    chmod 755 "$LOG_DIR" "$DATA_DIR"
fi

# Copy default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${GREEN}Installing default configuration...${NC}"
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# KindlyGuard Configuration

# Scanner settings
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 10
  enable_event_buffer: false  # Set to true for enhanced mode

# Shield display settings  
shield:
  display_enabled: true
  update_interval_ms: 1000
  show_timestamp: true
  show_stats: true

# Authentication settings
auth:
  enabled: true
  allowed_clients:
    - client_id: "default-client"
      secret: "change-me-in-production"
      allowed_scopes: ["tools:execute", "resources:read"]

# Rate limiting
rate_limit:
  enabled: true
  default_rpm: 60
  default_burst: 10
  threat_penalty_multiplier: 2.0

# Message signing
signing:
  enabled: false
  algorithm: "Ed25519"
  private_key_path: null
  public_key_path: null

# Event processor (enhanced mode)
event_processor:
  enabled: false  # Set to true for purple shield mode
  endpoint_limit: 1000
  pattern_detection: true
  correlation_window_secs: 300

# Logging
log_level: "info"
EOF
    
    if $SYSTEM_INSTALL; then
        chown root:kindlyguard "$CONFIG_DIR/config.yaml"
        chmod 640 "$CONFIG_DIR/config.yaml"
    fi
fi

# Install systemd service
echo -e "${GREEN}Installing systemd service...${NC}"
if $SYSTEM_INSTALL; then
    cp "$SCRIPT_DIR/kindly-guard.service" "$SERVICE_FILE"
    cp "$SCRIPT_DIR/kindly-guard.socket" "$SOCKET_FILE"
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}System service installed!${NC}"
    echo ""
    echo "To start KindlyGuard:"
    echo "  systemctl start kindly-guard"
    echo ""
    echo "To enable at boot:"
    echo "  systemctl enable kindly-guard"
    echo ""
    echo "To view logs:"
    echo "  journalctl -u kindly-guard -f"
else
    cp "$SCRIPT_DIR/kindly-guard-user.service" "$SERVICE_FILE"
    
    # Reload user systemd
    systemctl --user daemon-reload
    
    echo -e "${GREEN}User service installed!${NC}"
    echo ""
    echo "To start KindlyGuard:"
    echo "  systemctl --user start kindly-guard"
    echo ""
    echo "To enable at login:"
    echo "  systemctl --user enable kindly-guard"
    echo ""
    echo "To view logs:"
    echo "  journalctl --user -u kindly-guard -f"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Configuration file: $CONFIG_DIR/config.yaml"
echo "Binary location: $BINARY_PATH"
echo ""
echo "For MCP client integration, use:"
echo "  Command: $BINARY_PATH --stdio"
echo "  Working directory: $CONFIG_DIR"