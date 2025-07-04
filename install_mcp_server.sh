#!/bin/bash

# Kindly Guard MCP Server Installation Script
# This script builds and installs the kindly-guard MCP server for Claude Desktop

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions for colored output
error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

success() {
    echo -e "${GREEN}SUCCESS:${NC} $1"
}

info() {
    echo -e "${BLUE}INFO:${NC} $1"
}

warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

# Check if running from the kindly-guard directory
if [ ! -f "Cargo.toml" ] || [ ! -d "kindly-guard-server" ]; then
    error "This script must be run from the kindly-guard project root directory"
    exit 1
fi

# Variables
PROJECT_ROOT=$(pwd)
MCP_SERVER_DIR="$HOME/.claude/mcp-servers/kindly-guard"
MCP_CONFIG_FILE="$HOME/.mcp.json"
BINARY_NAME="kindly-guard"
BACKUP_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

info "Starting Kindly Guard MCP Server installation..."

# Step 1: Check for Rust installation
if ! command -v cargo &> /dev/null; then
    error "Rust is not installed. Please install Rust from https://rustup.rs/"
    exit 1
fi

info "Rust toolchain found"

# Step 2: Build the project in release mode
info "Building kindly-guard-server in release mode..."
if cargo build --release --package kindly-guard-server; then
    success "Build completed successfully"
else
    error "Build failed. Please check the error messages above."
    exit 1
fi

# Step 3: Create MCP server directory
info "Creating MCP server directory at $MCP_SERVER_DIR..."
mkdir -p "$MCP_SERVER_DIR"

# Step 4: Copy the binary
BUILT_BINARY="$PROJECT_ROOT/target/release/$BINARY_NAME"
if [ ! -f "$BUILT_BINARY" ]; then
    error "Binary not found at $BUILT_BINARY"
    exit 1
fi

info "Copying binary to $MCP_SERVER_DIR..."
cp "$BUILT_BINARY" "$MCP_SERVER_DIR/"
chmod +x "$MCP_SERVER_DIR/$BINARY_NAME"
success "Binary installed at $MCP_SERVER_DIR/$BINARY_NAME"

# Step 5: Create default configuration file
CONFIG_FILE="$MCP_SERVER_DIR/config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    info "Creating default configuration file..."
    cat > "$CONFIG_FILE" << 'EOF'
# Kindly Guard Configuration
mode = "standard"
log_level = "info"

[rate_limit]
window_secs = 60
max_requests = 100

[scanner]
max_input_size = 1048576  # 1MB
patterns_file = ""

[metrics]
enabled = true
export_interval_secs = 60

[auth]
require_auth = false
EOF
    success "Configuration file created at $CONFIG_FILE"
else
    info "Configuration file already exists at $CONFIG_FILE"
fi

# Step 6: Backup existing .mcp.json if it exists
if [ -f "$MCP_CONFIG_FILE" ]; then
    BACKUP_FILE="${MCP_CONFIG_FILE}.backup.${BACKUP_TIMESTAMP}"
    info "Backing up existing .mcp.json to $BACKUP_FILE..."
    cp "$MCP_CONFIG_FILE" "$BACKUP_FILE"
    success "Backup created"
else
    info "No existing .mcp.json found, creating new one..."
fi

# Step 7: Update .mcp.json configuration
info "Updating MCP configuration..."

# Create or update the .mcp.json file
if [ -f "$MCP_CONFIG_FILE" ]; then
    # Parse existing JSON and add kindly-guard configuration
    # Using jq if available, otherwise use Python
    if command -v jq &> /dev/null; then
        # Use jq to update the configuration
        jq '.mcpServers."kindly-guard" = {
            "type": "stdio",
            "command": "'"$MCP_SERVER_DIR/$BINARY_NAME"'",
            "args": ["--config", "'"$CONFIG_FILE"'"],
            "env": {}
        }' "$MCP_CONFIG_FILE" > "$MCP_CONFIG_FILE.tmp" && mv "$MCP_CONFIG_FILE.tmp" "$MCP_CONFIG_FILE"
    elif command -v python3 &> /dev/null; then
        # Use Python to update the configuration
        python3 -c "
import json
import sys

config_file = '$MCP_CONFIG_FILE'
try:
    with open(config_file, 'r') as f:
        config = json.load(f)
except:
    config = {'mcpServers': {}}

if 'mcpServers' not in config:
    config['mcpServers'] = {}

config['mcpServers']['kindly-guard'] = {
    'type': 'stdio',
    'command': '$MCP_SERVER_DIR/$BINARY_NAME',
    'args': ['--config', '$CONFIG_FILE'],
    'env': {}
}

with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)
"
    else
        warning "Neither jq nor python3 found. Please manually add the following to your $MCP_CONFIG_FILE:"
        cat << EOF

"kindly-guard": {
  "type": "stdio",
  "command": "$MCP_SERVER_DIR/$BINARY_NAME",
  "args": ["--config", "$CONFIG_FILE"],
  "env": {}
}

EOF
    fi
else
    # Create new .mcp.json file
    cat > "$MCP_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "kindly-guard": {
      "type": "stdio",
      "command": "$MCP_SERVER_DIR/$BINARY_NAME",
      "args": ["--config", "$CONFIG_FILE"],
      "env": {}
    }
  }
}
EOF
fi

if [ -f "$MCP_CONFIG_FILE" ]; then
    success "MCP configuration updated"
fi

# Step 8: Verify installation
info "Verifying installation..."
if [ -x "$MCP_SERVER_DIR/$BINARY_NAME" ]; then
    # Test if the binary runs
    if "$MCP_SERVER_DIR/$BINARY_NAME" --version &> /dev/null; then
        VERSION=$("$MCP_SERVER_DIR/$BINARY_NAME" --version 2>&1 || echo "unknown")
        success "Kindly Guard server installed successfully!"
        info "Version: $VERSION"
    else
        warning "Binary installed but --version command failed. This might be normal."
        success "Installation completed!"
    fi
else
    error "Binary is not executable"
    exit 1
fi

# Step 9: Final instructions
echo ""
success "Installation complete!"
echo ""
info "Next steps:"
echo "  1. Restart Claude Desktop to load the new MCP server"
echo "  2. The server will appear as 'kindly-guard' in Claude's MCP servers"
echo "  3. Configuration file: $CONFIG_FILE"
echo "  4. Binary location: $MCP_SERVER_DIR/$BINARY_NAME"
echo ""
info "To test the server manually, run:"
echo "  $MCP_SERVER_DIR/$BINARY_NAME --config $CONFIG_FILE"
echo ""
info "To uninstall, run:"
echo "  rm -rf $MCP_SERVER_DIR"
echo "  # Then remove the 'kindly-guard' entry from $MCP_CONFIG_FILE"
echo ""

# Check if Claude Desktop is running
if pgrep -f "Claude" > /dev/null 2>&1; then
    warning "Claude Desktop appears to be running. Please restart it to load the new MCP server."
fi

exit 0