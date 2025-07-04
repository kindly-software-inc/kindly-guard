#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration paths
MCP_CONFIG_FILE="$HOME/.mcp.json"
KINDLY_GUARD_DIR="$HOME/kindly-guard"
KINDLY_GUARD_BINARY="$KINDLY_GUARD_DIR/target/release/kindly-guard"
CLAUDE_DESKTOP_CONFIG_DIR="$HOME/.config/Claude"

# Status tracking
ISSUES_FOUND=0
CLAUDE_RESTART_NEEDED=0

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}KindlyGuard MCP Setup Verification${NC}"
echo -e "${BLUE}=====================================${NC}"
echo

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to log success
log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Function to log error
log_error() {
    echo -e "${RED}✗${NC} $1"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
}

# Function to log warning
log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to log info
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# 1. Check if MCP config file exists
echo -e "${BLUE}1. Checking MCP configuration...${NC}"
if [ -f "$MCP_CONFIG_FILE" ]; then
    log_success "MCP configuration file found at: $MCP_CONFIG_FILE"
    
    # Check if kindly-guard is in the configuration
    if grep -q '"kindly-guard"' "$MCP_CONFIG_FILE"; then
        log_success "kindly-guard is configured in MCP"
        
        # Extract and verify the configured path
        CONFIGURED_PATH=$(grep -A 3 '"kindly-guard"' "$MCP_CONFIG_FILE" | grep '"command"' | sed 's/.*"command": *"\([^"]*\)".*/\1/')
        
        if [ -n "$CONFIGURED_PATH" ]; then
            log_info "Configured binary path: $CONFIGURED_PATH"
            
            if [ "$CONFIGURED_PATH" != "$KINDLY_GUARD_BINARY" ]; then
                log_warning "Configured path differs from expected path"
                log_info "Expected: $KINDLY_GUARD_BINARY"
                log_info "Fix: Update the command path in $MCP_CONFIG_FILE"
            fi
        fi
    else
        log_error "kindly-guard is NOT configured in MCP"
        log_info "Fix: Add kindly-guard configuration to $MCP_CONFIG_FILE"
        echo -e "${YELLOW}  Example configuration:${NC}"
        cat << 'EOF'
    "kindly-guard": {
      "type": "stdio",
      "command": "/home/samuel/kindly-guard/target/release/kindly-guard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
EOF
    fi
else
    log_error "MCP configuration file not found at: $MCP_CONFIG_FILE"
    log_info "Fix: Create the MCP configuration file"
fi
echo

# 2. Check if kindly-guard binary exists and is executable
echo -e "${BLUE}2. Checking kindly-guard binary...${NC}"
if [ -f "$KINDLY_GUARD_BINARY" ]; then
    log_success "kindly-guard binary found at: $KINDLY_GUARD_BINARY"
    
    # Check if it's executable
    if [ -x "$KINDLY_GUARD_BINARY" ]; then
        log_success "Binary is executable"
        
        # Check file size (should be reasonable)
        FILE_SIZE=$(stat -c%s "$KINDLY_GUARD_BINARY" 2>/dev/null || stat -f%z "$KINDLY_GUARD_BINARY" 2>/dev/null)
        if [ -n "$FILE_SIZE" ] && [ "$FILE_SIZE" -gt 1000000 ]; then
            log_success "Binary size looks reasonable: $(numfmt --to=iec-i --suffix=B $FILE_SIZE 2>/dev/null || echo "$FILE_SIZE bytes")"
        else
            log_warning "Binary size seems small: $FILE_SIZE bytes"
        fi
    else
        log_error "Binary is not executable"
        log_info "Fix: chmod +x $KINDLY_GUARD_BINARY"
    fi
else
    log_error "kindly-guard binary not found at: $KINDLY_GUARD_BINARY"
    log_info "Fix: Build the project with: cd $KINDLY_GUARD_DIR && cargo build --release"
fi
echo

# 3. Test basic MCP communication
echo -e "${BLUE}3. Testing MCP communication...${NC}"
if [ -f "$KINDLY_GUARD_BINARY" ] && [ -x "$KINDLY_GUARD_BINARY" ]; then
    # Test basic stdio communication
    log_info "Testing basic stdio communication..."
    
    # Send initialize request with correct protocol version
    INIT_RESPONSE=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify_script","version":"1.0.0"}}}' | timeout 5 "$KINDLY_GUARD_BINARY" --stdio 2>&1)
    
    if [ $? -eq 0 ] && echo "$INIT_RESPONSE" | grep -q '"jsonrpc"'; then
        log_success "MCP server responds to initialization"
        
        # Check if response is valid JSON-RPC
        if echo "$INIT_RESPONSE" | grep -q '"result"'; then
            log_success "Valid JSON-RPC response received"
            
            # Extract server name
            SERVER_NAME=$(echo "$INIT_RESPONSE" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
            if [ -n "$SERVER_NAME" ]; then
                log_info "Server name: $SERVER_NAME"
            fi
        elif echo "$INIT_RESPONSE" | grep -q '"error"'; then
            log_error "Server returned an error"
            echo "  Error response: $INIT_RESPONSE"
        fi
    else
        log_error "Failed to communicate with MCP server"
        log_info "Response: $INIT_RESPONSE"
        log_info "Fix: Check server logs or run with RUST_LOG=debug for more details"
    fi
else
    log_warning "Skipping MCP communication test (binary not available)"
fi
echo

# 4. Check Claude Desktop integration
echo -e "${BLUE}4. Checking Claude Desktop integration...${NC}"

# Check if Claude Desktop process is running
if pgrep -f "Claude" >/dev/null 2>&1 || pgrep -f "claude" >/dev/null 2>&1; then
    log_info "Claude Desktop appears to be running"
    CLAUDE_RESTART_NEEDED=1
    
    # Check for Claude Desktop config directory
    if [ -d "$CLAUDE_DESKTOP_CONFIG_DIR" ]; then
        log_success "Claude Desktop config directory found"
    else
        log_warning "Claude Desktop config directory not found at: $CLAUDE_DESKTOP_CONFIG_DIR"
    fi
else
    log_info "Claude Desktop is not currently running"
fi

# Check if mcp.json was recently modified
if [ -f "$MCP_CONFIG_FILE" ]; then
    LAST_MODIFIED=$(stat -c %Y "$MCP_CONFIG_FILE" 2>/dev/null || stat -f %m "$MCP_CONFIG_FILE" 2>/dev/null)
    CURRENT_TIME=$(date +%s)
    TIME_DIFF=$((CURRENT_TIME - LAST_MODIFIED))
    
    if [ "$TIME_DIFF" -lt 300 ]; then # Less than 5 minutes
        log_warning "MCP config was recently modified (${TIME_DIFF}s ago)"
        CLAUDE_RESTART_NEEDED=1
    fi
fi
echo

# 5. Environment and dependencies check
echo -e "${BLUE}5. Checking environment and dependencies...${NC}"

# Check Rust installation
if command_exists rustc; then
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    log_success "Rust installed: $RUST_VERSION"
else
    log_warning "Rust not installed (needed for building from source)"
fi

# Check for required environment variables
if [ -n "$RUST_LOG" ]; then
    log_info "RUST_LOG is set to: $RUST_LOG"
else
    log_info "RUST_LOG not set (will use default logging level)"
fi

# Check permissions
if [ -r "$MCP_CONFIG_FILE" ] && [ -w "$MCP_CONFIG_FILE" ]; then
    log_success "MCP config file has correct permissions"
else
    log_warning "MCP config file permissions may need adjustment"
fi
echo

# 6. Summary and recommendations
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}Verification Summary${NC}"
echo -e "${BLUE}=====================================${NC}"

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo
    
    if [ $CLAUDE_RESTART_NEEDED -eq 1 ]; then
        echo -e "${YELLOW}Action Required:${NC}"
        echo "  - Restart Claude Desktop to apply MCP configuration changes"
    fi
    
    echo -e "${GREEN}KindlyGuard MCP setup appears to be configured correctly.${NC}"
else
    echo -e "${RED}✗ Found $ISSUES_FOUND issue(s) that need attention${NC}"
    echo
    echo -e "${YELLOW}Recommended fixes:${NC}"
    
    if ! [ -f "$MCP_CONFIG_FILE" ] || ! grep -q '"kindly-guard"' "$MCP_CONFIG_FILE" 2>/dev/null; then
        echo "  1. Add kindly-guard to your MCP configuration"
    fi
    
    if ! [ -f "$KINDLY_GUARD_BINARY" ]; then
        echo "  2. Build kindly-guard: cd $KINDLY_GUARD_DIR && cargo build --release"
    elif ! [ -x "$KINDLY_GUARD_BINARY" ]; then
        echo "  2. Make binary executable: chmod +x $KINDLY_GUARD_BINARY"
    fi
    
    if [ $CLAUDE_RESTART_NEEDED -eq 1 ]; then
        echo "  3. Restart Claude Desktop after fixing issues"
    fi
fi

echo
echo -e "${BLUE}Quick test command:${NC}"
echo "  echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0.0\"}}}' | $KINDLY_GUARD_BINARY --stdio"

echo
echo -e "${BLUE}For more detailed logs, run kindly-guard with:${NC}"
echo "  RUST_LOG=debug $KINDLY_GUARD_BINARY --stdio"

exit $ISSUES_FOUND