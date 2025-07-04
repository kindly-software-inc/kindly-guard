#!/bin/bash

# KindlyGuard Ecosystem Startup Script
# Starts all components in the proper order

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "kindly-guard-server" ]; then
    print_error "Please run this script from the KindlyGuard root directory"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
print_info "Checking dependencies..."

if ! command_exists cargo; then
    print_error "Rust/Cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi

if ! command_exists node; then
    print_warning "Node.js not found. Shield app may not work properly."
fi

# Function to check if server is already running
is_server_running() {
    pgrep -f "kindly-guard.*--stdio" > /dev/null 2>&1
}

# Function to check if shield is already running
is_shield_running() {
    pgrep -f "kindly-guard-shield" > /dev/null 2>&1 || \
    lsof -i:9100 > /dev/null 2>&1
}

# Start KindlyGuard Server
print_info "Starting KindlyGuard Server..."

if is_server_running; then
    print_warning "KindlyGuard Server is already running"
else
    # Build if needed
    if [ ! -f "target/release/kindly-guard" ]; then
        print_info "Building KindlyGuard Server (this may take a moment)..."
        cargo build --release --package kindly-guard-server
    fi
    
    # Start server in background with logging
    export RUST_LOG=kindly_guard=info
    nohup target/release/kindly-guard --stdio > kindly-guard.log 2>&1 &
    SERVER_PID=$!
    
    # Wait a moment for server to start
    sleep 2
    
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_status "KindlyGuard Server started (PID: $SERVER_PID)"
        echo $SERVER_PID > .kindly-guard-server.pid
    else
        print_error "Failed to start KindlyGuard Server"
        print_info "Check kindly-guard.log for details"
        exit 1
    fi
fi

# Start Shield App
print_info "Starting KindlyGuard Shield..."

if is_shield_running; then
    print_warning "KindlyGuard Shield is already running"
else
    cd kindly-guard-shield
    
    # Check if it's built
    if [ ! -d "src-tauri/target/release" ] || [ ! -f "src-tauri/target/release/kindly-guard-shield" ]; then
        print_info "Building KindlyGuard Shield (this may take a moment)..."
        
        # Install npm dependencies if needed
        if [ ! -d "node_modules" ]; then
            print_info "Installing Shield dependencies..."
            npm install
        fi
        
        # Build the shield
        npm run tauri build
    fi
    
    # Start shield in background
    if [ -f "src-tauri/target/release/kindly-guard-shield" ]; then
        nohup src-tauri/target/release/kindly-guard-shield > ../kindly-guard-shield.log 2>&1 &
        SHIELD_PID=$!
        
        # Wait a moment for shield to start
        sleep 2
        
        if kill -0 $SHIELD_PID 2>/dev/null; then
            print_status "KindlyGuard Shield started (PID: $SHIELD_PID)"
            echo $SHIELD_PID > ../.kindly-guard-shield.pid
        else
            print_error "Failed to start KindlyGuard Shield"
            print_info "Check kindly-guard-shield.log for details"
        fi
    else
        print_error "Shield binary not found. Build may have failed."
    fi
    
    cd ..
fi

# Display status
echo
print_info "=== KindlyGuard Ecosystem Status ==="
echo

# Check server status
if is_server_running; then
    SERVER_PID=$(cat .kindly-guard-server.pid 2>/dev/null || echo "unknown")
    print_status "Server: Running (PID: $SERVER_PID)"
    print_info "  Log: tail -f kindly-guard.log"
    print_info "  MCP: Listening on stdio"
else
    print_error "Server: Not running"
fi

# Check shield status
if is_shield_running; then
    SHIELD_PID=$(cat .kindly-guard-shield.pid 2>/dev/null || echo "unknown")
    print_status "Shield: Running (PID: $SHIELD_PID)"
    print_info "  Log: tail -f kindly-guard-shield.log"
    print_info "  WebSocket: ws://localhost:9100"
else
    print_error "Shield: Not running"
fi

echo
print_info "To stop all components, run: ./stop-all.sh"
print_info "To check status, run: ./status.sh"
print_info "To view logs, run: tail -f kindly-guard*.log"

# Test connection
if is_server_running && is_shield_running; then
    echo
    print_info "Testing connection..."
    sleep 1
    
    # Simple test using the CLI if available
    if [ -f "target/release/kindly-guard-cli" ]; then
        target/release/kindly-guard-cli monitor --once 2>/dev/null && \
            print_status "Connection test successful!" || \
            print_warning "Connection test failed (components may still be starting)"
    fi
fi

echo
print_status "KindlyGuard ecosystem is ready!"