#!/bin/bash

# KindlyGuard Development Mode Startup Script
# Starts components with debug output in separate terminals

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

# Detect terminal emulator
detect_terminal() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists osascript; then
            echo "osascript"
        else
            echo "none"
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists gnome-terminal; then
            echo "gnome-terminal"
        elif command_exists konsole; then
            echo "konsole"
        elif command_exists xterm; then
            echo "xterm"
        elif command_exists kitty; then
            echo "kitty"
        elif command_exists alacritty; then
            echo "alacritty"
        else
            echo "none"
        fi
    else
        echo "none"
    fi
}

# Function to open new terminal
open_terminal() {
    local title="$1"
    local command="$2"
    local terminal=$(detect_terminal)
    
    case $terminal in
        "osascript")
            osascript -e "tell app \"Terminal\" to do script \"cd $(pwd) && $command\""
            ;;
        "gnome-terminal")
            gnome-terminal --title="$title" -- bash -c "cd $(pwd) && $command; exec bash"
            ;;
        "konsole")
            konsole --new-tab -e bash -c "cd $(pwd) && $command; exec bash"
            ;;
        "xterm")
            xterm -title "$title" -e bash -c "cd $(pwd) && $command; exec bash" &
            ;;
        "kitty")
            kitty --title "$title" bash -c "cd $(pwd) && $command; exec bash" &
            ;;
        "alacritty")
            alacritty --title "$title" -e bash -c "cd $(pwd) && $command; exec bash" &
            ;;
        *)
            print_warning "Could not detect terminal emulator"
            print_info "Running in background instead..."
            return 1
            ;;
    esac
    return 0
}

# Check dependencies
print_info "Checking dependencies..."

if ! command_exists cargo; then
    print_error "Rust/Cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi

if ! command_exists node; then
    print_warning "Node.js not found. Shield app development mode requires Node.js"
fi

# Kill any existing processes
print_info "Checking for existing processes..."
./stop-all.sh 2>/dev/null || true

# Start Server in development mode
print_info "Starting KindlyGuard Server in development mode..."

SERVER_CMD="RUST_LOG=kindly_guard=debug,tower_http=debug cargo run --package kindly-guard-server -- --stdio"

if open_terminal "KindlyGuard Server (Dev)" "$SERVER_CMD"; then
    print_status "Server started in new terminal"
else
    # Fallback to background process
    $SERVER_CMD > kindly-guard-dev.log 2>&1 &
    print_status "Server started in background (check kindly-guard-dev.log)"
fi

# Give server time to start
sleep 3

# Start Shield in development mode
print_info "Starting KindlyGuard Shield in development mode..."

cd kindly-guard-shield

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    print_info "Installing Shield dependencies..."
    npm install
fi

SHIELD_CMD="npm run tauri dev"

if open_terminal "KindlyGuard Shield (Dev)" "$SHIELD_CMD"; then
    print_status "Shield started in new terminal"
else
    # Fallback to background process
    $SHIELD_CMD > ../kindly-guard-shield-dev.log 2>&1 &
    print_status "Shield started in background (check kindly-guard-shield-dev.log)"
fi

cd ..

# Start monitoring in a third terminal
print_info "Starting monitor..."

# Build CLI if needed
if [ ! -f "target/debug/kindly-guard-cli" ]; then
    print_info "Building CLI tool..."
    cargo build --package kindly-guard-cli
fi

MONITOR_CMD="RUST_LOG=debug target/debug/kindly-guard-cli monitor"

if open_terminal "KindlyGuard Monitor" "$MONITOR_CMD"; then
    print_status "Monitor started in new terminal"
else
    print_info "Could not start monitor in new terminal"
fi

# Display helpful information
echo
print_info "=== KindlyGuard Development Mode ==="
echo
print_status "All components started in development mode"
echo
print_info "Terminals opened:"
print_info "  1. Server - Running with debug logging"
print_info "  2. Shield - Running with hot-reload"
print_info "  3. Monitor - Showing real-time statistics"
echo
print_info "Useful commands:"
print_info "  View logs: tail -f kindly-guard*.log"
print_info "  Test threat: ./demo/test_unicode_threat.py"
print_info "  Stop all: ./stop-all.sh"
print_info "  Check status: ./status.sh"
echo
print_info "Configuration files:"
print_info "  Server: kindly-guard.toml.example"
print_info "  Shield: kindly-guard-shield/src-tauri/tauri.conf.json"
echo
print_warning "Note: Development mode has verbose logging enabled"
print_warning "For production use, run ./start-all.sh instead"